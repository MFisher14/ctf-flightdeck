#!/usr/bin/env python3
"""Live targets of the event, filed by challenge or lane: one small file, <CHALLENGES>/_targets.json.

  python3 tools/target.py add <challenge-or-lane> <address[:port]> [label ...]
  python3 tools/target.py list
  python3 tools/target.py get <challenge> [--json]
  python3 tools/target.py clear [<challenge-or-lane>]

Why: when the team is handed a challenge's host/port (or the player starts a VM and pastes its
address), file it here under the challenge id (or a lane name), so a solver (and
solvers/toolkits/web.py) reads it from the file instead of from a chat line it never saw.

add    files one address under a challenge id or a lane name. The address may be `10.1.2.3`,
       `10.1.2.3:8080`, `http://10.1.2.3:8080/app`, `host.example:443`, or the pasted form
       `nc 10.1.2.3 31337`. A second add under the same key replaces the first. When the event
       config declares `vpn_ranges`, the line it prints says whether the address lies in them
       (then tools/vpn.py ensure comes first).
get    the target of a challenge, one line (a URL when one is known, else host[:port]): the entry
       under the exact id, else under the longest lane name the id starts with. Exit 1 when none.
       (A platform adapter may pass lookup(base_of=...) to map an id to the id whose target it
       shares, e.g. the Huntress adapter's `/time_trial` and `/mastery` ids; master has no such rule.)
list   every entry, one line each.
clear  one entry, or all of them with no argument.

Nothing here makes a request, connects anything or reads the token. An address is data the caller
gave: it is checked for shape (no spaces, no shell characters, no credentials in a URL) and stored
as given. The event platform is never a target and is refused in code (event_policy() below): the
host of the configured platform URL (ctf.config base_url), $CTF_PLATFORM_URL, and every host in the
event config's `platform_hosts` are refused by their EXACT host (a subdomain of the platform's
domain can be a challenge host and is filed); a word in `platform_words` (another spelling of a
platform road, such as a proxy's dashed address or name) is refused anywhere in the address, also
URL-decoded. Filing only assigned targets beyond that stays the caller's job.

Event config keys read here (ctf.config's event config, read on every call):
  vpn_ranges       CIDRs the event VPN routes (split tunnel). $CTF_VPN_RANGES (comma separated)
                   replaces it. Absent: no address is said to be inside or outside the VPN.
  platform_hosts   hosts that are the platform, never a target.
  platform_words   spellings of a platform road refused anywhere in an address.
A malformed value is a loud ValueError naming the key; a config that cannot be loaded is a loud
RuntimeError.

In process: target.lookup(challenge, base_of=None) -> dict or None, target.parse(text) -> dict
(ValueError), target.in_event_ranges(host) -> bool | None, target.event_ranges() -> tuple.
"""
import fcntl
import ipaddress
import json
import os
import re
import sys
import urllib.parse
from datetime import datetime
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import env as ctf_env, paths as ctf_paths

REPO = Path(__file__).resolve().parent.parent
FILE = "_targets.json"
KEY = re.compile(r"[a-z0-9][a-z0-9._-]*(/[a-z0-9_]+)?")
HOST = re.compile(r"(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*")
# A host the C library reads as an address although it is not a dotted quad (0x0a0000db, 10.219, 012.0.0.1):
# every label a decimal or 0x number. Refused unless it is a plain IPv4 address.
NUMERIC = re.compile(r"(?i)(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+))*")
DIGITS = re.compile(r"[0-9]{1,5}")
URL_SAFE = re.compile(r"[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*")
USAGE = "usage: target.py add <challenge-or-lane> <address[:port]> [label ...] | list | get <challenge> [--json] | clear [<key>]"


def folder() -> Path:
    """<CHALLENGES>, resolved on every call: the event workdir, ctf.paths.workdir()."""
    return ctf_paths.workdir()


def path() -> Path:
    return folder() / FILE


# ---- the event config's target policy (platform refusal, VPN ranges) -------------------------------

def _event_config():
    """(platform base URL, raw event-config dict) from ctf.config, read on every call. An import
    failure is loud: the platform refusal and the VPN ranges are part of the target policy and must
    not silently go unchecked."""
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    try:
        from ctf import config as _config
    except ImportError as e:
        raise RuntimeError(f"target.py: cannot load the event config (ctf.config) for the target policy: {e}") from e
    return _config.load().base_url, _config._load_file()


def _as_list(value, key) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    if isinstance(value, (list, tuple)) and all(isinstance(x, str) for x in value):
        return [x.strip() for x in value if x.strip()]
    raise ValueError(f"event config `{key}` must be a list of strings, got {type(value).__name__}")


def _host_of(url_or_host) -> str:
    s = str(url_or_host or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "//" + s
    try:
        return (urllib.parse.urlsplit(s).hostname or "").lower()
    except ValueError:
        return ""


def _networks(cidrs, key):
    nets = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            raise ValueError(f"event config `{key}` holds {c!r}, which is not a CIDR range") from None
        if net.version != 4:
            raise ValueError(f"event config `{key}` holds {c!r}: only IPv4 ranges are routed by the event VPN")
        nets.append(net)
    return nets


def event_policy(cfg=None) -> dict:
    """{"vpn_ranges": (CIDR, ...), "platform_hosts": set, "platform_words": tuple}, from `cfg` (a
    config dict, as a platform adapter or a test hands it) or from ctf.config. See the module text."""
    base_url = None
    if cfg is None:
        base_url, cfg = _event_config()
    if not isinstance(cfg, dict):
        raise ValueError("the event config is not a JSON object")
    env_ranges = os.environ.get("CTF_VPN_RANGES")
    if env_ranges is not None and env_ranges.strip():
        ranges, rkey = _as_list(env_ranges, "CTF_VPN_RANGES"), "$CTF_VPN_RANGES"
    else:
        ranges, rkey = _as_list(cfg.get("vpn_ranges"), "vpn_ranges"), "vpn_ranges"
    nets = _networks(ranges, rkey)
    hosts = {_host_of(h) for h in [base_url, ctf_env.get("CTF_PLATFORM_URL")]
             + _as_list(cfg.get("platform_hosts"), "platform_hosts")}
    hosts.discard("")
    words = tuple(w.lower() for w in _as_list(cfg.get("platform_words"), "platform_words"))
    return {"vpn_ranges": tuple(str(n) for n in nets), "platform_hosts": hosts, "platform_words": words}


def event_ranges(policy=None) -> tuple:
    """The CIDRs the event VPN routes, () when the event config declares none."""
    return (event_policy() if policy is None else policy)["vpn_ranges"]


def in_event_ranges(host, policy=None):
    """True for a literal IPv4 address inside the event VPN's ranges, False for anything else, and
    None when the event config declares no ranges (nothing can be said). A name is never resolved."""
    ranges = event_ranges(policy)
    if not ranges:
        return None
    try:
        ip = ipaddress.ip_address(str(host))
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(n) for n in ranges)


def refuse_platform(host, word="", policy=None):
    """ValueError when `host` (or a platform word anywhere in `word`, also URL-decoded) is the event
    platform. Nothing is returned otherwise."""
    pol = event_policy() if policy is None else policy
    low = str(host or "").lower()
    plain = str(word or "").lower()
    for _ in range(3):                   # %68ost..., and %2568ost...
        plain = urllib.parse.unquote(plain)
    if low in pol["platform_hosts"]:
        raise ValueError(f"{low} is the event platform (platform_hosts / the platform URL), never a challenge target")
    hit = next((w for w in pol["platform_words"] if w in low or w in plain), None)
    if hit:
        raise ValueError(f"that names the event platform ({hit!r} in platform_words), never a challenge target")


def parse(text, policy=None) -> dict:
    """An address a caller passed -> {host, port, scheme, url, address, vpn}. ValueError, with one
    line, for anything that is not one address or that is the event platform. `vpn` is True/False
    for inside/outside the event config's vpn_ranges, None when it declares none. `policy` is
    event_policy()'s dict (read from the event config when not given)."""
    raw = " ".join(str(text or "").split())
    if not raw:
        raise ValueError("no address given")
    words = raw.split(" ")
    if words[0] in ("nc", "ncat", "netcat"):
        words = [w for w in words[1:] if not w.startswith("-")]
    if len(words) == 2 and DIGITS.fullmatch(words[1]) and "://" not in words[0] and ":" not in words[0]:
        words = [f"{words[0]}:{words[1]}"]
    if len(words) != 1:
        raise ValueError(f"not one address: {raw[:80]!r}")
    word = words[0]
    scheme = url = None
    if "://" in word:
        if not URL_SAFE.fullmatch(word):
            raise ValueError("the URL holds a character a URL cannot carry as it is")
        parts = urllib.parse.urlsplit(word)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"only http and https URLs are targets (got {parts.scheme}://)")
        if parts.username or parts.password:
            raise ValueError("a URL with a user name or password in it is not stored")
        host, scheme = parts.hostname or "", parts.scheme
        try:
            port = parts.port
        except ValueError:
            raise ValueError("the port is not a number from 1 to 65535") from None
        url = word
    else:
        host, sep, tail = word.rpartition(":")
        if not sep:
            host, tail = word, ""
        if tail and not DIGITS.fullmatch(tail):
            raise ValueError(f"the port is not a number: {tail[:20]!r}")
        port = int(tail) if tail else None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("the port is not a number from 1 to 65535")
    if not HOST.fullmatch(host):
        raise ValueError(f"not a host name or an IPv4 address: {host[:60]!r}")
    if NUMERIC.fullmatch(host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            raise ValueError(f"not an IPv4 address: {host[:60]!r}") from None
    low = host.lower()
    pol = event_policy() if policy is None else policy
    refuse_platform(low, word, pol)
    return {"host": low, "port": port, "scheme": scheme, "url": url,
            "address": low + (f":{port}" if port else ""), "vpn": in_event_ranges(low, pol)}


def _load() -> dict:
    try:
        data = json.loads(path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    rows = data.get("targets") if isinstance(data, dict) else None
    return {k: v for k, v in rows.items() if isinstance(k, str) and isinstance(v, dict)} if isinstance(rows, dict) else {}


class _Lock:
    def __enter__(self):
        folder().mkdir(parents=True, exist_ok=True)
        self.fd = os.open(folder() / ".targets.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)


def _save(rows: dict):
    p = path()
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"version": 1, "targets": rows}, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, p)


def _key(text) -> str:
    key = str(text or "").strip().lower()
    if not KEY.fullmatch(key):
        raise ValueError(f"not a challenge id or a lane name: {str(text)[:60]!r}")
    return key


def add(key, address, label="") -> dict:
    """File one target. Returns the stored entry (with its key)."""
    key, entry = _key(key), parse(address)
    entry["label"] = " ".join(str(label or "").split())[:120]
    entry["added"] = datetime.now().astimezone().isoformat(timespec="seconds")
    with _Lock():
        rows = _load()
        rows[key] = entry
        _save(rows)
    return dict(entry, key=key)


def clear(key=None) -> int:
    """Remove one entry (or all). Returns how many went."""
    with _Lock():
        rows = _load()
        if key is None:
            gone, rows = len(rows), {}
        else:
            gone = 1 if rows.pop(_key(key), None) is not None else 0
        if gone or path().exists():
            _save(rows)
    return gone


def lookup(challenge, rows=None, base_of=None):
    """The entry for a challenge id (see `get` above), with "key" added, or None. Never raises on a
    lookup miss or a bad file. `base_of` (a platform adapter's rule, None in master) maps the id to
    the id whose target it shares; that id is tried after the exact one, and lanes match on it."""
    try:
        cid = str(challenge or "").strip().lower()
        rows = _load() if rows is None else rows
        if not cid or not rows:
            return None
        base = str(base_of(cid) or cid).strip().lower() if base_of is not None else cid
        for key in (cid, base):
            if key in rows:
                return dict(rows[key], key=key)
        lanes = [k for k in rows if "/" not in k and (base == k or base.startswith(k + "-"))]
        if lanes:
            key = max(lanes, key=len)
            return dict(rows[key], key=key)
    except Exception:
        pass
    return None


def line(entry) -> str:
    return entry.get("url") or entry.get("address") or ""


def describe(entry) -> str:
    label = f" ({entry['label']})" if entry.get("label") else ""
    vpn = entry.get("vpn")
    if vpn is True:
        where = "; inside the VPN's ranges: tools/vpn.py ensure " + str(entry.get("address", ""))
    elif vpn is False:
        where = "; outside the VPN's ranges"
    else:
        where = ""                       # the event config declares no vpn_ranges: nothing to say
    return f"{entry.get('key', '?')} -> {line(entry)}{label}{where}"


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    cmd, args = argv[0], argv[1:]
    try:
        if cmd == "add" and len(args) >= 2:
            # `nc 10.1.2.3 31337` and `10.1.2.3 31337` are one address in two or three words
            n = 3 if args[1] in ("nc", "ncat", "netcat") else (2 if len(args) >= 3 and DIGITS.fullmatch(args[2]) and ":" not in args[1] else 1)
            print("TARGET " + describe(add(args[0], " ".join(args[1:1 + n]), " ".join(args[1 + n:]))))
            return 0
        if cmd == "list" and not args:
            rows = _load()
            for key in sorted(rows):
                print("TARGET " + describe(dict(rows[key], key=key)))
            print(f"{len(rows)} target(s) in {path()}")
            return 0
        if cmd == "get" and len([a for a in args if a != "--json"]) == 1:
            entry = lookup(next(a for a in args if a != "--json"))
            if entry is None:
                print("no target on file for it (tools/target.py add <challenge-or-lane> <address>)", file=sys.stderr)
                return 1
            print(json.dumps(entry, sort_keys=True) if "--json" in args else line(entry))
            return 0
        if cmd == "clear" and len(args) <= 1:
            print(f"cleared {clear(args[0] if args else None)} target(s)")
            return 0
    except ValueError as e:
        print(f"target.py: refused: {e}", file=sys.stderr)
        return 2
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
