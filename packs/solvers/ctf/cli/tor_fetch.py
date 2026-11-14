"""ctf tor-fetch -- fetch a Tor hidden service and read its leaf certificate (B-091).

The online half of the `.onion` OSINT path: `osint.py` extracts the `.onion` lead offline, and this
command makes the one safe, in-scope request against it -- a single passive GET over a *local* Tor
SOCKS5h proxy -- capturing the response headers, the body, the declared favicon (with B-089's
scan-engine hashes) and the leaf certificate the service presents. The certificate's serial (uppercase
hex, no colons) is printed first, because a "read the certificate" onion task asks for exactly that: a
self-signed onion certificate never enters Certificate Transparency, so it can only be read off the
service.

    python -m ctf tor-fetch https://abc...d.onion/                 fetch; print the serial + hashes
    python -m ctf tor-fetch abc...d.onion --out ./evidence         write the evidence files too
    python -m ctf tor-fetch https://abc...d.onion/ --socks-port 19066   use a specific SocksPort

`scope.check_host` on the onion host runs before any connection, so only an in-scope service is
contacted. A running Tor SocksPort is required: it is auto-detected on 9050/9150, or named with
`--socks-port`. Starting a `tor` daemon is a human step (a named job under B-175); this command never
launches tor and never falls back to a clearnet fetch.

Exit codes: 0 ok; 2 a bad argument or a fetch/parse error; 3 no running Tor SOCKS proxy (start tor,
B-175); 4 the onion host is out of the event scope.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import tor as _tor
from .. import scope as _scope

HELP = "fetch a Tor .onion service over a local SOCKS proxy and read its leaf certificate (B-091)"

REFUSED_EXIT = 4
NO_TOR_EXIT = 3
ERROR_EXIT = 2


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("url", help="a .onion URL (or host); https is assumed when no scheme is given")
    p.add_argument("--socks-port", type=int, default=None, metavar="PORT",
                   help="the local Tor SocksPort (default: auto-detect 9050, then 9150)")
    p.add_argument("--socks-host", default=_tor.DEFAULT_SOCKS_HOST, metavar="HOST",
                   help="the local Tor SOCKS host (default 127.0.0.1)")
    p.add_argument("--timeout", type=float, default=30.0, metavar="S",
                   help="per-request timeout in seconds (default 30)")
    p.add_argument("--out", metavar="DIR",
                   help="write the evidence files (headers, body, leaf certificate, favicon) into DIR")
    p.add_argument("--no-favicon", action="store_true", help="skip the favicon fetch")
    p.add_argument("--json", action="store_true", help="print the capture summary as one JSON object")


def _print_report(resp: _tor.OnionResponse, out_paths) -> None:
    cert = resp.cert or {}
    if cert.get("serial"):
        print(f"leaf certificate serial: {cert['serial']}")
    print(f"onion: {resp.url}  ({resp.status_line or 'no status line'})")
    if cert:
        print(f"  subject CN:   {cert.get('subject_cn')}")
        print(f"  issuer CN:    {cert.get('issuer_cn')}")
        print(f"  SHA-1   fp:   {cert.get('fingerprint_sha1')}")
        print(f"  SHA-256 fp:   {cert.get('fingerprint_sha256')}")
    else:
        print("  (no leaf certificate parsed: cryptography absent or the leaf did not decode)")
    print(f"  body:         {len(resp.body)} bytes")
    if resp.favicon_hashes:
        print(f"  favicon:      {resp.favicon_url}  mmh3={resp.favicon_hashes.get('mmh3')} "
              f"md5={resp.favicon_hashes.get('md5')}")
    for p in out_paths:
        print(f"  wrote {p}")


def run(args: argparse.Namespace) -> int:
    try:
        resp = _tor.fetch_onion(args.url, socks_port=args.socks_port, socks_host=args.socks_host,
                                timeout=args.timeout, want_favicon=not args.no_favicon)
    except _scope.OutOfScope as e:
        print(f"tor-fetch: {e}", file=sys.stderr)
        return REFUSED_EXIT
    except _tor.TorError as e:
        msg = str(e)
        print(f"tor-fetch: {msg}", file=sys.stderr)
        # A missing SOCKS proxy is its own exit code so a caller can prompt for the tor human step.
        return NO_TOR_EXIT if "SOCKS" in msg or "SocksPort" in msg else ERROR_EXIT
    out_paths = _tor.write_evidence(resp, args.out) if args.out else []
    if args.json:
        summary = {
            "url": resp.url, "host": resp.host, "port": resp.port, "socks": resp.socks,
            "status": resp.status_code, "status_line": resp.status_line,
            "headers": [[k, v] for k, v in resp.headers], "body_bytes": len(resp.body),
            "certificate": {k: v for k, v in (resp.cert or {}).items() if k != "pem"} or None,
            "favicon": ({"source": resp.favicon_url, **(resp.favicon_hashes or {})}
                        if resp.favicon else None),
            "evidence": [str(p) for p in out_paths],
        }
        print(json.dumps(summary, indent=2))
    else:
        _print_report(resp, out_paths)
    return 0
