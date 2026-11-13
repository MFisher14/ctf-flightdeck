"""ctf favicon — fetch a service's declared icon and record every scan-engine hash (B-089).

The online half of B-089 (the offline half is the `toolkits.favicon_hash` intake engine). It fetches
the favicon a URL declares -- parsing `<link rel=icon>` from the page, else the conventional
`/favicon.ico` -- and prints the Shodan MurmurHash3, the MD5 (Censys / ZoomEye), SHA-256 and the
ready-made `icon_hash` lookups, so the first pass has the fingerprint whichever index the next step
needs. A local file argument is hashed directly, no network.

    python -m ctf favicon http://host.example/            fetch the declared icon, then hash it
    python -m ctf favicon http://host.example/favicon.ico  fetch that icon directly
    python -m ctf favicon ./favicon.ico                    hash a local file (offline)

Every network fetch runs `ctf.scope.check_url` first (this command runs outside intake's
network-denied engine guard), so only an in-scope host is contacted, and each redirect hop is
re-checked. A `.onion` host is refused here and routed to B-091 (Tor fetch + leaf-certificate engine):
`.onion` names resolve only inside Tor, which this clearnet fetch cannot reach.

Exit codes: 0 ok; 2 a bad argument or a fetch/parse error; 3 a `.onion` host (use B-091); 4 the URL is
out of the event scope.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .. import favicon as _favicon
from .. import scope as _scope

HELP = "fetch a service's declared favicon and record its Shodan/Censys hashes (B-089)"

REFUSED_EXIT = 4
ONION_EXIT = 3
ERROR_EXIT = 2

USER_AGENT = "ctf-tools-favicon/1 (B-089)"
MAX_ICON_BYTES = 4 * 1024 * 1024


class FetchError(Exception):
    """A favicon could not be fetched or hashed (not a scope refusal)."""


def _is_onion(url: str) -> bool:
    host, _ = _scope.split_url(url)
    return host.endswith(".onion")


class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    """Re-run the scope check on every redirect target, so a 30x can't walk off-scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _scope.check_url(newurl, what=f"favicon redirect to {newurl!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener():
    return urllib.request.build_opener(_ScopedRedirect())


def _get(url: str, timeout: float) -> tuple[bytes, str, str]:
    """GET `url` (already scope-checked) and return (body, content_type, final_url). Caps the body.
    `final_url` is where the response came from after any redirects (each re-scope-checked)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with _opener().open(req, timeout=timeout) as resp:
            body = resp.read(MAX_ICON_BYTES + 1)
            ctype = resp.headers.get("Content-Type", "")
            final_url = resp.geturl()
    except urllib.error.HTTPError as e:
        raise FetchError(f"{url}: HTTP {e.code} {e.reason}") from e
    except (urllib.error.URLError, OSError) as e:
        raise FetchError(f"{url}: {e}") from e
    if len(body) > MAX_ICON_BYTES:
        raise FetchError(f"{url}: body over {MAX_ICON_BYTES} bytes; not a favicon")
    return body, ctype, final_url


def fetch_favicon(url: str, *, timeout: float = 30.0, profile=None) -> tuple[bytes, str]:
    """Fetch the icon `url` declares and return (icon_bytes, icon_url). Scope-checks every request.
    `url` may be a page (its `<link rel=icon>`, else `/favicon.ico`) or an icon URL directly.
    Raises `scope.OutOfScope` for an out-of-scope host and `FetchError` for a fetch/parse failure."""
    if _is_onion(url):
        raise FetchError(f"{url}: .onion host -- resolves only inside Tor; use B-091 (Tor fetch engine)")
    _scope.check_url(url, what=f"favicon fetch {url!r}", profile=profile)
    path = urllib.parse.urlsplit(url).path
    leaf = path.rsplit("/", 1)[-1].lower()
    # A URL that already points at an icon: fetch it directly.
    if path.lower().endswith((".ico", ".icon")) or leaf.startswith("favicon"):
        body, _ctype, final_url = _get(url, timeout)
        return body, final_url
    # Otherwise it is a page: read its declared icon links.
    page, ctype, _final = _get(url, timeout)
    try:
        html = page.decode("utf-8", "replace")
    except Exception:  # pragma: no cover - decode("replace") does not raise
        html = page.decode("latin-1", "replace")
    links = _favicon.icon_links(html, base_url=url)
    last_err: Exception | None = None
    for icon_url in links:
        if _is_onion(icon_url):
            last_err = FetchError(f"{icon_url}: .onion icon -- use B-091")
            continue
        try:
            _scope.check_url(icon_url, what=f"favicon fetch {icon_url!r}", profile=profile)
            body, _c, final_url = _get(icon_url, timeout)
        except FetchError as e:
            last_err = e
            continue
        return body, final_url
    raise FetchError(f"{url}: no icon could be fetched ({last_err})" if last_err
                     else f"{url}: the page declares no icon")


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", help="an icon URL, a page URL, or a local icon file")
    p.add_argument("--timeout", type=float, default=30.0, metavar="S",
                   help="per-request timeout in seconds (default 30)")
    p.add_argument("--json", action="store_true", help="print the hashes and queries as one JSON object")


def _print_report(source: str, fh: _favicon.FaviconHashes, as_json: bool) -> None:
    queries = _favicon.icon_hash_queries(fh)
    if as_json:
        print(json.dumps({"source": source, **fh.to_dict(), "queries": queries}, indent=2))
        return
    print(f"favicon: {source}  ({fh.size} bytes)")
    print(f"  Shodan mmh3 (signed):  {fh.mmh3}")
    print(f"  mmh3 (unsigned):       {fh.mmh3_unsigned}")
    print(f"  MD5 (Censys/ZoomEye):  {fh.md5}")
    print(f"  SHA-256:               {fh.sha256}")
    print("ready-made icon_hash queries:")
    for engine, query in queries.items():
        print(f"  {engine:8} {query}")


def run(args: argparse.Namespace) -> int:
    target = args.target
    local = Path(target)
    if "://" not in target and local.is_file():
        fh = _favicon.fingerprint(local.read_bytes())
        _print_report(str(local), fh, args.json)
        return 0
    if "://" not in target:
        print(f"favicon: {target!r} is neither a URL (scheme://...) nor an existing file", file=sys.stderr)
        return ERROR_EXIT
    if _is_onion(target):
        host, _ = _scope.split_url(target)
        print(f"favicon: {host} is a .onion host; .onion names resolve only inside Tor. "
              f"Route it through B-091 (Tor fetch + leaf-certificate engine), not this clearnet fetch.",
              file=sys.stderr)
        return ONION_EXIT
    try:
        body, icon_url = fetch_favicon(target, timeout=args.timeout)
    except _scope.OutOfScope as e:
        print(f"favicon: {e}", file=sys.stderr)
        return REFUSED_EXIT
    except FetchError as e:
        print(f"favicon: {e}", file=sys.stderr)
        return ERROR_EXIT
    fh = _favicon.fingerprint(body)
    _print_report(icon_url, fh, args.json)
    return 0
