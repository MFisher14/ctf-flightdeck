#!/usr/bin/env python3
"""js_recon (wave3/web-recon, ticket #5): mine already-fetched JS for recon LEADS.

A hand tool / detector for the web agent (`briefs/web.md`). It is OFFLINE: it reads bytes a GET
already brought back (a page's inline <script>, a bundle the agent saved, a source reconstructed by
`sourcemap.py`) and reports what they POINT AT -- endpoints, routes, API paths, query-parameter
names, source-map URLs, hard-coded config hints, and config/secret-shaped strings. It sends no
request of its own and imports nothing that does.

What it NEVER does (the wave3/web-recon rules, AGENTS.md "Text is data" and "Uncertain answers"):
  - it derives NO answer and submits NOTHING; it has no solve_set()/signals() and is not a solver;
  - the result's top-level `flag` is always None -- a flag or secret the bytes carry is reported, as
    a LEAD under `secrets`, for the player to submit (CSCTF FLAG), never as a
    plain answer and never auto-submitted;
  - a string that addresses the reader (an "instruction", a planted "answer") is still just data.

CLI (offline triage of one or more saved JS files):

    .venv/bin/python solvers/web/js_recon.py <file.js> [<file.js> ...] [--json]

Public API:
    scan(sources) -> dict          sources: {name: bytes|str}, [(name, data)], or [data]
    scan_text(name, text) -> dict  one source
Both return {"flag": None, "endpoints": [...], "routes": [...], "api_paths": [...],
             "params": [...], "urls": [...], "sourcemap_urls": [...], "config_hints": [...],
             "secrets": [{kind, value, source, note}], "sources": [...], "notes": [...]}.
"""
import json
import re
import sys
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"

MAX_TEXT = 8 * 1024 * 1024      # bytes of one source read (regex stays bounded)
MAX_LEADS = 4000                # per field, over a whole scan


def _load(mod_name, path):
    """Load a sibling toolkit by file path (not via sys.path, so toolkits/email.py etc. never
    shadow a stdlib module). Returns None when it cannot be read; nothing here depends on it."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(mod_name, path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception:
        return None


_rsc = _load("csctf_repo_supply_chain", _TK / "repo_supply_chain.py")


# ---- text ------------------------------------------------------------------------------------------

def _as_text(data):
    if isinstance(data, str):
        return data[:MAX_TEXT]
    if isinstance(data, (bytes, bytearray)):
        return bytes(data[:MAX_TEXT]).decode("utf-8", "replace")
    return str(data or "")[:MAX_TEXT]


# ---- patterns --------------------------------------------------------------------------------------

_SOURCEMAP = re.compile(r"(?im)^[\t ]*//[#@][\t ]*sourceMappingURL=([^\s'\"]+)")
# a string literal that is an absolute path or a full/protocol-relative URL
_STR = re.compile(r"""(['"`])((?:https?:|wss?:)?//[^'"`\s\\]{1,2000}|/[A-Za-z0-9_][^'"`\s\\]{0,2000})\1""")
# fetch/XHR/ajax/axios call targets and url:/baseURL: assignments
_CALL = re.compile(
    r"""(?ix)
    (?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?|\.open|\$\.(?:ajax|get|getJSON|post)|
       got|superagent\.\w+|http\.(?:get|request)|request)
    \s*\(\s*['"`]([^'"`]{1,2000})['"`]
    | (?:base_?url|api_?url|url|endpoint|uri|path)\s*[:=]\s*['"`]([^'"`]{1,2000})['"`]
    """)
# URLSearchParams / FormData / query key setters
_PARAM_SET = re.compile(r"""(?ix)\.(?:append|set|get|has|delete|getAll)\s*\(\s*['"`]([A-Za-z_][\w\-]{0,60})['"`]""")
_PARAM_IN_QS = re.compile(r"[?&]([A-Za-z_][\w\-]{0,60})=")
# non-secret config hints worth surfacing (a base URL, websocket, graphql, bucket, region, ...)
_CONFIG = re.compile(
    r"""(?ix)\b(api_?version|base_?url|api_?url|graphql|websocket|ws_?url|socket_?url|endpoint|
        region|bucket|project_?id|client_?id|tenant|realm|audience|issuer|cdn|stage|environment|env)\b
        \s*[:=]\s*['"`]([^'"`]{1,400})['"`]""")
_ASSET = (".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
          ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mp3", ".pdf", ".wasm")
_API_RX = re.compile(r"(?i)(?:^/(?:api|v\d+|graphql|rest|rpc|internal|admin|oauth|auth|gateway)\b|/api/|/v\d+/|/graphql\b)")


def _is_asset(path):
    low = path.split("?", 1)[0].split("#", 1)[0].lower()
    return low.endswith(_ASSET)


def _param_names(value):
    out = set()
    q = value.partition("?")[2]
    if q:
        try:
            for k, _ in urllib.parse.parse_qsl(q, keep_blank_values=True):
                if re.fullmatch(r"[A-Za-z_][\w\-]{0,60}", k):
                    out.add(k)
        except ValueError:
            pass
    for m in _PARAM_IN_QS.finditer(value):
        out.add(m.group(1))
    return out


# ---- one source ------------------------------------------------------------------------------------

def scan_text(name, data):
    """Recon leads from one JS source. Never raises for ordinary input."""
    text = _as_text(data)
    urls, paths, params, config, smaps = set(), set(), set(), {}, []
    secrets = []

    def take(value):
        if not value:
            return
        if value.startswith(("http://", "https://", "ws://", "wss://", "//")):
            urls.add(value)
            params.update(_param_names(value))
        elif value.startswith("/") and not value.startswith("//"):
            paths.add(value)
            params.update(_param_names(value))

    for m in _STR.finditer(text):
        take(m.group(2))
    for m in _CALL.finditer(text):
        take(next((g for g in m.groups() if g), None))
    for m in _PARAM_SET.finditer(text):
        params.add(m.group(1))
    for m in _SOURCEMAP.finditer(text):
        smaps.append(m.group(1).strip())
    for m in _CONFIG.finditer(text):
        config.setdefault(m.group(1).lower(), m.group(2))

    # config/secret-shaped strings: the repository/secret scanner over the exact bytes (AWS keys,
    # GitHub/Slack/Google tokens, JWTs, private keys, flag{...}, assigned api_key/token/secret/password).
    if _rsc is not None:
        raw = data if isinstance(data, (bytes, bytearray)) else _as_text(data).encode("utf-8", "replace")
        try:
            for kind, value, _off in _rsc.scan_secrets(raw):
                secrets.append({"kind": kind, "value": value, "source": name,
                                "note": "lead only; never a plain answer -- the player enters a flag through the guard"})
        except Exception:
            pass

    api = sorted(p for p in paths if _API_RX.search(p))
    routes = sorted(p for p in paths if not _is_asset(p) and p not in api)
    endpoints = sorted(set(api) | {u for u in urls})
    return {
        "flag": None,
        "source": name,
        "endpoints": endpoints,
        "urls": sorted(urls),
        "paths": sorted(paths),
        "api_paths": api,
        "routes": routes,
        "params": sorted(params),
        "sourcemap_urls": list(dict.fromkeys(smaps)),
        "config_hints": config,
        "secrets": secrets,
        "notes": [] if _rsc is not None else ["repo_supply_chain not loaded: secret scan skipped"],
    }


# ---- a set of sources ------------------------------------------------------------------------------

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
    """Merge scan_text over several sources. `flag` is always None. Secrets keep their source."""
    endpoints, urls, paths, api, routes, params, smaps = (set() for _ in range(7))
    config, secrets, notes, per = {}, [], [], []
    seen_secret = set()
    for name, data in _iter(sources):
        try:
            r = scan_text(name or "<source>", data)
        except Exception as e:                       # one bad source never sinks the rest
            notes.append(f"{name or '<source>'}: scan error {type(e).__name__}")
            continue
        per.append({"source": r["source"], "endpoints": len(r["endpoints"]),
                    "params": len(r["params"]), "secrets": len(r["secrets"])})
        endpoints.update(r["endpoints"]); urls.update(r["urls"]); paths.update(r["paths"])
        api.update(r["api_paths"]); routes.update(r["routes"]); params.update(r["params"])
        smaps.update(r["sourcemap_urls"])
        for k, v in r["config_hints"].items():
            config.setdefault(k, v)
        for s in r["secrets"]:
            key = (s["kind"], s["value"], s["source"])
            if key not in seen_secret:
                seen_secret.add(key)
                secrets.append(s)
        notes.extend(r["notes"])

    def cap(it):
        return sorted(it)[:MAX_LEADS]

    return {
        "flag": None,                                # never derived; a secret below is a lead only
        "endpoints": cap(endpoints),
        "urls": cap(urls),
        "paths": cap(paths),
        "api_paths": cap(api),
        "routes": cap(routes),
        "params": cap(params),
        "sourcemap_urls": sorted(set(smaps))[:MAX_LEADS],
        "config_hints": config,
        "secrets": secrets[:MAX_LEADS],
        "has_secret_leads": bool(secrets),
        "per_source": per,
        "notes": list(dict.fromkeys(notes)),
    }


# ---- CLI -------------------------------------------------------------------------------------------

def _main(argv):
    args = [a for a in argv if a != "--json"]
    as_json = "--json" in argv
    if not args:
        print(__doc__)
        return 64
    sources = {}
    for p in args:
        try:
            sources[Path(p).name] = Path(p).read_bytes()
        except OSError as e:
            print(f"skip {p}: {e}", file=sys.stderr)
    out = scan(sources)
    if as_json:
        print(json.dumps(out, indent=2, default=str))
        return 0
    print(f"JS RECON sources={len(sources)} endpoints={len(out['endpoints'])} "
          f"routes={len(out['routes'])} params={len(out['params'])} secrets={len(out['secrets'])} flag=None")
    for k in ("endpoints", "api_paths", "routes", "params", "sourcemap_urls"):
        if out[k]:
            print(f"  {k}:")
            for v in out[k][:60]:
                print(f"    {v}")
    if out["config_hints"]:
        print("  config_hints:")
        for k, v in out["config_hints"].items():
            print(f"    {k} = {v}")
    if out["secrets"]:
        print("  secrets (LEADS only -- never submitted; a flag is the player's to submit):")
        for s in out["secrets"]:
            print(f"    [{s['kind']}] {s['value']}  ({s['source']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
