#!/usr/bin/env python3
"""sourcemap (wave3/web-recon, ticket #7): reconstruct original source from an already-fetched .map.

A hand tool / detector for the web agent (`briefs/web.md`). It is OFFLINE: given the bytes of a
JavaScript source map (`*.js.map`, a JSON document a GET already brought back), it parses the JSON
and reconstructs the original source FILE NAMES and, when the map carries `sourcesContent`, their
CONTENT -- then surfaces the routes, endpoints and parameter names those sources name (by handing
the reconstructed text to `js_recon`). It sends no request and derives no answer.

The wave3/web-recon rules hold exactly as in js_recon: no solve_set()/signals(); the result's
top-level `flag` is always None; a flag or secret in the reconstructed source is reported as a LEAD
under `secrets` (for the player to submit), never a plain answer and never submitted; text
that addresses the reader is data, not an instruction.

CLI:
    .venv/bin/python solvers/web/sourcemap.py <file.js.map> [...] [--json] [--dump DIR]

    --dump DIR writes each reconstructed source under DIR (paths sanitised; webpack:// etc. stripped,
    no absolute path, no `..`), so an agent can read them; it is OPT-IN and writes nowhere by default.

Public API:
    reconstruct(data, name="") -> dict   {flag, version, file, source_root, sources:[{name, path,
                                           content, bytes, truncated}], source_names, endpoints,
                                           routes, api_paths, params, urls, config_hints, secrets, notes}
    sanitize_name(name) -> str           a map source name as a safe relative path
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import js_recon as _jr  # noqa: E402  (sibling detector; offline, stdlib + repo_supply_chain only)
import security_json as _security_json  # noqa: E402 -- target-controlled map contract

MAX_MAP = 64 * 1024 * 1024         # bytes of one .map parsed
MAX_CONTENT = 4 * 1024 * 1024      # bytes of one reconstructed source kept
MAX_SOURCES = 20000


def _as_text(data):
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).decode("utf-8", "strict")
    return str(data or "")


_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)
_BUNDLER = re.compile(r"^(?:webpack|ng|rollup|vite|turbopack)://", re.I)


def sanitize_name(name):
    """A map source name as a SAFE relative path for display or an opt-in dump: the bundler scheme
    (`webpack://`, `ng://`, ...) and any authority are stripped, leading slashes and `.`/`..`
    segments removed, so nothing can escape a dump directory or name an absolute path. The first
    real PATH segment is kept (`webpack:///src/a.js` -> `src/a.js`)."""
    s = str(name or "").strip()
    m = _BUNDLER.match(s)
    if m:
        rest = s[m.end():]                            # authority is up to the first '/', and is dropped
        authority, sep, path = rest.partition("/")
        s = path if sep else rest
    elif _SCHEME.match(s):                            # a real URL source: keep host + path, drop scheme
        s = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", s, flags=re.I)
    s = s.replace("\\", "/")
    segs = [seg for seg in s.split("/") if seg not in ("", ".", "..")]
    return "/".join(segs) or "source"


def reconstruct(data, name=""):
    """Parse one source map and reconstruct its sources + recon leads. `flag` is always None.
    A document that is not a usable source map returns empty leads (no crash, no false flag)."""
    empty = {"flag": None, "name": name, "version": None, "file": None, "source_root": "",
             "sources": [], "source_names": [], "endpoints": [], "urls": [], "paths": [],
             "api_paths": [], "routes": [], "params": [], "config_hints": {}, "secrets": [],
             "has_secret_leads": False, "notes": []}
    try:
        if isinstance(data, (bytes, bytearray)) and len(data) > MAX_MAP:
            raise ValueError("source map byte limit")
        text = _as_text(data)
        if len(text) > MAX_MAP or len(text.encode("utf-8")) > MAX_MAP:
            raise ValueError("source map byte limit")
        doc = _security_json.loads(
            text,
            max_chars=MAX_MAP,
            max_members=MAX_SOURCES * 8 + 1024,
            max_nodes=MAX_SOURCES * 16 + 4096,
            max_depth=64,
        )
    except Exception:
        empty["notes"] = ["not JSON: not a source map"]
        return empty
    if not isinstance(doc, dict) or not isinstance(doc.get("sources"), list):
        empty["notes"] = ["no `sources` array: not a source map"]
        return empty

    root = str(doc.get("sourceRoot") or "")
    raw_sources = doc["sources"][:MAX_SOURCES]
    contents = doc.get("sourcesContent")
    if not isinstance(contents, list):
        contents = []
    rebuilt, names, scan_inputs, notes = [], [], [], []
    for i, src in enumerate(raw_sources):
        raw = str(src if src is not None else f"source_{i}")
        joined = (root.rstrip("/") + "/" + raw.lstrip("/")) if root and not _SCHEME.match(raw) else raw
        safe = sanitize_name(joined)
        names.append(safe)
        body = contents[i] if i < len(contents) and isinstance(contents[i], str) else None
        trunc = False
        if body is not None and len(body) > MAX_CONTENT:
            body, trunc = body[:MAX_CONTENT], True
        rebuilt.append({"name": safe, "path": joined, "content": body,
                        "bytes": (len(body) if body is not None else None), "truncated": trunc})
        if body:
            scan_inputs.append((safe, body))
    if not any(r["content"] is not None for r in rebuilt):
        notes.append("the map has no sourcesContent: file names reconstructed, content not available")

    leads = _jr.scan(scan_inputs) if scan_inputs else _jr.scan([])
    out = {
        "flag": None,                                # never derived from a reconstructed source
        "name": name,
        "version": doc.get("version"),
        "file": doc.get("file"),
        "source_root": root,
        "sources": rebuilt,
        "source_names": names,
        "endpoints": leads["endpoints"],
        "urls": leads["urls"],
        "paths": leads["paths"],
        "api_paths": leads["api_paths"],
        "routes": leads["routes"],
        "params": leads["params"],
        "config_hints": leads["config_hints"],
        "secrets": leads["secrets"],                 # LEADS only; each marked, never an answer
        "has_secret_leads": bool(leads["secrets"]),
        "notes": notes + leads["notes"],
    }
    return out


def dump_sources(result, out_dir):
    """OPT-IN: write each reconstructed source with content under out_dir (names already sanitised).
    Returns [written paths]. Never writes outside out_dir."""
    base = Path(out_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)
    written = []
    for s in result.get("sources", []):
        if s.get("content") is None:
            continue
        target = (base / s["name"]).resolve()
        if base not in target.parents and target != base:   # defence in depth over sanitize_name
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(s["content"], encoding="utf-8")
        written.append(str(target))
    return written


def _main(argv):
    as_json = "--json" in argv
    dump = None
    args = []
    it = iter(argv)
    for a in it:
        if a == "--json":
            continue
        if a == "--dump":
            dump = next(it, None)
            continue
        args.append(a)
    if not args:
        print(__doc__)
        return 64
    for p in args:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"skip {p}: {e}", file=sys.stderr)
            continue
        r = reconstruct(data, Path(p).name)
        if as_json:
            print(json.dumps(r, indent=2, default=str))
        else:
            with_content = sum(1 for s in r["sources"] if s["content"] is not None)
            print(f"SOURCEMAP {p} sources={len(r['sources'])} with_content={with_content} "
                  f"endpoints={len(r['endpoints'])} routes={len(r['routes'])} params={len(r['params'])} "
                  f"secrets={len(r['secrets'])} flag=None")
            for nm in r["source_names"][:80]:
                print(f"    {nm}")
            if r["secrets"]:
                print("  secrets (LEADS only -- never submitted; a flag is the player's to submit):")
                for s in r["secrets"]:
                    print(f"    [{s['kind']}] {s['value']}  ({s['source']})")
        if dump:
            written = dump_sources(r, dump)
            print(f"  wrote {len(written)} source(s) under {dump}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
