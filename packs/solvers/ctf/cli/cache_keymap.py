"""ctf cache-keymap — front-vs-backend cache-key-confusion report over saved traffic (B-105).

    python -m ctf cache-keymap --request REQ --response RESP [--source SRC]
        [--marker M] [--path RAW ...] [--seed BASE ...] [--front COMP ...] [--backend COMP ...]
        [--exfil-read PATH] [--json]

Offline only: it reads saved request/response/source bytes and candidate request targets, maps
which inputs the front cache keys versus which the backend reads, and flags cache-key anomalies
(unkeyed inputs, %2e%2e normalisation collisions). It never sends traffic. Assembling the chain
through an authenticated bot and a second cache zone stays a human step; the report says so.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ctf.engines import layout

HELP = "front/back cache-key-confusion report over saved traffic (offline; flags anomalies only)"


def _load_module():
    """Import the solvers/web cache_analysis engine on the engine sys.path (lazily, at run time)."""
    for p in layout.sys_path():
        if p not in sys.path:
            sys.path.insert(0, p)
    import cache_analysis  # noqa: E402 -- solvers/web engine on the engine path
    return cache_analysis


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--request", required=True, help="saved raw HTTP request file")
    p.add_argument("--response", required=True, help="saved raw HTTP response file")
    p.add_argument("--source", help="saved front/back cache-key or routing source (optional)")
    p.add_argument("--marker", help="inert marker string to check for reflection")
    p.add_argument("--path", action="append", default=[], metavar="RAW",
                   help="candidate raw request target to test for a normalisation collision (repeatable)")
    p.add_argument("--seed", action="append", default=[], metavar="BASE",
                   help="base path: add it and its parser_differential normalisation variants "
                        "(%%2e, %%2e%%2e, //, ;) as candidates (repeatable)")
    p.add_argument("--front", action="append", default=[], metavar="COMP",
                   help="explicit front-keyed component, e.g. path or header:x-forwarded-host (repeatable)")
    p.add_argument("--backend", action="append", default=[], metavar="COMP",
                   help="explicit backend-read component (repeatable)")
    p.add_argument("--exfil-read", metavar="PATH",
                   help="stage an inert authenticated-bot exfil plan reading this path "
                        "(needs a candidate poison key from --path or --seed)")
    p.add_argument("--json", action="store_true", help="print the full JSON report")


def _read_bytes(cache, label: str, path: str) -> bytes:
    data = Path(path).read_bytes()
    if not data:
        raise cache.CacheAnalysisError(f"{label} file {path!r} is empty")
    return data


def run(args: argparse.Namespace) -> int:
    cache = _load_module()
    try:
        request = _read_bytes(cache, "request", args.request)
        response = _read_bytes(cache, "response", args.response)
        source = _read_bytes(cache, "source", args.source) if args.source else None
        candidates: list[str] = list(args.path)
        for base in getattr(args, "seed", []) or []:
            for item in cache.seed_candidate_paths(base):
                if item not in candidates:
                    candidates.append(item)
        report = cache.analyze_cache_key_confusion(
            request, response, source=source, marker=args.marker,
            candidate_paths=tuple(candidates),
            front_keyed=tuple(args.front) or None,
            backend_used=tuple(args.backend) or None,
            exfil_read_path=args.exfil_read,
        )
    except cache.CacheAnalysisError as e:
        print(f"ctf cache-keymap: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"ctf cache-keymap: cannot read input: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    primitives = report["primitives"]
    print(f"cache-key primitives: {len(primitives)}  collisions: {len(report['collisions'])}  "
          f"(offline, {report['network_requests']} requests)")
    for item in primitives:
        print(f"  [{item['severity']}/{item['confidence']}] {item['kind']}  {item['primitive_id']}")
        for line in item["evidence"]:
            print(f"      - {line}")
    status = report["key_map_status"]
    if status == cache.KEY_MAP_FRONT_UNKNOWN:
        print("cache-key map: front cache key could not be determined (no hash_data/proxy_cache_key "
              "in --source and no --front), so no input is flagged as unkeyed")
    elif status == cache.KEY_MAP_BACKEND_UNKNOWN:
        print("cache-key map: backend inputs could not be determined (no --backend and none found "
              "in --source), so no input is flagged as unkeyed")
    elif status == cache.KEY_MAP_EMPTY:
        print("cache-key map: no key information (give --source, or --front and --backend)")
    if report["key_map"]:
        print(f"cache-key map ({status}):")
        for row in report["key_map"]:
            tag = row["primitive"] or "keyed+used"
            print(f"  {row['component']:<28} front={row['keyed_front']!s:<5} backend={row['used_backend']!s:<5} {tag}")
    if report["bot_plan"]:
        plan = report["bot_plan"]
        print(f"bot exfil plan (inert, requires live bot={plan['requires_live_bot']}):")
        for step in plan["steps"]:
            print(f"  {step['order']}. [{step['actor']}] {step['action']}")
        print(f"  human step: {plan['human_step']}")
    print(f"note: {report['caution']}")
    return 0
