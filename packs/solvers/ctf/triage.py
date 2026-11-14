"""Route a pulled challenge to the right engines and playbook.

Given a challenge's category, description and downloaded files, suggest which solver engines/CLIs to
reach for and which docs/playbooks/<category>.md to follow. This is advice for the player/agent, not an
autosolver: it narrows the search, it does not submit anything.

The engines are ranked by the priorities in their manifests (docs/CONTRACTS.md section 6): suggest()
reads the route table generated from every `<module>.manifest.toml` (ctf/engines/routetable.py). To
route an engine, edit its manifest and run `python -m ctf engines generate`; nothing here names an
engine.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
for _d in ("solvers/common", "solvers/toolkits"):
    p = str(REPO / _d)
    if p not in sys.path:
        sys.path.insert(0, p)

# The canonical event categories: each has a docs/playbooks/<category>.md. Routing is not here: every
# engine's routes live in its <module>.manifest.toml, and suggest() ranks them from the route table
# generated from those manifests (ctf/engines/route_table.jsonl, `python -m ctf engines generate`).
CATEGORIES = ("crypto", "web", "pwn", "reverse", "forensics", "stego", "networking", "ics", "mobile", "ml",
              "osint", "linux", "windows", "opsec", "programming", "misc", "sanity")
ALIASES = {"rev": "reverse", "re": "reverse", "reversing": "reverse", "cryptography": "crypto",
           "binary": "pwn", "binary exploitation": "pwn", "network": "networking",
           "industrial control systems": "ics", "scada": "ics", "machine learning": "ml",
           "forensic": "forensics", "steganography": "stego", "stegano": "stego",
           "win": "windows", "operational security": "opsec", "operational-security": "opsec",
           "opsec / operational security": "opsec", "cloud": "opsec", "container": "opsec",
           "cloud / container": "opsec", "prog": "programming"}


def canonical_category(cat: str) -> str:
    c = (cat or "").strip().lower()
    return ALIASES.get(c, c)


def identify_files(files_dir: Path) -> list[tuple[str, str]]:
    """[(filename, one-line identity)] for each downloaded file, read by solvers/common/triage.py's
    identify(). That module is loaded by path (ctf/packs.py): a missing or broken one raises PackMissing /
    PackLoadError (B-001b) instead of every file quietly getting only its magic bytes."""
    from .packs import load_module
    ident = load_module("ctf_common_triage", REPO / "solvers" / "common" / "triage.py",
                        pack="solvers/common/triage.py").identify
    out = []
    for f in sorted(Path(files_dir).glob("**/*")):
        if not f.is_file():
            continue
        why = ""
        try:
            desc = str(ident(f.read_bytes()))[:120]
        except Exception as e:      # one file the reader cannot name: said on its line, never blank
            desc, why = "", f"identify() raised {type(e).__name__}; "
        if not desc:
            head = f.read_bytes()[:16]
            desc = why + "%d bytes, magic %s" % (f.stat().st_size, head[:4].hex())
        out.append((str(f.relative_to(files_dir)), desc))
    return out


def suggest(category: str, description: str = "", files_dir: Path | None = None) -> dict:
    """The engines worth trying, ranked by manifest route priority (best first).

    Every engine whose route matches (category, a keyword of the description, a downloaded file) is
    listed once, at its best matching route's priority; ties sort by engine id. The routes come from
    the generated route table, so a missing or malformed table raises RouteTableError naming the fix."""
    from .engines import routetable
    cat = canonical_category(category)
    hits = routetable.match(cat, description, files_dir)
    files = identify_files(files_dir) if files_dir and Path(files_dir).is_dir() else []
    return {
        "category": cat,
        "playbook": f"docs/playbooks/{cat}.md",
        "engines": [h.path for h in hits],
        "routes": [{"engine": h.path, "id": h.id, "class": h.cls, "priority": h.priority, "reason": h.reason}
                   for h in hits],
        "files": files,
    }


def _category_engines() -> dict[str, list[str]]:
    """category -> engines its bare-category routes always suggest there, best priority first."""
    from .engines import routetable
    best: dict[str, dict[str, tuple[int, str]]] = {}
    for r in routetable.load():
        if r.keywords or r.files:
            continue
        for c in r.category:
            cur = best.setdefault(c, {}).get(r.path)
            if cur is None or r.priority > cur[0]:
                best[c][r.path] = (r.priority, r.id)
    return {c: [p for p, _ in sorted(d.items(), key=lambda kv: (-kv[1][0], kv[1][1]))]
            for c, d in sorted(best.items())}


def _import_only() -> frozenset[str]:
    """Routed engines whose manifest class is `library`: no CLI, so `python <path> <file>` is a no-op."""
    from .engines import routetable
    return frozenset(r.path for r in routetable.load() if r.cls == "library")


def __getattr__(name: str):
    # Read-only views of the route table under the names the carried router used; computed on use so
    # they always match the table.
    if name == "CATEGORY_ENGINES":
        return _category_engines()
    if name == "IMPORT_ONLY":
        return _import_only()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def render(s: dict) -> str:
    lines = [f"category: {s['category']}", f"playbook: {s['playbook']}", "engines to try first:"]
    for r in s["routes"]:
        why = f"  # priority {r['priority']}: {r['reason']}"
        if r["class"] == "library":
            lines.append(f"  (import-only, no CLI — call from Python per the playbook) {r['engine']}{why}")
        else:
            lines.append(f"  .venv/bin/python {r['engine']} <file>{why}")
    if s["files"]:
        lines.append("files:")
        lines += [f"  {n}: {d}" for n, d in s["files"]]
    return "\n".join(lines)
