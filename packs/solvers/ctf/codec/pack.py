"""Codec breadth packs for the shared graph (B-163): more decoders, loaded by path through ctf.packs.

A breadth pack is a module whose decoder list adds edges to the graph. The one pack so far is the
warmups decoder set (`solvers/warmups/crib_decode.py`, its `STRICT` list: base91/62/36, uu, yEnc, xx,
z85, braille, NATO, EBCDIC, the escape and dump forms, ...), the widest codec collection in the tree.
Its decoders join the graph as `pack` codecs named `<pack>.<name>` (e.g. `warmups.b91`), so a chain
always says which edges came from a pack. Names the core set already implements are left out, and so
are the pack's letter shifts (rot13 is a loose step in the graph, not a representation change).

The oracle check: a pack decoder is not trusted to be all-or-nothing the way the core codecs are, so
the graph never stops at a pack decode by itself. A reading is an answer only when the goal oracle
validates the final state (always true of the graph), and pack codecs are asked only on states up to
graph.PACK_MAX_STATE bytes. A pack decoder that raises is recorded in SearchResult.errors by name.

    from ctf.codec import pack, Graph
    g = Graph(core() + pack.load("warmups"))

A missing or broken pack raises ctf.packs.PackMissing / PackLoadError naming it (no silent fallback);
an unknown pack name raises PackError.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from .. import packs as _packs
from .. import paths as _paths
from . import codecs as C

# name -> (module name, repo-relative path, attribute holding the decoder list)
PACKS = {
    "warmups": ("crib_decode", "solvers/warmups/crib_decode.py", "STRICT"),
}
SKIP = frozenset({"rot13", "compress"})     # loose in the graph / the core decompressors cover it


def names() -> list[str]:
    return sorted(PACKS)


def _file_of(mod) -> Optional[Path]:
    f = getattr(mod, "__file__", None)
    return Path(f).resolve() if f else None


def _wrap(fn):
    def dec(b: bytes):
        out = fn(b)
        if isinstance(out, str):
            out = out.encode("utf-8", "surrogateescape")
        return out if isinstance(out, (bytes, bytearray)) else None
    return dec


def load(name: str, root: Optional[Path] = None) -> tuple:
    """The pack's codecs (kind `pack`), core names excluded. PackError for an unknown name; PackMissing /
    PackLoadError when its module is not there or does not import; PackLoadError when it has no decoder
    list."""
    if name not in PACKS:
        raise _packs.PackError(name, Path("-"), f"unknown codec pack (known: {', '.join(names())})")
    module, rel, attr = PACKS[name]
    path = Path(root or _paths.repo_root()) / rel
    # The module may already be in sys.modules (fastlane imports crib_decode under the same name). It is
    # reused only when it was loaded from this very path; a pack under another root is loaded fresh and
    # kept out of sys.modules, so `root` is never ignored and never replaces the module fastlane uses.
    cached = sys.modules.get(module)
    same = cached is not None and _file_of(cached) == path.resolve()
    use_cache = same or (cached is None and root is None)
    mod = _packs.load_module(module, path, pack=f"codec pack {name}", cache=use_cache)
    decoders = getattr(mod, attr, None)
    if not isinstance(decoders, (list, tuple)) or not decoders:
        raise _packs.PackLoadError(f"codec pack {name}", path, f"no decoder list {attr!r}")
    core = {c.name for c in C.core()}
    out, seen = [], set()
    for fn in decoders:
        short = getattr(fn, "__name__", "")
        short = short[2:] if short.startswith("d_") else short
        if not short or short in core or short in SKIP or short in seen:
            continue
        seen.add(short)
        out.append(C.Codec(f"{name}.{short}", C.PACK, _wrap(fn), (fn.__doc__ or "").strip().split("\n")[0]))
    if not out:
        raise _packs.PackLoadError(f"codec pack {name}", path, "every decoder duplicates the core set")
    return tuple(out)
