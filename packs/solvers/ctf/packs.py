"""Loading a pack by path, with a named error for every miss (B-001b).

A *pack* is a module that routing or a lane loads by file path rather than by import: a category
toolkit named in `solvers/toolkits/registry.py`, the registry itself, a metadata reader pack beside
`solvers/metadata-forensics/properties_strict.py`. Before B-001b each loader caught the miss and went
on without it (bundle routing ran with no registry at CSCTF and Pink and nobody saw). Now:

    load_module(module_name, path, pack=None, cache=True)   the module, or
        PackMissing      the file is not there
        PackLoadError    the file is there and raised while importing (the cause is chained)
    toolkit_registry(root=None)                             solvers/toolkits/registry.py, or
        RegistryLoadError                                   (missing or broken)

Every error names the pack and the path. An *optional external tool* (a PyPI package or a binary)
is not a pack: a module may degrade without one, but only by naming it.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

__all__ = ["PackError", "PackMissing", "PackLoadError", "RegistryLoadError",
           "load_module", "toolkit_registry", "REGISTRY_MODULE"]

REGISTRY_MODULE = "ctf_toolkit_registry"   # the one module name the registry is loaded under


class PackError(RuntimeError):
    """A pack could not be loaded. `pack` names it, `path` is the file looked for."""

    def __init__(self, pack: str, path: Path | str, reason: str):
        self.pack, self.path, self.reason = pack, Path(path), reason
        super().__init__(f"pack {pack!r} ({path}): {reason}")


class PackMissing(PackError):
    """The pack's file is not there."""


class PackLoadError(PackError):
    """The pack's file is there but raised while importing."""


class RegistryLoadError(PackError):
    """solvers/toolkits/registry.py is missing or does not import: no bundle routing, no toolkit map."""


def load_module(module_name: str, path: Path | str, pack: str | None = None, cache: bool = True,
                missing: type[PackError] = PackMissing, broken: type[PackError] = PackLoadError) -> ModuleType:
    """Import the file `path` as module `module_name`.

    cache=True: the module is kept in sys.modules under `module_name` (a second call returns it) and is
    in sys.modules while it executes (dataclasses and pickling need that). cache=False: a fresh module
    each call, never put in sys.modules (the metadata lane's `_load_beside` semantics).
    A run-time stop that is not an Exception (KeyboardInterrupt, a runner's BaseException timeout)
    passes through unchanged; SystemExit raised by the pack's import is a load error."""
    path = Path(path)
    pack = pack or path.stem
    if cache and module_name in sys.modules:
        return sys.modules[module_name]
    if not path.is_file():
        raise missing(pack, path, "file not there")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise broken(pack, path, "not an importable Python file")
    mod = importlib.util.module_from_spec(spec)
    if cache:
        sys.modules[module_name] = mod
    try:
        spec.loader.exec_module(mod)
    except (Exception, SystemExit) as e:
        if cache:
            sys.modules.pop(module_name, None)
        raise broken(pack, path, f"{type(e).__name__}: {str(e)[:300]}") from e
    except BaseException:
        if cache:
            sys.modules.pop(module_name, None)
        raise
    return mod


def toolkit_registry(root: Path | str | None = None) -> ModuleType:
    """solvers/toolkits/registry.py of this checkout (or of `root`), loaded once under REGISTRY_MODULE.
    RegistryLoadError when it is missing or does not import."""
    if root is None:
        from . import paths
        root = paths.repo_root()
    path = Path(root) / "solvers" / "toolkits" / "registry.py"
    cached = sys.modules.get(REGISTRY_MODULE)
    if cached is not None and Path(getattr(cached, "__file__", "") or "").resolve() == path.resolve():
        return cached
    if cached is not None:
        sys.modules.pop(REGISTRY_MODULE, None)    # another checkout's registry: load this one
    return load_module(REGISTRY_MODULE, path, pack="toolkit registry",
                       missing=RegistryLoadError, broken=RegistryLoadError)
