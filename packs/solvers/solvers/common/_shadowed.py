"""Load one exact module file when another engine folder has a module of the same name (R-10).

Some engines share a basename across folders (docs/coverage/duplicate-basenames.toml): a reader in
solvers/common and its toolkit face in solvers/toolkits (classical, modern_crypto, ...), or one module
per CSCTF lane (generic, respell, ...). On the engine sys.path (`ctf run`, `tools/ctfpy`, the test
suite) the first folder wins a flat `import <name>`, so a flat import from any other folder gets the
wrong file, which fails later with an AttributeError far from the cause.

    from _shadowed import common_module, module_at
    modern_crypto = common_module("modern_crypto")        # solvers/common/modern_crypto.py, always
    generic = module_at(HERE / "generic.py", "binary_generic")

Both return the module already imported for that file when there is one (under its own name, the
alias, or its `solvers.<lane>.<name>` package name), so a caller and its tests share one module
object; otherwise they load the file by path under the alias. A missing file raises
ModuleNotFoundError naming it.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _same_file(mod, target: Path) -> bool:
    f = getattr(mod, "__file__", None)
    try:
        return bool(f) and Path(f).resolve() == target
    except OSError:
        return False


def module_at(path: Path | str, alias: str):
    """The module for the file `path`: an already-imported one if any, else loaded under `alias`."""
    target = Path(path).resolve()
    if not target.is_file():
        raise ModuleNotFoundError(f"{target} does not exist", name=alias)
    names = (target.stem, alias, f"solvers.{target.parent.name}.{target.stem}")
    for key in names:
        mod = sys.modules.get(key)
        if mod is not None and _same_file(mod, target):
            return mod
    spec = importlib.util.spec_from_file_location(alias, target)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(alias, None)
        raise
    return mod


def common_module(name: str):
    """solvers/common/<name>.py, whichever folder a flat `import <name>` would pick."""
    return module_at(HERE / f"{name}.py", f"{name}_common")
