#!/usr/bin/env python3
"""Offline readiness check for the static-RE engines.

This imports the three byte-analysis/emulation libraries those engines depend on
(capstone, unicorn, lief) and checks the exact entry points they use.  It reads no
challenge, token or network state and performs no emulation.
"""
from __future__ import annotations

import importlib
import json
import sys

REQUIRED = {
    "capstone": ("Cs", "CS_ARCH_X86", "CS_MODE_64"),
    "unicorn": ("Uc", "UC_ARCH_X86", "UC_MODE_64"),
    "lief": ("parse",),
}


def version(module) -> str:
    value = getattr(module, "__version__", None)
    if value is None and hasattr(module, "__lief_version__"):
        value = module.__lief_version__
    return str(value or "unknown").replace(" ", "_")[:80]


def inspect(importer=importlib.import_module) -> tuple[dict[str, str], list[str]]:
    versions, problems = {}, []
    for name, attrs in REQUIRED.items():
        try:
            module = importer(name)
        except Exception as exc:
            problems.append(f"{name}: import {type(exc).__name__}: {str(exc).splitlines()[0][:120]}")
            continue
        versions[name] = version(module)
        missing = [attr for attr in attrs if not hasattr(module, attr)]
        if missing:
            problems.append(f"{name}: missing {','.join(missing)}")
        if name in ("capstone", "unicorn") and hasattr(module, attrs[0]) and not callable(getattr(module, attrs[0])):
            problems.append(f"{name}: {attrs[0]} is not callable")
        if name == "lief" and hasattr(module, "parse") and not callable(module.parse):
            problems.append("lief: parse is not callable")
    return versions, problems


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv not in ([], ["--json"]):
        print("usage: static_re_check.py [--json]", file=sys.stderr)
        return 64
    versions, problems = inspect()
    if argv == ["--json"]:
        print(json.dumps({"ok": not problems, "versions": versions, "problems": problems}, sort_keys=True))
    elif problems:
        print("STATIC_RE_IMPORTS FAIL " + " | ".join(problems))
    else:
        detail = " ".join(f"{name}={versions[name]}" for name in sorted(versions))
        print(f"STATIC_RE_IMPORTS OK {detail}")
    return 0 if not problems else 2


if __name__ == "__main__":
    raise SystemExit(main())
