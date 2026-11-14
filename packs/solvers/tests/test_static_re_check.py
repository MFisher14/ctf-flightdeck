#!/usr/bin/env python3
"""No-network contract checks for tools/static_re_check.py."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("static_re_check_under_test", ROOT / "tools" / "static_re_check.py")
CHECK = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CHECK)


def fake(name):
    rows = {
        "capstone": SimpleNamespace(__version__="5.test", Cs=lambda: None, CS_ARCH_X86=1, CS_MODE_64=2),
        "unicorn": SimpleNamespace(__version__="2.test", Uc=lambda: None, UC_ARCH_X86=1, UC_MODE_64=2),
        "lief": SimpleNamespace(__version__="1.test", parse=lambda _: None),
    }
    return rows[name]


versions, problems = CHECK.inspect(fake)
assert problems == []
assert versions == {"capstone": "5.test", "unicorn": "2.test", "lief": "1.test"}


def broken(name):
    if name == "unicorn":
        raise ModuleNotFoundError("offline fixture")
    if name == "lief":
        return SimpleNamespace(__version__="bad", parse="not-callable")
    return fake(name)


_, problems = CHECK.inspect(broken)
assert any(row.startswith("unicorn: import ModuleNotFoundError") for row in problems)
assert "lief: parse is not callable" in problems
assert CHECK.main(["unexpected"]) == 64
print("test_static_re_check: 7 checks pass (imports, APIs, versions, missing/incompatible refusal)")
