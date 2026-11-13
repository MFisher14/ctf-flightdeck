"""Collection config for the carried CSCTF regression suite.

Every tests/test_*.py is a pytest module: checks are asserts inside test functions, and a file that
can also be run by hand (`python tests/<name>.py`) does so only under `if __name__ == "__main__":`.
No test file may call sys.exit() (or raise SystemExit) at import: pytest would raise it during
collection and abort the whole session (INTERNALERROR) on every xdist worker. R-01 converted the 25
script-style files that did, and removed the collect_ignore list that hid 16 of them;
tests/test_suite_tools.py fails if a module-level exit or a collect_ignore list comes back.
(tests/real/ is the exception by design: its conftest runs each script in a child process.)
"""

import datetime as _dt

from ctf import event as _event, scope as _scope

# B-001c: the web, chat and pwn clients refuse any host outside the current event profile's
# rules.live_service_scope (ctf/scope.py). The suite pins this test-only profile so the carried client
# tests can build clients against loopback toy servers and reserved names (RFC 2606 .test/.invalid,
# RFC 5737 documentation nets, private ranges). Real public addresses stay out of scope, and the
# platform host below is refused. Scope tests re-pin their own profiles (tests/test_scope_guard.py).
SUITE_SCOPE_PROFILE = _event.parse({
    "slug": "test-suite", "name": "test suite scope profile",
    "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 12, 31)},
    "platform": {"kind": "ctfd", "base_url": "https://board.suite-platform.test"},
    "flag": {"prefixes": []},
    "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
              "live_service_scope": ["localhost", "127.0.0.0/8", "::1", "*.test", "*.invalid",
                                     "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                     "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]},
}, src="tests/conftest.py")
_scope.pin(SUITE_SCOPE_PROFILE)
