"""B-014: armed Layer-1 openers per lane — the day-1 no-model regression gate.

Two halves. The shipped declaration is armed with the real opener engines against the synthetic
first-days fixtures: every case must solve with no model, and the keys must discriminate (no key may
hold on a neutral control). The gate's own mechanics (exit codes, the scrubbed environment, the
network guard, the timeout, the timed window, controls, tool and sandbox needs, the CLI's exit codes)
are tested against small probe engines in a temporary checkout, so each check is shown to fail when
the behaviour is wrong.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import textwrap
import types

import pytest

from ctf import event, openers, paths
from ctf.cli import arm as arm_cli
from ctf.engines import runner
from ctf.intake import guard as G
from ctf.openers import fixtures

PY = sys.executable
REPO = paths.repo_root()


def run_ctf(*args, env_extra=None):
    e = dict(os.environ)
    e.update(env_extra or {})
    return subprocess.run([PY, "-m", "ctf", *args], cwd=REPO, env=e, capture_output=True,
                          text=True, timeout=300)


def _replace(o: openers.Opener, **kw) -> openers.Opener:
    fields = {f: getattr(o, f) for f in openers.Opener.__dataclass_fields__}
    fields.update(kw)
    return openers.Opener(**fields)


# --------------------------------------------------------------------------- probe checkout

PROBES = {
    # prints the key, then what the environment and the cwd look like from inside the engine
    "arm_envecho": """\
import os, sys
print("PROBE-KEY")
print("SECRET=" + os.environ.get("MY_API_KEY_PROBE", "<absent>"))
print("PLAIN=" + os.environ.get("ARM_PLAIN_PROBE", "<absent>"))
print("LEDGER=" + os.environ.get("CTF_ENGINE_LEDGER", "<absent>"))
print("WORKDIR=" + os.environ.get("CTF_WORKDIR", "<absent>"))
print("EVENT=" + os.environ.get("CTF_EVENT", "<absent>"))
print("CWD=" + os.getcwd())
print("ARG=" + sys.argv[1])
print("HEAD=" + open(sys.argv[1], errors="replace").read()[:8])
""",
    # prints the key and then fails
    "arm_exits": "import sys\nprint('PROBE-KEY')\nsys.exit(3)\n",
    # tries to open an internet socket
    "arm_net": """\
import socket
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("NET-OPEN")
except PermissionError as e:
    print("NET-REFUSED", e)
print("PROBE-KEY")
""",
    "arm_sleeper": "import time\ntime.sleep(30)\nprint('PROBE-KEY')\n",
    "arm_slow": "import time\ntime.sleep(1.2)\nprint('PROBE-KEY')\n",
    # os.fork()s a second process in the same process group (a pure fork keeps the audit hook, so it
    # is allowed under the hook guard, unlike an exec'd child). That process sleeps past the timeout,
    # then writes a marker file; it keeps the inherited stdout pipe open. Killing only the direct
    # child (proc.kill) leaves it running and its marker appears; killing the whole process group
    # (os.killpg) takes it down before it can write.
    "arm_grandchild": """\
import os, sys, time
marker = os.environ["ARM_GRANDCHILD_MARKER_B014"]
if os.fork() == 0:
    time.sleep(6)
    try:
        open(marker, "w").write("grandchild-survived")
    finally:
        os._exit(0)
print("PROBE-KEY")
sys.stdout.flush()
time.sleep(30)
""",
    # prints the key on the base64 warmups blob (head V2Vs), but hangs on any other input, so a
    # control fixture of a different shape makes this engine time out on the control only.
    "arm_hang_on_control": """\
import sys, time
data = open(sys.argv[1], "rb").read()
if data[:4] == b"V2Vs":
    print("PROBE-KEY")
else:
    time.sleep(30)
""",
    # prints the key whatever it is given: a tautological opener
    "arm_always": "print('PROBE-KEY')\n",
    # a decoder that picks the WRONG line as the slug but echoes the decoded text (with the real slug)
    "arm_wrongslug": """\
import sys
print(sys.argv[1] + ": wrong-line-check-00   [b64]   1 ms")
print("    'The answer slug is on the last line.\\narmed-opener-check-01'")
""",
    "arm_needy": "print('PROBE-KEY')\n",
}


def _w(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


@pytest.fixture
def probe_root(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    (r / "ctf").symlink_to(REPO / "ctf", target_is_directory=True)
    for name, code in PROBES.items():
        _w(r, f"solvers/toolkits/{name}.py", code)
        extra = 'needs_tools = ["py:no_such_module_b014"]\n' if name == "arm_needy" else ""
        _w(r, f"solvers/toolkits/{name}.manifest.toml",
           f'id = "toolkits.{name}"\nlane = "toolkits"\nentry = "cli:python solvers/toolkits/{name}.py"\n'
           f'capabilities = ["analysis", "cli"]\ncost_class = "cheap"\n{extra}')
    _w(r, "solvers/toolkits/arm_external.manifest.toml",
       'id = "toolkits.arm_external"\nlane = "toolkits"\nentry = "cli:true"\ncapabilities = ["cli"]\n'
       'cost_class = "cheap"\n')
    _w(r, "solvers/toolkits/arm_fn.py", "def solve(challenge_dir, profile, **opts):\n    return None\n")
    _w(r, "solvers/toolkits/arm_fn.manifest.toml",
       'id = "toolkits.arm_fn"\nlane = "toolkits"\nentry = "solvers.toolkits.arm_fn:solve"\n'
       'capabilities = ["executes"]\ncost_class = "cheap"\n')
    return r


def probe(engine, expect=("PROBE-KEY",), **kw) -> openers.Opener:
    kw.setdefault("fixture", "warmups_base64_slug")
    return openers.Opener(lane="probe", category="Probe", engine=f"toolkits.{engine}", label="probe",
                          expect=tuple(expect), **kw)


# --------------------------------------------------------------------------- the shipped declaration

def test_shipped_declaration_loads_and_every_offline_opener_has_a_control():
    os_ = openers.load()
    lanes = {o.lane for o in os_}
    assert {"warmups", "metadata-forensics", "script-analysis", "mobile-android", "binary", "web"} <= lanes
    for o in os_:
        if o.offline:
            assert o.controls, f"{o.lane} has no neutral control"
            assert set(o.controls).isdisjoint(c.fixture for c in o.all_cases)
        else:
            assert o.reason


def test_shipped_cases_cover_the_rows_shapes():
    """The rows ask for Mastery record prefixes, rot13, multi-record blobs, hex and layered input, and
    the timed paths; each is a case of its lane's opener (not one blob per lane)."""
    w = openers.for_lane("warmups")
    fx = {c.fixture: c for c in w.all_cases}
    for need in ("warmups_base64_slug", "warmups_base64_variant", "warmups_mastery_record", "warmups_rot13_slug",
                 "warmups_multi_record", "warmups_hex_slug", "warmups_layered"):
        assert need in fx, need
    assert {c.mode for c in w.all_cases} >= {"base", "time_trial", "mastery", "single"}
    for lane in ("script-analysis", "mobile-android"):
        timed = [c for c in openers.for_lane(lane).all_cases if c.mode == "time_trial"]
        assert timed and all(c.within for c in timed), lane


@pytest.mark.parametrize("lane", ["warmups", "metadata-forensics", "script-analysis", "mobile-android"])
def test_each_hook_safe_opener_arms_every_case_and_control(lane):
    """The real engine, run with no model under the network guard, prints the frozen key for every
    case, and no key holds on the control."""
    o = openers.for_lane(lane)
    assert not o.needs_os_sandbox
    r = openers.arm(o)
    assert r.status == openers.ARMED, f"{lane} not armed: {r.reason}\n{r.output}"
    assert len(r.cases) == len(o.all_cases) + len(o.controls)
    assert all(c.status == openers.ARMED and c.exit_code == 0 for c in r.cases), r.cases
    assert not r.missing and set(r.found) == {e for c in o.all_cases for e in c.expect}


@pytest.mark.needs_tool("py:capstone", "py:elftools")
def test_binary_opener_is_not_run_under_the_audit_hook_alone():
    r = openers.arm(openers.for_lane("binary"), guard="hook")
    assert r.status == openers.NOT_RUN
    assert "needs the OS network sandbox" in r.reason and "hook chosen" in r.reason


@pytest.mark.needs_tool("py:capstone", "py:elftools")
def test_binary_opener_arms_under_the_os_sandbox():
    try:
        g = G.resolve("os")
    except G.GuardError as e:
        pytest.skip(f"OS network sandbox unavailable here, so the binary opener cannot be armed: {e}")
    r = openers.arm(openers.for_lane("binary"), guard=g)
    assert r.status == openers.ARMED, f"binary not armed: {r.reason}\n{r.output}"


@pytest.mark.needs_tool("py:capstone", "py:elftools")
def test_binary_key_is_what_the_reader_prints_and_not_on_the_bare_elf(tmp_path):
    """The binary key checked directly against binary.d01 (the gate can only arm it under the OS
    sandbox, which a sandboxed test run may lack): every field holds on the orientation ELF, the
    marker and the code fields do not hold on the bare one."""
    o = openers.for_lane("binary")
    assert "  analysis_marker = synthetic-day01" in o.expect
    outs = {}
    for fx in ("elf64_orientation", "elf64_bare"):
        p = fixtures.build(fx, tmp_path / fx)
        cp = subprocess.run(runner.command(o.engine, [str(p)], via="arm", record=False), capture_output=True,
                            text=True, timeout=120, env={**os.environ, "CTF_WORKDIR": str(tmp_path)})
        assert cp.returncode == 0, cp.stderr
        outs[fx] = cp.stdout
    assert [e for e in o.expect if e not in outs["elf64_orientation"]] == []
    absent = [e for e in o.expect if e not in outs["elf64_bare"]]
    assert "  analysis_marker = synthetic-day01" in absent and "  analysis_recover_code = 8100" in absent


def test_web_opener_is_reported_not_run_not_green():
    r = openers.arm(openers.for_lane("web"))
    assert r.status == openers.NOT_RUN
    assert "fake service" in r.reason


def test_neutral_powershell_does_not_arm_the_script_analysis_key():
    """The analyzer prints its default scenario even on a one-line script, so the old key
    (`scenario=resource_hijacking` alone) armed on anything. The shipped key needs the technique and
    the indicators, which only a signalling specimen produces."""
    o = openers.for_lane("script-analysis")
    neutral = _replace(o, fixture="powershell_neutral", cases=(), controls=())
    r = openers.arm(neutral)
    assert r.status == openers.FAILED
    assert "scenario=resource_hijacking" in r.output           # the default the old key matched
    assert "scenario=resource_hijacking attack=T1496 descriptor=plain" in r.missing
    assert "attack=None" in r.output


def test_warmups_key_is_anchored_on_the_answer_line(probe_root):
    """A decoder that answers the wrong line but echoes the decoded text (which contains the slug)
    must not arm: the key is the answer as printed, `: <slug>   [<chain>]`."""
    key = openers.for_lane("warmups").expect
    r = openers.arm(probe("arm_wrongslug", expect=key, controls=()), root=probe_root)
    assert "armed-opener-check-01" in r.output                  # the slug is in the echo
    assert r.status == openers.FAILED and r.missing == key


def test_mastery_record_needs_the_prefix_stripped():
    """The base key on the Mastery member: a decoder that kept `01<TAB>` would not print it, and the
    base slug is not the Mastery slug, so one case cannot stand in for the other."""
    o = openers.for_lane("warmups")
    swapped = _replace(o, fixture="warmups_mastery_record", cases=(), controls=())
    r = openers.arm(swapped)
    assert r.status == openers.FAILED and r.missing == o.expect


# --------------------------------------------------------------------------- arm() mechanics

def test_arm_fails_when_the_expected_key_is_wrong_and_reports_what_was_found():
    o = openers.for_lane("warmups")
    bad = _replace(o, expect=(o.expect[0], "this-slug-is-never-produced-99"), cases=(), controls=())
    r = openers.arm(bad)
    assert r.status == openers.FAILED
    assert r.found == (o.expect[0],)
    assert r.missing == ("this-slug-is-never-produced-99",)
    assert "missing from output: this-slug-is-never-produced-99" in r.reason


def test_arm_fails_when_the_engine_exits_nonzero_even_with_the_key_printed(probe_root):
    r = openers.arm(probe("arm_exits"), root=probe_root)
    assert r.status == openers.FAILED
    assert r.found == ("PROBE-KEY",) and r.missing == ()
    assert r.cases[0].reason == "engine exited 3" and r.exit_code == 3


def test_arm_scrubs_secrets_and_gives_a_fresh_workdir_and_cwd(probe_root, monkeypatch, tmp_path):
    monkeypatch.setenv("MY_API_KEY_PROBE", "super-secret-value-b014")
    monkeypatch.setenv("ARM_PLAIN_PROBE", "visible-b014")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "callers-workdir"))
    monkeypatch.setenv("CTF_EVENT", "csctf")
    r = openers.arm(probe("arm_envecho"), root=probe_root)
    assert r.status == openers.ARMED, r.reason
    out = r.cases[0].output
    assert "super-secret-value-b014" not in out and "SECRET=<absent>" in out
    assert "PLAIN=visible-b014" in out                          # the rest of the environment is passed on
    assert "LEDGER=0" in out and "EVENT=<absent>" in out
    lines = dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)
    assert "callers-workdir" not in lines["WORKDIR"] and "/arm-" in lines["WORKDIR"]
    assert os.path.realpath(lines["CWD"]) != os.path.realpath(str(probe_root))
    assert "/arm-" in lines["CWD"] and lines["ARG"].endswith("blob.txt")


def test_arm_passes_the_profile_as_the_event(probe_root):
    r = openers.arm(probe("arm_envecho"), root=probe_root, profile=event.load("huntress"))
    assert "EVENT=huntress" in r.cases[0].output


def test_arm_runs_the_engine_under_the_network_guard(probe_root):
    r = openers.arm(probe("arm_net"), root=probe_root)
    assert r.status == openers.ARMED, r.reason
    assert "NET-REFUSED" in r.output and "network guard" in r.output and "NET-OPEN" not in r.output


def test_arm_times_out_and_kills_the_engine(probe_root):
    r = openers.arm(probe("arm_sleeper"), root=probe_root, timeout=1)
    assert r.status == openers.FAILED and "timed out after 1s" in r.reason
    assert r.seconds < 15 and r.exit_code is None


def test_arm_timeout_kills_the_whole_process_group_not_just_the_direct_child(probe_root, monkeypatch,
                                                                             tmp_path):
    """An engine that spawned a grandchild must not leave it running after the timeout: the whole
    process group is killed, not only the direct child. The grandchild would write a marker file
    after the timeout; if only the direct child were killed, the marker appears."""
    marker = tmp_path / "grandchild-marker"
    monkeypatch.setenv("ARM_GRANDCHILD_MARKER_B014", str(marker))
    r = openers.arm(probe("arm_grandchild", controls=()), root=probe_root, timeout=2)
    assert r.status == openers.FAILED and "timed out after 2s" in r.reason
    assert not marker.exists(), "the grandchild outlived the timeout: the process group was not killed"


def test_a_timed_case_fails_when_it_overruns_its_window(probe_root):
    late = probe("arm_slow", fixture=None, cases=(openers.Case("warmups_base64_slug", ("PROBE-KEY",),
                                                               "time_trial", within=0.3),))
    r = openers.arm(late, root=probe_root)
    assert r.status == openers.FAILED and "over its 0.3s window" in r.reason
    roomy = probe("arm_slow", fixture=None, cases=(openers.Case("warmups_base64_slug", ("PROBE-KEY",),
                                                                "time_trial", within=30),))
    assert openers.arm(roomy, root=probe_root).status == openers.ARMED


def test_a_key_that_also_holds_on_a_control_fails(probe_root):
    r = openers.arm(probe("arm_always", controls=("warmups_no_slug",)), root=probe_root)
    assert r.status == openers.FAILED
    ctl = [c for c in r.cases if c.mode == "control"]
    assert len(ctl) == 1 and ctl[0].status == openers.FAILED and "also holds" in ctl[0].reason
    assert r.cases[0].status == openers.ARMED                   # the case itself was fine


def test_a_control_that_times_out_fails_the_opener(probe_root):
    """A control the engine hangs on must fail the opener: a timed-out control produced no output and
    cannot be shown to discriminate, so it must not be counted as a passing (discriminating) control."""
    o = probe("arm_hang_on_control", controls=("metadata_text",))
    r = openers.arm(o, root=probe_root, timeout=2)
    assert r.status == openers.FAILED
    ctl = [c for c in r.cases if c.mode == "control"]
    assert len(ctl) == 1 and ctl[0].status == openers.FAILED
    assert "timed out after 2s" in ctl[0].reason
    assert r.cases[0].status == openers.ARMED                   # the base case itself was fine


def test_a_control_that_discriminates_passes():
    o = openers.for_lane("warmups")
    one = _replace(o, cases=(), controls=("warmups_no_slug",))
    r = openers.arm(one)
    assert r.status == openers.ARMED, r.reason
    assert [c.mode for c in r.cases] == ["base", "control"]


def test_arm_reports_not_run_for_a_tool_the_manifest_needs(probe_root):
    r = openers.arm(probe("arm_needy"), root=probe_root)
    assert r.status == openers.NOT_RUN and "py:no_such_module_b014" in r.reason
    assert r.missing == ("PROBE-KEY",)


def test_arm_reports_not_run_for_a_tool_the_opener_needs():
    o = _replace(openers.for_lane("warmups"), needs_tools=("py:a_module_that_is_not_installed_xyz",))
    r = openers.arm(o)
    assert r.status == openers.NOT_RUN and "a_module_that_is_not_installed_xyz" in r.reason


def test_an_os_sandbox_engine_is_not_run_under_the_hook(probe_root):
    r = openers.arm(probe("arm_always", needs_os_sandbox=True), root=probe_root, guard="hook")
    assert r.status == openers.NOT_RUN and "needs the OS network sandbox" in r.reason
    r = openers.arm(probe("arm_external"), root=probe_root, guard="hook")
    assert r.status == openers.NOT_RUN and "external-command entry" in r.reason
    # the same probe without the flag does run under the hook
    assert openers.arm(probe("arm_always"), root=probe_root, guard="hook").status == openers.ARMED


def test_arm_fails_on_a_fixture_that_cannot_be_built(probe_root):
    r = openers.arm(probe("arm_always", fixture="no_such_builder"), root=probe_root)
    assert r.status == openers.FAILED and "no_such_builder" in r.reason


# --------------------------------------------------------------------------- fixtures

def test_every_shipped_fixture_builds_a_real_file(tmp_path):
    for i, kind in enumerate(sorted(fixtures.BUILDERS)):
        p = fixtures.build(kind, tmp_path / str(i))
        assert p.is_file() and p.stat().st_size > 0


def test_fixtures_are_deterministic(tmp_path):
    for kind in fixtures.BUILDERS:
        a = fixtures.build(kind, tmp_path / "a" / kind).read_bytes()
        b = fixtures.build(kind, tmp_path / "b" / kind).read_bytes()
        assert a == b, kind
    png = fixtures.build("metadata_png", tmp_path / "png").read_bytes()
    key = openers.for_lane("metadata-forensics").expect
    assert f"sha256 = {hashlib.sha256(png).hexdigest()}" in key


def test_unknown_fixture_kind_fails_loudly(tmp_path):
    with pytest.raises(fixtures.FixtureError) as ei:
        fixtures.build("no_such_builder", tmp_path)
    assert "no_such_builder" in str(ei.value)


def test_warmups_fixtures_hold_their_slugs(tmp_path):
    p = fixtures.warmups_base64_slug(tmp_path / "a")
    assert fixtures.WARMUPS_SLUG.encode() in base64.b64decode(p.read_bytes())
    m = fixtures.warmups_mastery_record(tmp_path / "b").read_bytes()
    assert m.startswith(b"01\t") and fixtures.WARMUPS_MASTERY_SLUG.encode() in base64.b64decode(m[3:].strip())
    rec = fixtures.warmups_multi_record(tmp_path / "c").read_bytes().splitlines()
    assert [ln.split(b"\t")[0] for ln in rec] == [b"02", b"01", b"03"]     # written out of order


# --------------------------------------------------------------------------- load() validation

def _write_decl(root, body):
    (root / "openers").mkdir(parents=True, exist_ok=True)
    (root / "openers" / "layer1.toml").write_text(textwrap.dedent(body))


WARM = """
    [[opener]]
    lane = "warmups"
    category = "Warmups"
    engine = "warmups.layered_decode"
    label = "l"
"""


@pytest.mark.parametrize("body, needle", [
    (WARM + 'fixture = "does_not_exist"\nexpect = ["x"]\ncontrols = ["warmups_no_slug"]\n', "does_not_exist"),
    (WARM + 'expect = ["x"]\ncontrols = ["warmups_no_slug"]\n', "needs a 'fixture'"),
    (WARM + 'fixture = "warmups_base64_slug"\ncontrols = ["warmups_no_slug"]\n', "non-empty 'expect'"),
    (WARM + 'fixture = "warmups_base64_slug"\nexpect = ["x"]\n', "at least one 'controls'"),
    (WARM + 'fixture = "warmups_base64_slug"\nexpect = ["x"]\ncontrols = ["nope_ctl"]\n', "nope_ctl"),
    (WARM + 'fixture = "warmups_base64_slug"\nexpect = ["x"]\ncontrols = ["warmups_no_slug"]\nbogus = 1\n', "bogus"),
    (WARM + 'fixture = "warmups_base64_slug"\nexpect = ["x"]\ncontrols = ["warmups_no_slug"]\n'
     '[[opener.case]]\nfixture = "warmups_hex_slug"\nexpect = ["y"]\nwithin = -1\n', "'within'"),
    (WARM + 'fixture = "warmups_base64_slug"\nexpect = ["x"]\ncontrols = ["warmups_no_slug"]\n'
     '[[opener.case]]\nfixture = "warmups_hex_slug"\nexpect = []\n', "non-empty 'expect'"),
    (WARM + 'fixture = "warmups_base64_slug"\nexpect = ["x"]\ncontrols = ["warmups_no_slug"]\n'
     '[[opener.case]]\nfixture = "warmups_hex_slug"\nexpect = ["y"]\nextra = 1\n', "unknown case key"),
    (WARM + 'fixture = "warmups_base64_slug"\nexpect = ["x"]\ncontrols = ["warmups_no_slug"]\n'
     'needs_os_sandbox = "yes"\n', "'needs_os_sandbox'"),
    ('[[opener]]\nlane = "web"\ncategory = "Web"\nengine = "web.passive_checks"\noffline = false\nlabel = "l"\n',
     "needs a 'reason'"),
])
def test_load_rejects_a_malformed_block(tmp_path, body, needle):
    _write_decl(tmp_path, body)
    with pytest.raises(openers.OpenerError) as ei:
        openers.load(root=tmp_path)
    assert needle in str(ei.value)


def test_load_rejects_a_duplicate_lane(tmp_path):
    one = WARM + 'fixture = "warmups_base64_slug"\nexpect = ["x"]\ncontrols = ["warmups_no_slug"]\n'
    _write_decl(tmp_path, one + one)
    with pytest.raises(openers.OpenerError) as ei:
        openers.load(root=tmp_path)
    assert "two openers for lane 'warmups'" in str(ei.value)


def test_load_rejects_an_engine_that_does_not_resolve(probe_root):
    _write_decl(probe_root, """
        [[opener]]
        lane = "probe"
        category = "Probe"
        engine = "toolkits.not_a_real_engine"
        fixture = "warmups_base64_slug"
        expect = ["x"]
        controls = ["warmups_no_slug"]
        label = "l"
    """)
    with pytest.raises(openers.OpenerError) as ei:
        openers.load(root=probe_root)
    assert "does not resolve" in str(ei.value)


def test_load_rejects_an_offline_opener_on_a_function_engine(probe_root):
    _write_decl(probe_root, """
        [[opener]]
        lane = "probe"
        category = "Probe"
        engine = "toolkits.arm_fn"
        fixture = "warmups_base64_slug"
        expect = ["x"]
        controls = ["warmups_no_slug"]
        label = "l"
    """)
    with pytest.raises(openers.OpenerError) as ei:
        openers.load(root=probe_root)
    assert "function entry" in str(ei.value)


def test_load_reads_cases_and_controls(probe_root):
    _write_decl(probe_root, """
        [[opener]]
        lane = "probe"
        category = "Probe"
        engine = "toolkits.arm_always"
        fixture = "warmups_base64_slug"
        expect = ["PROBE-KEY"]
        controls = ["warmups_no_slug"]
        label = "l"
        [[opener.case]]
        mode = "time_trial"
        fixture = "warmups_hex_slug"
        expect = ["PROBE-KEY"]
        within = 30
    """)
    (o,) = openers.load(root=probe_root)
    assert o.all_cases == (openers.Case("warmups_base64_slug", ("PROBE-KEY",)),
                           openers.Case("warmups_hex_slug", ("PROBE-KEY",), "time_trial", 30.0))
    assert o.controls == ("warmups_no_slug",)


def test_missing_declaration_fails_loudly(tmp_path):
    with pytest.raises(openers.OpenerError) as ei:
        openers.load(root=tmp_path)
    assert "no opener declaration" in str(ei.value)


# --------------------------------------------------------------------------- select / for_lane

def test_for_lane_returns_the_opener_and_rejects_an_unknown_lane():
    assert openers.for_lane("warmups").engine == "warmups.layered_decode"
    with pytest.raises(openers.OpenerError):
        openers.for_lane("there-is-no-such-lane")


def test_select_by_lane_and_by_event_profile():
    os_ = openers.load()
    hunt = event.load("huntress")
    assert {o.lane for o in openers.select(os_, profile=hunt)} == {
        "warmups", "metadata-forensics", "script-analysis", "mobile-android", "binary", "binary-hcfg", "web"}
    # B-136: an opener for a category Huntress never had (memory forensics) is not selected for Huntress,
    # and is selected for an event that has the category
    csctf = {o.lane for o in openers.select(os_, profile=event.load("csctf"))}
    assert "memory-forensics" in csctf and "warmups" not in csctf
    assert openers.select(os_, profile=event.load("spooky")) == []        # spooky declares no categories
    assert [o.lane for o in openers.select(os_, lanes=["binary"])] == ["binary"]
    assert [o.lane for o in openers.select(os_, lanes=["binary"], profile=event.load("spooky"))] == []
    with pytest.raises(openers.OpenerError):
        openers.select(os_, lanes=["nope"])


def test_select_matches_a_profile_category_by_lane_name_too():
    rev = openers.Opener(lane="binary", category="Reverse Engineering", engine="binary.d01", label="l")
    other = openers.Opener(lane="web", category="Web", engine="web.passive_checks", label="l")
    by_lane = types.SimpleNamespace(categories=["Binary"])
    by_cat = types.SimpleNamespace(categories=["reverse-engineering"])
    assert openers.select([rev, other], profile=by_lane) == [rev]
    assert openers.select([rev, other], profile=by_cat) == [rev]
    assert openers.select([rev, other], profile=types.SimpleNamespace(categories=["Crypto"])) == []


# --------------------------------------------------------------------------- the CLI

def test_cli_arm_runs_the_gate_green():
    r = run_ctf("arm", "--lane", "warmups", "--lane", "metadata-forensics")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ARMED" in r.stdout and "warmups" in r.stdout and "guard:" in r.stdout


def test_cli_arm_strict_fails_when_something_is_not_run():
    r = run_ctf("arm", "--lane", "web", "--strict")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "not run" in r.stdout
    assert run_ctf("arm", "--lane", "web").returncode == 0          # not-run alone does not fail


def test_cli_arm_json_lists_every_case():
    r = run_ctf("arm", "--lane", "warmups", "--json")
    assert r.returncode == 0, r.stderr
    rows = json.loads(r.stdout)
    assert rows and rows[0]["lane"] == "warmups" and rows[0]["status"] == "armed"
    modes = [c["mode"] for c in rows[0]["cases"]]
    assert "mastery" in modes and "time_trial" in modes and modes[-1] == "control"


def test_cli_arm_unknown_lane_is_a_usage_error():
    r = run_ctf("arm", "--lane", "nope")
    assert r.returncode == 2 and "no opener for lane" in r.stderr


def test_cli_arm_event_with_no_matching_lane_is_a_usage_error():
    r = run_ctf("arm", "--event", "spooky")
    assert r.returncode == 2 and "no openers selected for event 'spooky'" in r.stderr


def _probe_decl(root, engine, expect=("HEAD=V2Vs",), category="Probe"):
    """One probe opener: the base64 blob as its case (its head is `V2Vs`, base64 of `Wel`) and a text
    file as its control (whose head is not), so the key discriminates."""
    _write_decl(root, f"""
        [[opener]]
        lane = "probe"
        category = "{category}"
        engine = "toolkits.{engine}"
        fixture = "warmups_base64_slug"
        expect = {json.dumps(list(expect))}
        controls = ["metadata_text"]
        label = "probe"
    """)


def test_cli_arm_exits_1_on_a_failed_opener(probe_root):
    _probe_decl(probe_root, "arm_envecho", expect=["A-KEY-THE-PROBE-NEVER-PRINTS"])
    r = run_ctf("arm", "--root", str(probe_root))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "FAILED" in r.stdout and "A-KEY-THE-PROBE-NEVER-PRINTS" in r.stdout
    assert "0 armed, 1 failed, 0 not run" in r.stdout


def test_cli_arm_root_green_and_timeout(probe_root):
    _probe_decl(probe_root, "arm_envecho")
    ok = run_ctf("arm", "--root", str(probe_root))
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "1 armed, 0 failed" in ok.stdout
    _probe_decl(probe_root, "arm_sleeper")
    slow = run_ctf("arm", "--root", str(probe_root), "--timeout", "1")
    assert slow.returncode == 1 and "timed out after 1s" in slow.stdout


def test_cli_arm_event_selects_by_profile_and_reaches_the_engine(probe_root):
    _probe_decl(probe_root, "arm_envecho", expect=["HEAD=V2Vs", "EVENT=huntress"], category="Warmups")
    r = run_ctf("arm", "--root", str(probe_root), "--event", "huntress", "--json")
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)[0]["lane"] == "probe"
    without = run_ctf("arm", "--root", str(probe_root), "--json")
    assert without.returncode == 1                              # no --event: CTF_EVENT is not passed
    assert json.loads(without.stdout)[0]["missing"] == ["EVENT=huntress"]


def test_cli_arm_guard_os_unavailable_is_a_usage_error(monkeypatch, capsys):
    monkeypatch.setitem(G._PROBE, "os", (None, "no sandbox here"))
    ns = argparse.Namespace(root=None, event=None, lane=["warmups"], strict=False, json=False, timeout=60.0,
                            guard="os")
    assert arm_cli.run(ns) == 2
    assert "no sandbox here" in capsys.readouterr().err
