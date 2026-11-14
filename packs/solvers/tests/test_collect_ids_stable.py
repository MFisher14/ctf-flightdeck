"""SH-07: test ids are the same every time the suite is collected.

pytest-xdist aborts a run ("Different tests were collected between gwN and gwM") when two workers
collect different ordered id lists. Four Phase 1 full-suite runs aborted that way: parametrize ids
built at collection from gzip / zip bytes that embedded the wall clock (fixed in R-01 by pinning the
times). ctf.testing.collect_ids collects twice with the clock moved and the hash seed changed and
compares the ids; these tests hold the two modules that diverged, and then the whole tree, to it,
and check that the comparison catches each way an id can drift.
"""
import datetime
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from ctf.testing import collect_ids
from ctf.testing.collect_ids import CollectFailed, collect, compare

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
NAMED = ["tests/test_ff_iwork_inspect.py", "tests/test_review_binary_hcfg_storage_fold.py"]


def _clean_env(tmp: Path) -> dict:
    env = {k: v for k, v in os.environ.items()
           if k != "PYTHONPATH" and not k.startswith(("PYTEST_", "CTF_", "CSCTF_", "HUNTRESS_"))}
    env.update(CTF_WORKDIR=str(tmp), CTF_TESTING="1", CTF_EVENT="csctf", PYTHONDONTWRITEBYTECODE="1")
    return env


# ======================================================================== the suite's own ids are stable
def test_the_two_modules_that_diverged_collect_identically_across_a_clock_move(tmp_path):
    cmp = compare(NAMED, cwd=ROOT, env=_clean_env(tmp_path))
    assert cmp.stable, cmp.diff()
    assert not cmp.a.errors, cmp.a.output[-3000:]
    # the cases that embedded a timestamp are in the lists compared: the gzip member and the zip params
    gz = [i for i in cmp.a.ids if "test_nonbase64_layers_are_unsure_never_plain[" in i]
    assert len(gz) == 7, gz
    assert any(i.startswith(NAMED[0] + "::") and "[" in i for i in cmp.a.ids)
    assert len(cmp.a.ids) >= 91


@pytest.mark.slow
@pytest.mark.timeout(1800)
def test_the_whole_tree_collects_identically_across_a_clock_move(tmp_path):
    cmp = compare(["tests"], cwd=ROOT, env=_clean_env(tmp_path), timeout=840)
    assert cmp.stable, cmp.diff()[-6000:]
    assert len(cmp.a.ids) > 20000


# ===================================================================== the comparison catches each drift
def _module(tmp_path: Path, body: str) -> Path:
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    path = tmp_path / "test_synthetic.py"
    path.write_text(textwrap.dedent(body))
    return path


def _compare(tmp_path, body, gap=0.0, **kw):
    path = _module(tmp_path, body)
    env = dict(_clean_env(tmp_path), PYTHONPATH=str(ROOT))
    return compare([path.name], cwd=tmp_path, gap=gap, env=env, **kw)


DRIFTS = {
    # what R-01 fixed, reintroduced: a gzip member with the default (wall-clock) header mtime
    "gzip_default_mtime": """
        import gzip, pytest
        @pytest.mark.parametrize("member", [b"plain", gzip.compress(b"x")])
        def test_member(member): pass
    """,
    # and a zip member written under a name, which stamps it with the local time
    "zip_default_date_time": """
        import io, zipfile, pytest
        def zbytes():
            sink = io.BytesIO()
            with zipfile.ZipFile(sink, "w") as z:
                z.writestr("a.txt", b"x")
            return sink.getvalue()
        @pytest.mark.parametrize("blob", [zbytes()])
        def test_blob(blob): pass
    """,
    # day-level clocks: only the clock move tells these apart (gap 0: both runs share a day)
    "date_today": """
        import datetime, pytest
        @pytest.mark.parametrize("day", [datetime.date.today().isoformat()])
        def test_day(day): pass
    """,
    "strftime": """
        import time, pytest
        @pytest.mark.parametrize("stamp", [time.strftime("%Y-%m-%d")])
        def test_stamp(stamp): pass
    """,
    "datetime_now": """
        from datetime import datetime
        import pytest
        @pytest.mark.parametrize("hour", [datetime.now().strftime("%Y%m%d%H")])
        def test_hour(hour): pass
    """,
    "time_ns": """
        import time, pytest
        @pytest.mark.parametrize("day", [time.time_ns() // 86_400_000_000_000])
        def test_day(day): pass
    """,
    # str hashes are seeded per process: iterating a set orders params differently per worker
    "set_order": """
        import pytest
        NAMES = {"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
                 "juliet", "kilo", "lima", "mike", "november", "oscar", "papa"}
        @pytest.mark.parametrize("name", NAMES)
        def test_name(name): pass
    """,
}


@pytest.mark.parametrize("case", sorted(DRIFTS))
def test_an_id_that_drifts_is_caught(tmp_path, case):
    cmp = _compare(tmp_path, DRIFTS[case])
    assert not cmp.stable, (cmp.a.ids, cmp.b.ids)
    assert cmp.a.ids and cmp.b.ids
    diff = cmp.diff()
    assert diff.startswith("--- run A ids") and "\n-" in diff and "\n+" in diff


def test_pinned_and_explicit_ids_are_stable(tmp_path):
    cmp = _compare(tmp_path, """
        import datetime, gzip, io, time, zipfile, pytest
        def zbytes():
            sink = io.BytesIO()
            with zipfile.ZipFile(sink, "w") as z:
                z.writestr(zipfile.ZipInfo("a.txt", date_time=(2020, 1, 1, 0, 0, 0)), b"x")
            return sink.getvalue()
        @pytest.mark.parametrize("member", [gzip.compress(b"x", mtime=0), zbytes()])
        def test_member(member): pass
        @pytest.mark.parametrize("stamp", [time.time()], ids=["now"])
        def test_stamp(stamp): pass
        @pytest.mark.parametrize("name", sorted({"alpha", "bravo", "charlie", "delta", "echo"}))
        def test_name(name): pass
        @pytest.mark.parametrize("day", [datetime.date(2026, 1, 2)])
        def test_day(day): pass
    """, gap=collect_ids.DEFAULT_GAP)
    assert cmp.stable, cmp.diff()
    assert len(cmp.a.ids) == 9 and "test_synthetic.py::test_stamp[now]" in cmp.a.ids


def test_a_module_that_errors_in_one_collection_only_is_a_difference(tmp_path):
    # the module imports only on today's clock, so run B loses its one id and records an error
    cmp = _compare(tmp_path, f"""
        import time
        assert time.time() < {time.time() + 30 * 86400!r}
        def test_x(): pass
    """)
    assert cmp.a.ids == ["test_synthetic.py::test_x"] and cmp.b.ids == []
    assert cmp.b.errors == ["test_synthetic.py"] and not cmp.a.errors
    assert not cmp.stable
    assert "+test_synthetic.py" in cmp.diff()


def test_identical_ids_with_an_error_in_one_collection_only_is_a_difference(tmp_path):
    # a helper module with no tests breaks at import on the moved clock only; the id lists stay equal,
    # so only the comparison of collection errors can tell the two runs apart
    _module(tmp_path, "def test_x(): pass\n")
    (tmp_path / "test_helpers.py").write_text(textwrap.dedent(f"""
        import time
        assert time.time() < {time.time() + 30 * 86400!r}
    """))
    env = dict(_clean_env(tmp_path), PYTHONPATH=str(ROOT))
    cmp = compare(["test_helpers.py", "test_synthetic.py"], cwd=tmp_path, gap=0.0, env=env)
    assert cmp.a.ids == cmp.b.ids == ["test_synthetic.py::test_x"]
    assert cmp.a.errors == [] and cmp.b.errors == ["test_helpers.py"]
    assert not cmp.stable
    assert cmp.diff() == "\n".join(["--- run A collection errors", "+++ run B collection errors",
                                    "@@ -0,0 +1 @@", "+test_helpers.py"])


def test_collection_errors_are_recorded_sorted_whatever_the_collection_order(tmp_path):
    # errors are compared as a set of node ids: two runs that hit the same broken modules in a different
    # order are the same, so the plugin records them sorted, not in the order pytest reported them
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    for name in ("test_zz_broken.py", "test_aa_broken.py"):
        (tmp_path / name).write_text("raise ImportError('synthetic')\n")
    env = dict(_clean_env(tmp_path), PYTHONPATH=str(ROOT))
    z_first = collect(["test_zz_broken.py", "test_aa_broken.py"], cwd=tmp_path, shift=0, hash_seed="1", env=env)
    a_first = collect(["test_aa_broken.py", "test_zz_broken.py"], cwd=tmp_path, shift=0, hash_seed="1", env=env)
    # pytest reports the errors in command-line order (z first here), so only the sort puts a first
    assert z_first.output.index("test_zz_broken.py") < z_first.output.index("test_aa_broken.py")
    assert z_first.errors == a_first.errors == ["test_aa_broken.py", "test_zz_broken.py"]
    assert z_first.ids == a_first.ids == []


def test_a_collection_with_no_id_list_fails_loudly(tmp_path):
    env = dict(_clean_env(tmp_path), PYTHONPATH=str(ROOT))
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    with pytest.raises(CollectFailed, match="exited 4 .an internal or usage error"):
        collect(["no_such_file.py"], cwd=tmp_path, shift=0, hash_seed="1", env=env)
    _module(tmp_path, "X = 1\n")
    with pytest.raises(CollectFailed, match="collected no tests"):
        collect(["test_synthetic.py"], cwd=tmp_path, shift=0, hash_seed="1", env=env)
    # the plugin cannot load (no PYTHONPATH: ctf is not importable from tmp_path): pytest stops at startup
    with pytest.raises(CollectFailed, match="without writing an id list"):
        collect(["test_synthetic.py"], cwd=tmp_path, shift=0, hash_seed="1", env=_clean_env(tmp_path))


def test_the_child_gets_the_requested_seed_and_shift_and_not_the_parents_xdist_vars(tmp_path):
    path = _module(tmp_path, """
        import os, time, pytest
        @pytest.mark.parametrize("seen", [
            "seed=" + os.environ["PYTHONHASHSEED"],
            "year=" + time.strftime("%Y"),
            "xdist=" + str(any(k.startswith("PYTEST_XDIST_") for k in os.environ)),
            "current=" + str("PYTEST_CURRENT_TEST" in os.environ),
            "shift=" + os.environ.get("CTF_COLLECT_CLOCK_SHIFT", "none"),
        ])
        def test_seen(seen): pass
    """)
    env = dict(_clean_env(tmp_path), PYTHONPATH=str(ROOT), PYTEST_XDIST_WORKER="gw3",
               PYTEST_CURRENT_TEST="x", PYTHONHASHSEED="99", CTF_COLLECT_CLOCK_SHIFT="5")
    plain = collect([path.name], cwd=tmp_path, shift=0, hash_seed="7", env=env)
    moved = collect([path.name], cwd=tmp_path, shift=2 * 366 * 86400, hash_seed="8", env=env)
    year = time.localtime().tm_year

    def seen(c):
        return [i.split("[", 1)[1].rstrip("]") for i in c.ids]
    assert seen(plain) == ["seed=7", f"year={year}", "xdist=False", "current=False", "shift=none"]
    assert seen(moved)[:2] == ["seed=8", f"year={year + 2}"] and seen(moved)[4] == f"shift={2 * 366 * 86400.0!r}"


# ============================================================================================= the clock shift
_PROBE = r"""
import json, sys
real = __import__("time").time()
import ctf.testing.collect_ids                        # installs the shift at import, as `-p` does
import datetime, time
shift = float(sys.argv[1])
base = datetime.datetime.__dict__.get("_ctf_shifted_base", datetime.datetime)
base_date = datetime.date.__dict__.get("_ctf_shifted_base", datetime.date)
class Later(datetime.datetime): pass
now = datetime.datetime.now()
aware = datetime.datetime.now(datetime.timezone.utc)
print(json.dumps({
    "time": time.time() - real,
    "time_ns": time.time_ns() / 1e9 - real,
    "localtime": time.mktime(time.localtime()) - real,
    "gmtime": __import__("calendar").timegm(time.gmtime()) - real,
    "ctime_year": int(time.ctime().split()[-1]),
    "asctime_year": int(time.asctime().split()[-1]),
    "strftime_year": int(time.strftime("%Y")),
    "explicit_args_are_real": time.mktime(time.localtime(12345.0)) == 12345.0 and time.gmtime(0).tm_year == 1970
        and time.strftime("%Y", time.gmtime(0)) == "1970" and time.ctime(0) == time.asctime(time.localtime(0)),
    "now": now.timestamp() - real,
    "aware": aware.timestamp() - real,
    "aware_tz": aware.tzinfo is datetime.timezone.utc,
    "utcnow": (datetime.datetime.utcnow() - base.utcnow()).total_seconds(),
    "dt_today": datetime.datetime.today().timestamp() - real,
    "date_today": (datetime.date.today() - datetime.date.fromtimestamp(real)).days,
    "now_is_datetime": isinstance(now, datetime.datetime) and isinstance(now, base),
    "base_is_datetime": isinstance(base(2020, 1, 1), datetime.datetime),
    "date_is_date": isinstance(datetime.date.today(), datetime.date),
    "base_date_is_date": isinstance(base_date(2020, 1, 1), datetime.date),
    "later_is_strict": not isinstance(base(2020, 1, 1), Later) and isinstance(Later(2020, 1, 1), Later),
    "subclass": issubclass(base, datetime.datetime),
    "name": datetime.datetime.__name__ + "/" + datetime.datetime.__module__,
}))
"""


def _probe(shift: str | None):
    env = {k: v for k, v in os.environ.items() if k != collect_ids.SHIFT_ENV}
    if shift is not None:
        env[collect_ids.SHIFT_ENV] = shift
    proc = subprocess.run([PY, "-c", _PROBE, shift or "0"], cwd=ROOT, env=env, capture_output=True, text=True,
                          timeout=120)
    assert proc.returncode == 0, proc.stderr[-3000:]
    import json
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_the_plugin_moves_every_python_wall_clock():
    shift = 400 * 86400 + 3661
    got = _probe(str(float(shift)))
    for key in ("time", "time_ns", "localtime", "gmtime", "now", "aware", "dt_today", "utcnow"):
        assert abs(got[key] - shift) < 60, (key, got[key])
    year = datetime.datetime.fromtimestamp(time.time() + shift).year
    assert got["ctime_year"] == got["asctime_year"] == got["strftime_year"] == year
    assert 399 <= got["date_today"] <= 401
    assert got["aware_tz"] and got["explicit_args_are_real"] and got["later_is_strict"]
    # stand-ins still pass the isinstance checks libraries make (cryptography's x509 builder does)
    assert got["now_is_datetime"] and got["base_is_datetime"] and got["date_is_date"] and got["base_date_is_date"]
    assert got["subclass"] and got["name"] == "datetime/datetime"


def test_without_the_env_var_the_plugin_moves_nothing():
    got = _probe(None)
    for key in ("time", "time_ns", "localtime", "gmtime", "now", "aware", "dt_today", "utcnow"):
        assert abs(got[key]) < 60, (key, got[key])
    assert got["date_today"] in (0, 1) and got["name"] == "datetime/datetime" and got["explicit_args_are_real"]


# ===================================================================================================== the CLI
def test_cli_exit_codes_and_report(tmp_path):
    env = dict(_clean_env(tmp_path), PYTHONPATH=str(ROOT))
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_ok.py").write_text("import pytest\n@pytest.mark.parametrize('v', [1, 2])\ndef test_v(v): pass\n")
    (tmp_path / "test_bad.py").write_text(
        "import gzip, pytest\n@pytest.mark.parametrize('v', [gzip.compress(b'x')])\ndef test_v(v): pass\n")

    def run(*args):
        return subprocess.run([PY, "-m", "ctf.testing.collect_ids", "--gap", "0", *args], cwd=tmp_path, env=env,
                              capture_output=True, text=True, timeout=300)
    ok = run("test_ok.py")
    assert ok.returncode == 0 and "stable: 2 ids" in ok.stdout, ok.stdout + ok.stderr
    bad = run("test_bad.py")
    assert bad.returncode == 1 and "DIVERGED" in bad.stderr, bad.stdout + bad.stderr
    assert "-test_bad.py::test_v[" in bad.stdout and "+test_bad.py::test_v[" in bad.stdout
    missing = run("test_absent.py")
    assert missing.returncode == 2 and "usage error" in missing.stderr and "test_absent.py" in missing.stderr
    # with no clock move the gzip id only differs across a second: --shift 0 --gap 0 can miss it,
    # the default gap cannot
    assert run("--shift", "0", "--gap", "1.1", "test_bad.py").returncode == 1
