"""SH-05: the Script lane's readers use their own generic.py, whatever else holds the name `generic`.

solvers/binary has a generic.py too. tests/test_day20_binary_overlay.py puts solvers/binary first on
sys.path and imports it at collection time, so in a full-suite run sys.modules["generic"] is the Binary
module before tests/test_day28_script_descriptor_whole.py is imported. lang_escript did a bare
`import generic`, got the Binary module, and its `answers` raised AttributeError, which analyze catches:
the Erlang integer-charlist specimen came back {} (the order-dependent failure of test_erlang_static_forms).
day23_fold, fields_derived and shape_fallback_lib had the same bare import behind `except Exception`.

Every case runs in a child interpreter, because the condition under test is a polluted sys.modules and
these tests must not leave one behind for the rest of the worker.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SA = REPO / "solvers" / "script-analysis"
BIN = REPO / "solvers" / "binary"
COMMON = REPO / "solvers" / "common"


def _child(body: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run `body` in a fresh interpreter that first loads the Binary lane's generic.py as `generic`,
    as the culprit test module does, then puts the Script lane on sys.path."""
    prelude = textwrap.dedent(f"""
        import os, sys
        os.environ["CTF_TESTING"] = "1"
        sys.dont_write_bytecode = True
        sys.path.insert(0, {str(BIN)!r})
        import generic as _binary_generic
        assert _binary_generic.__file__.startswith({str(BIN)!r}), _binary_generic.__file__
        sys.path[:0] = [{str(SA)!r}, {str(COMMON)!r}]
    """)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ONLY", "BATCH_", "CTF_HIDE"))}
    return subprocess.run([sys.executable, "-c", prelude + textwrap.dedent(body)], cwd=str(REPO), env=env,
                          capture_output=True, text=True, timeout=timeout)


def _ok(proc: subprocess.CompletedProcess) -> str:
    assert proc.returncode == 0, f"child failed ({proc.returncode}):\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}"
    return proc.stdout


def test_regression_culprit_then_erlang_static_forms_in_one_process():
    """The documented reproduction: the culprit module, then the target file, in one pytest process.
    Before the fix this child fails test_erlang_static_forms with `assert {} == {...}`.

    The target is given as a whole file: run as a `file::test` node id after the culprit, the failure did
    not reproduce (observed; the binary generic did not hold the name when the target was imported)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ONLY", "BATCH_", "CTF_HIDE",
                                                                     "PYTEST_XDIST", "PYTEST_CURRENT"))}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rA", "-p", "no:randomly", "-p", "no:xdist", "-p", "no:cacheprovider",
         "tests/test_day20_binary_overlay.py", "tests/test_day28_script_descriptor_whole.py"],
        cwd=str(REPO), env=env, capture_output=True, text=True, timeout=300)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out[-4000:]
    assert "PASSED tests/test_day28_script_descriptor_whole.py::test_erlang_static_forms" in out, out[-4000:]
    assert "5 passed" in out and "failed" not in out, out[-4000:]


def test_lang_escript_reads_integer_charlist_with_binary_generic_loaded():
    out = _ok(_child("""
        import base64, json
        import lang_escript
        print("GENERIC", lang_escript.generic.__file__)
        plan = ("v=3|language=terraform_hcl|role=benign_utility|verdict=benign|attack=none|adapter=local_parser|"
                "host_profile=standalone|obfuscation_profile=plain_hex|stage_profile=single_descriptor|"
                "next_language=powershell|stage_count=2|steps=decode_configuration,return_configuration|"
                "campaign_id=TERRAFORM_HCL-f919da2b|url=https://t.example.invalid/stage|file_path=/tmp/x/.f.stage")
        b64 = base64.b64encode(plan.encode()).decode()
        ints = ", ".join(str(ord(c)) for c in b64)
        text = ("-module(fixture).\\n"
                'codec_1() -> "base64|identity".\\n'
                f"material_1() -> [{ints}].\\n"
                'main(_) -> io:format("~p~n", [length(material_1())]).\\n')
        got = lang_escript._material(text)
        print("MATERIAL", json.dumps(got))
        q = {"id": "future-benign-adapter", "qid": "future-benign-adapter", "answer_id": "future-benign-adapter",
             "member": "f.escript", "artifact": "e.zip -> f.escript", "question": "Recover the value.",
             "answer_format": {"kind": "exact_text"}, "normalization": "trim"}
        ans = lang_escript.answers([q], {"f.escript": text.encode()}, {"partial": {}, "set": 0})
        print("ANSWER", json.dumps(ans))
        print("BINARY_KEEPS_NAME", sys.modules["generic"] is _binary_generic)
    """))
    assert f"GENERIC {SA / 'generic.py'}" in out, out
    assert 'MATERIAL ["base64|identity", ' in out, out
    assert 'ANSWER {"future-benign-adapter": "local_parser"}' in out, out
    # The Binary module keeps its place under the short name; ours is held under another key.
    assert "BINARY_KEEPS_NAME True" in out, out


def test_day23_fold_plan_of_reads_with_binary_generic_loaded():
    out = _ok(_child("""
        import json
        import day23_fold
        plan = "v=1|steps=decode,run|adapter=wscript.exe|campaign_id=C-1|file_path=/tmp/a.js"
        text = f"Codec_static = {json.dumps('raw|identity')}\\nMaterial_static = {json.dumps(plan)}\\n"
        got, cut, meta = day23_fold._plan_of("static.js", text.encode())
        print("PLAN", json.dumps(got, sort_keys=True))
    """))
    line = next(l for l in out.splitlines() if l.startswith("PLAN "))
    assert '"adapter": "wscript.exe"' in line and '"campaign_id": "C-1"' in line, out


def test_fields_derived_tail_with_binary_generic_loaded():
    out = _ok(_child("""
        import fields_derived
        print("TAIL", fields_derived._tail({"qid": "jscript-launcher-adapter"}))
    """))
    assert "TAIL adapter" in out.splitlines(), out


def test_shape_fallback_known_form_with_binary_generic_loaded():
    out = _ok(_child("""
        import shape_fallback_lib
        print("KNOWN", shape_fallback_lib._id_in_known_form("jscript-launcher-adapter"))
        print("RENAMED", shape_fallback_lib._id_in_known_form("d13-jscript-launcher-adapter"))
    """))
    lines = out.splitlines()
    assert "KNOWN True" in lines and "RENAMED False" in lines, out


def test_own_shares_analyze_module_and_fails_loudly():
    out = _ok(_child("""
        import analyze, plan_codec
        g = plan_codec.own("generic")
        print("SAME_AS_ANALYZE", g is analyze.generic)
        print("KEY", [k for k, m in sys.modules.items() if m is g])
        print("BINARY_KEEPS_NAME", sys.modules["generic"] is _binary_generic)
        try:
            plan_codec.own("no_such_sibling_sh05")
        except ModuleNotFoundError as e:
            print("MISSING", "no_such_sibling_sh05.py" in str(e))
        try:
            plan_codec.own("../generic")
        except ValueError as e:
            print("BADNAME", "not a module name" in str(e))
    """))
    lines = out.splitlines()
    assert "SAME_AS_ANALYZE True" in lines, out
    assert "KEY ['script_analysis_generic']" in lines, out
    assert "BINARY_KEEPS_NAME True" in lines, out
    assert "MISSING True" in lines and "BADNAME True" in lines, out


def test_own_takes_the_short_name_when_it_is_free():
    """Without a Binary module loaded, own() registers the file under `generic` itself (analyze._own's
    rule), so a later bare `import generic` elsewhere in the lane gets the very same module."""
    proc = subprocess.run([sys.executable, "-c", textwrap.dedent(f"""
        import sys
        sys.dont_write_bytecode = True
        sys.path[:0] = [{str(SA)!r}, {str(COMMON)!r}]
        import plan_codec
        g = plan_codec.own("generic")
        print("SHORT", sys.modules.get("generic") is g, "script_analysis_generic" in sys.modules)
        print("AGAIN", plan_codec.own("generic") is g)
    """)], cwd=str(REPO), capture_output=True, text=True, timeout=120)
    out = _ok(proc)
    assert "SHORT True False" in out.splitlines() and "AGAIN True" in out.splitlines(), out


@pytest.mark.parametrize("module", ["lang_escript.py", "day23_fold.py", "fields_derived.py",
                                    "shape_fallback_lib.py"])
def test_no_bare_generic_import_left(module):
    """The lane modules this item fixed hold no bare `import generic` (a source check backing the
    behaviour tests above: a re-added bare import is the bug coming back)."""
    import re
    text = (SA / module).read_text(encoding="utf-8")
    assert not re.search(r"(?m)^[ \t]*(?:import generic\b|from generic import)", text), module


def test_own_drops_a_broken_sibling_and_raises_again(tmp_path):
    """A sibling whose code raises is never left registered half-loaded: own() re-raises the file's own
    error and takes its key back out of sys.modules, under the short name and under the private one, so a
    second call raises again instead of handing back the broken module."""
    (tmp_path / "sh05_broken.py").write_text("VALUE = 1\nraise RuntimeError('sh05 boom')\n", encoding="utf-8")
    (tmp_path / "sh05_held.py").write_text("raise RuntimeError('sh05 boom held')\n", encoding="utf-8")
    out = _ok(_child(f"""
        import types
        from pathlib import Path
        import plan_codec
        plan_codec.HERE = Path({str(tmp_path.resolve())!r})
        sys.modules["sh05_held"] = types.ModuleType("sh05_held")      # another lane's module holds the name
        for name, key in (("sh05_broken", "sh05_broken"), ("sh05_held", "script_analysis_sh05_held")):
            for attempt in (1, 2):
                try:
                    plan_codec.own(name)
                    print("NO_RAISE", name, attempt)
                except RuntimeError as e:
                    print("RAISED", name, attempt, "sh05 boom" in str(e))
            print("LEFT", key, key in sys.modules)
        held = sys.modules.get("sh05_held")
        print("HELD_KEPT", type(held).__name__, getattr(held, "__file__", None))
    """))
    lines = out.splitlines()
    for name, key in (("sh05_broken", "sh05_broken"), ("sh05_held", "script_analysis_sh05_held")):
        assert f"RAISED {name} 1 True" in lines and f"RAISED {name} 2 True" in lines, out
        assert f"LEFT {key} False" in lines, out
    assert not any(l.startswith("NO_RAISE") for l in lines), out
    assert "HELD_KEPT module None" in lines, out


def test_id_words_come_from_the_script_generic_with_binary_generic_loaded():
    """shape_fallback_lib._id_words reads ID_WORDS from this lane's generic even when the Binary generic
    holds the name (that module has no ID_WORDS). analyze is blocked so its known_words() cannot supply
    the words instead."""
    out = _ok(_child("""
        print("BINARY_HAS_ID_WORDS", hasattr(_binary_generic, "ID_WORDS"))
        sys.modules["analyze"] = None          # `import analyze` raises ImportError: generic is the only source
        import shape_fallback_lib, plan_codec
        words = shape_fallback_lib._id_words()
        script_words = set(plan_codec.own("generic").ID_WORDS)
        print("NONEMPTY", bool(script_words))
        print("EQUAL", words == script_words)
        print("JSCRIPT", "jscript" in words, "vbscript" in words)
    """))
    lines = out.splitlines()
    assert "BINARY_HAS_ID_WORDS False" in lines, out
    assert "NONEMPTY True" in lines and "EQUAL True" in lines and "JSCRIPT True True" in lines, out


def test_analyze_own_delegates_to_plan_codec_own(tmp_path):
    """analyze._own is plan_codec.own (one copy of the rule): pointing plan_codec at another folder moves
    analyze._own with it, and the module lands under the key own() chose."""
    (tmp_path / "sh05_probe.py").write_text("VALUE = 4205\n", encoding="utf-8")
    (tmp_path / "sh05_probe2.py").write_text("VALUE = 7\n", encoding="utf-8")
    out = _ok(_child(f"""
        from pathlib import Path
        import analyze, plan_codec
        print("SAME_PLAN_CODEC", analyze.plan_codec is plan_codec)
        plan_codec.HERE = Path({str(tmp_path.resolve())!r})
        m = analyze._own("sh05_probe")
        print("VALUE", m.VALUE, sys.modules.get("sh05_probe") is m)
        sys.modules["sh05_probe2"] = _binary_generic                 # the short name held by another file
        m2 = analyze._own("sh05_probe2")
        print("HELD", m2.VALUE, sys.modules.get("script_analysis_sh05_probe2") is m2)
    """))
    lines = out.splitlines()
    assert "SAME_PLAN_CODEC True" in lines, out
    assert "VALUE 4205 True" in lines and "HELD 7 True" in lines, out


def test_analyze_boots_plan_codec_when_nothing_loaded_it():
    """In a fresh process analyze loads plan_codec itself (its bootstrap copy stays unregistered) and
    registers the real one under the short name: the same module its siblings' bare `import plan_codec`
    get."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ONLY", "BATCH_", "CTF_HIDE"))}
    proc = subprocess.run([sys.executable, "-c", textwrap.dedent(f"""
        import os, sys
        os.environ["CTF_TESTING"] = "1"
        sys.dont_write_bytecode = True
        sys.path[:0] = [{str(SA)!r}, {str(COMMON)!r}]
        assert "plan_codec" not in sys.modules
        import analyze
        pc = sys.modules.get("plan_codec")
        print("REGISTERED", pc is analyze.plan_codec, pc.__file__ == {str(SA / 'plan_codec.py')!r})
        print("BOOT_LEFT", "script_analysis_plan_codec_boot" in sys.modules)
        import plan_codec
        print("BARE_SAME", plan_codec is analyze.plan_codec, analyze.generic.plan_codec is plan_codec)
    """)], cwd=str(REPO), env=env, capture_output=True, text=True, timeout=120)
    lines = _ok(proc).splitlines()
    assert "REGISTERED True True" in lines and "BOOT_LEFT False" in lines and "BARE_SAME True True" in lines, \
        "\n".join(lines)


@pytest.mark.parametrize("key", ["plan_codec", "script_analysis_plan_codec"])
def test_analyze_reuses_a_loaded_plan_codec_without_running_it_again(key):
    """With this folder's plan_codec already loaded (under its short name, or under the private key when
    another lane holds the short name), importing analyze runs plan_codec's code zero more times: the
    loaded module is used to load the rest, not a fresh bootstrap copy. Counted with an `exec` audit hook
    on code compiled from plan_codec.py."""
    out = _ok(_child(f"""
        import importlib.util
        TARGET = {str((SA / 'plan_codec.py').resolve())!r}
        RUNS = []
        def _hook(event, args):
            if event == "exec" and args and getattr(args[0], "co_filename", None) == TARGET:
                RUNS.append(1)
        sys.addaudithook(_hook)
        if {key!r} == "plan_codec":
            import plan_codec as pc
        else:
            sys.modules["plan_codec"] = _binary_generic          # the short name held by another file
            spec = importlib.util.spec_from_file_location({key!r}, TARGET)
            pc = importlib.util.module_from_spec(spec)
            sys.modules[{key!r}] = pc
            spec.loader.exec_module(pc)
        before = len(RUNS)
        import analyze
        print("LOADED_RUNS", before)
        print("EXTRA_RUNS", len(RUNS) - before)
        print("SAME", analyze.plan_codec is pc)
    """))
    lines = out.splitlines()
    assert "LOADED_RUNS 1" in lines, out          # the hook does see plan_codec's own load
    assert "SAME True" in lines, out
    assert "EXTRA_RUNS 0" in lines, out


def test_binary_lane_keeps_its_generic_with_script_generic_loaded():
    """The reverse collision: with the Script lane's generic.py holding the short name `generic`, the
    Binary readers that use generic (structural_recover, selftest) still get solvers/binary/generic.py.
    The loader there is R-10's _shadowed.module_at; this guards it from the Script lane's side."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ONLY", "BATCH_", "CTF_HIDE"))}
    proc = subprocess.run([sys.executable, "-c", textwrap.dedent(f"""
        import os, sys
        os.environ["CTF_TESTING"] = "1"
        sys.dont_write_bytecode = True
        sys.path[:0] = [{str(SA)!r}, {str(COMMON)!r}]
        import generic as _script_generic
        assert _script_generic.__file__ == {str(SA / 'generic.py')!r}, _script_generic.__file__
        sys.path.insert(0, {str(BIN)!r})
        import structural_recover, selftest
        print("STRUCT", structural_recover.generic.__file__)
        print("SELFTEST", selftest.generic.__file__)
        print("SCRIPT_KEEPS_NAME", sys.modules["generic"] is _script_generic)
    """)], cwd=str(REPO), env=env, capture_output=True, text=True, timeout=120)
    lines = _ok(proc).splitlines()
    assert f"STRUCT {BIN / 'generic.py'}" in lines, lines
    assert f"SELFTEST {BIN / 'generic.py'}" in lines, lines
    assert "SCRIPT_KEEPS_NAME True" in lines, lines
