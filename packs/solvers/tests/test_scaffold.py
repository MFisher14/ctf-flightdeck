"""B-258: the shipped scratch scaffolds (ctf/scaffold.py, ctf/scaffold_templates/) and `ctf scaffold`.

The library runs are driven with small targets written here. The generated files are then run for
real as scripts (a subprocess of this interpreter) in a temp folder with a synthetic sample, so a
template that no longer fits the library fails here. Timing assertions use an injected clock or CPU
time with lower bounds only (rule 16).
"""
from __future__ import annotations

import io
import subprocess
import sys

import pytest

import ctf.cli as cli
from ctf import expectations as X
from ctf import paths
from ctf import scaffold as S


def reader(data: bytes):
    """A toy day reader: the record after b'CFG:' and its length; None when absent or doubled."""
    if data.count(b"CFG:") != 1:
        return {"q_value": None, "q_len": None}
    tail = data.split(b"CFG:", 1)[1][:8]
    return {"q_value": tail.decode("latin-1"), "q_len": len(data)}


def fragile(data: bytes):
    return {"q_first": data[0]}          # raises on empty input


def checked(data: bytes):
    """A careful reader: one CFG: record whose 8 bytes carry their checksum byte, else None."""
    if data.count(b"CFG:") != 1:
        return {"q_value": None}
    tail = data.split(b"CFG:", 1)[1][:9]
    if len(tail) != 9 or sum(tail[:8]) % 256 != tail[8]:
        return {"q_value": None}
    return {"q_value": tail[:8].decode("latin-1")}


def overconfident(data: bytes):
    """Answers whatever follows the first CFG:, checked or not: a damaged record still answers."""
    i = data.find(b"CFG:")
    return {"q_value": data[i + 4:i + 12].decode("latin-1") if i >= 0 else None}


def sample(value: bytes = b"abcdefgh") -> bytes:
    return b"\x00" * 16 + b"CFG:" + value + bytes([sum(value) % 256]) + b"\x11" * 16


SAMPLE = sample()


# ================================================================================================ repro

def test_repro_reports_pass_fail_error_and_out():
    out = io.StringIO()
    cases = [S.case("ok", SAMPLE, expect={"q_value": "abcdefgh", "q_len": len(SAMPLE)}),
             S.case("wrong", SAMPLE, expect={"q_value": "zzzzzzzz", "q_len": len(SAMPLE)}),
             S.case("loose", SAMPLE)]
    code, doc = S.repro(reader, cases, out=out)
    text = out.getvalue()
    assert code == 1
    assert "PASS  ok" in text
    assert "FAIL  wrong: 1 difference(s)" in text
    assert "wrong['q_value']: expected \"zzzzzzzz\", got \"abcdefgh\"" in text
    assert "OUT   loose: {'q_value': 'abcdefgh'" in text
    assert "repro: pass=1 fail=1 error=0 out=1" in text
    assert doc["cases"]["ok"] == {"output": {"q_value": "abcdefgh", "q_len": len(SAMPLE)}}
    out = io.StringIO()
    code, doc = S.repro(fragile, [S.case("empty", b"")], out=out)
    assert code == 1
    assert "ERROR empty: IndexError" in out.getvalue()
    assert "data[0]" in out.getvalue()                 # the failing frame is shown
    assert doc["cases"]["empty"]["error"].startswith("IndexError")


def test_repro_checks_a_saved_expectations_file_and_only_filters():
    saved = X.generate(reader, [S.case("a", SAMPLE), S.case("b", b"none here")])
    code, _ = S.repro(reader, [S.case("a", SAMPLE), S.case("b", b"none here")], expect_doc=saved, out=io.StringIO())
    assert code == 0
    out = io.StringIO()
    code, _ = S.repro(reader, [S.case("a", SAMPLE + b"CFG:decoy!!!"), S.case("b", b"x")], expect_doc=saved,
                      only="^a$", out=out)
    assert code == 1 and "FAIL  a" in out.getvalue() and " b" not in out.getvalue().replace("b'", "")
    with pytest.raises(S.ScaffoldError, match="matched none"):
        S.repro(reader, [S.case("a", SAMPLE)], only="zzz", out=io.StringIO())


def test_repro_fails_a_case_whose_saved_error_now_returns_output():
    saved = X.generate(fragile, [S.case("empty", b""), S.case("one", b"\x05")])
    assert saved["cases"]["empty"] == {"error": "IndexError: index out of range"}
    out = io.StringIO()
    code, doc = S.repro(lambda data: {"q_first": None}, [S.case("empty", b""), S.case("one", b"\x05")],
                        expect_doc=saved, out=out)
    text = out.getvalue()
    assert code == 1
    assert "FAIL  empty: 1 difference(s)" in text
    assert "IndexError: index out of range" in text and 'got {"output": {"q_first": null}}' in text
    assert "FAIL  one: 1 difference(s)" in text
    assert "repro: pass=0 fail=2 error=0 out=0" in text
    assert doc["cases"]["empty"] == {"output": {"q_first": None}}
    # the same saved error, raised again, is reported as an error, never a pass
    out = io.StringIO()
    code, _ = S.repro(fragile, [S.case("empty", b"")], expect_doc=saved, out=out)
    assert code == 1 and "ERROR empty: IndexError" in out.getvalue()


def test_repro_refuses_a_repeated_case_id_and_a_non_case():
    with pytest.raises(S.ScaffoldError, match="'a' appears twice"):
        S.repro(reader, [S.case("a", SAMPLE), S.case("a", b"x")], out=io.StringIO())
    # an id filtered out by --only is not counted twice
    code, doc = S.repro(reader, [S.case("a", SAMPLE), S.case("b", b"x"), S.case("b", b"y")], only="^a$",
                        out=io.StringIO())
    assert code == 0 and list(doc["cases"]) == ["a"]
    with pytest.raises(S.ScaffoldError, match="not a case"):
        S.repro(reader, [("a", SAMPLE)], out=io.StringIO())


# ================================================================================================ probe

def test_probe_prints_facts_needles_hexdump_strings_and_custom_probes(tmp_path):
    f = tmp_path / "s.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 12 + b"HCFG" + b"hello world" + b"HCFG")

    def tail(name, data):
        return data[-4:]

    def broken(name, data):
        raise KeyError("nope")

    out = io.StringIO()
    assert S.probe([f], [tail, broken], find=["HCFG", "hex:7f454c46"], at=16, length=8, min_strings=5,
                   grep="world", out=out) == 0
    text = out.getvalue()
    assert "format   elf" in text
    assert "size     35" in text
    assert "find 'HCFG': 0x10, 0x1f" in text
    assert "find 'hex:7f454c46': 0x0" in text
    assert "  00000010  48 43 46 47 68 65 6c 6c" + " " * 24 + "  HCFGhell\n" in text
    assert "strings  1" in text and "HCFGhello world" in text
    assert "tail: b'HCFG'" in text
    assert "broken: raised KeyError" in text
    with pytest.raises(S.ScaffoldError, match="no such file"):
        S.probe([tmp_path / "missing"], out=io.StringIO())


def test_probe_helpers():
    assert S.entropy(b"") == 0.0
    assert S.entropy(b"aaaa") == 0.0
    assert S.entropy(bytes(range(256))) == pytest.approx(8.0)
    assert S.needle("0x4142") == b"AB" and S.needle("hex:41 42") == b"AB" and S.needle("AB") == b"AB"
    with pytest.raises(S.ScaffoldError, match="not hex"):
        S.needle("hex:zz")
    assert S.find_all(b"aXaXa", b"a") == [0, 2, 4]
    assert S.hexdump(b"0123456789", at=-2) == ["00000008  38 39" + " " * 42 + "  89"]
    assert S.sniff(b"PK\x03\x04rest") == "zip" and S.sniff(b"??") == "unknown"


# ========================================================================================== adversarial

def test_variants_are_seeded_and_cover_each_subject_kind():
    a = S.variants(SAMPLE, seed=3)
    assert a == S.variants(SAMPLE, seed=3)
    assert a != S.variants(SAMPLE, seed=4)
    labels = [lab for lab, _ in a]
    assert {"empty", "truncate-half", "duplicate-whole", "append-junk"} <= set(labels)
    assert sum(lab.startswith("bitflip@") for lab in labels) == 8
    for lab, v in a:
        if lab.startswith("bitflip@"):
            assert len(v) == len(SAMPLE) and sum(bin(x ^ y).count("1") for x, y in zip(v, SAMPLE)) == 1
    files = S.variants({"d77--a.bin": b"abc"})
    names = dict(files)
    assert names["drop:d77--a.bin"] == {}
    assert names["decoy-copy:d77--a.bin"] == {"d77--a.bin": b"abc", "d77--a.decoy.bin": b"abc"}
    assert S.variants({"k": 1, "j": 2})[0] == ("drop:j", {"k": 1})
    assert ("upper", "ABC") in S.variants("abc")
    with pytest.raises(S.ScaffoldError, match="no mutators"):
        S.variants(3.5)


def test_classify_per_key():
    assert S.classify({"a": 1, "b": 2}, {"a": 1, "b": 2}) == ("same", [])
    assert S.classify({"a": 1, "b": 2}, {"a": 1}) == ("declined", ["b"])
    assert S.classify({"a": 1, "b": 2}, {"a": 1, "b": None}) == ("declined", ["b"])
    kind, detail = S.classify({"a": 1, "b": 2}, {"a": 1, "b": 3})
    assert kind == "changed" and detail == ["b: 2 -> 3"]
    assert S.classify({"a": 1}, {"a": True})[0] == "changed"
    assert S.classify("x", None)[0] == "declined"


def test_adversarial_passes_a_reader_that_declines_and_fails_a_guessing_one():
    out = io.StringIO()
    code, verdicts = S.adversarial(checked, S.case("base", SAMPLE), out=out)
    kinds = {v.label: v.kind for v in verdicts}
    assert code == 0, out.getvalue()
    assert kinds["duplicate-whole"] == "declined"           # two records: not unique, None
    assert kinds["empty"] == "declined"
    assert kinds["truncate-half"] == "declined"              # the record is cut: its checksum fails
    assert "changed" not in kinds.values() and "raised" not in kinds.values()

    out = io.StringIO()
    code, verdicts = S.adversarial(overconfident, S.case("base", SAMPLE), only="truncate-half", out=out)
    assert code == 1 and verdicts[0].kind == "changed"
    assert "changed   truncate-half" in out.getvalue()

    code, verdicts = S.adversarial(fragile, S.case("base", SAMPLE), only="^empty$", out=io.StringIO())
    assert code == 1 and verdicts[0].kind == "raised" and "IndexError" in verdicts[0].detail
    code, _ = S.adversarial(fragile, S.case("base", SAMPLE), only="^empty$", allow_raise=True, out=io.StringIO())
    assert code == 0


def test_adversarial_oracle_accepts_a_change_the_mutation_caused():
    seen = []

    def oracle(label, case, base, got):
        seen.append(label)
        return label == "truncate-half"

    code, verdicts = S.adversarial(overconfident, S.case("base", SAMPLE), only="truncate-half",
                                   oracle=oracle, out=io.StringIO())
    assert code == 0 and verdicts[0].kind == "accepted" and seen == ["truncate-half"]


def test_adversarial_mutates_a_keyword_subject_and_refuses_a_broken_base():
    def by_kw(*, files):
        return {"n": len(files)}
    code, verdicts = S.adversarial(by_kw, S.case("base", files={"a": b"1", "b": b"2"}), subject="files",
                                   only="^drop:a$", out=io.StringIO())
    assert verdicts[0].kind == "changed" and code == 1
    with pytest.raises(S.ScaffoldError, match="base case raises"):
        S.adversarial(fragile, S.case("base", b""), out=io.StringIO())
    with pytest.raises(S.ScaffoldError, match="subject index 2"):
        S.adversarial(reader, S.case("base", SAMPLE), subject=2, out=io.StringIO())


# ================================================================================================ bench

def test_bench_with_an_injected_clock_reports_exact_cpu_and_the_budget():
    def runs():                                         # three runs: 0.5, 0.25, 1.5 CPU seconds
        return iter([0.0, 0.5, 1.0, 1.25, 2.0, 3.5])
    ticks, walls = runs(), iter(range(100))
    out = io.StringIO()
    code, rows = S.bench(len, [S.case("a", b"x")], repeat=3, cpu_budget=0.4, out=out,
                         clock=lambda: next(ticks), wall=lambda: float(next(walls)))
    assert rows[0].cpu == [0.5, 0.25, 1.5] and rows[0].median_cpu == 0.5
    assert code == 1 and "OVER a: cpu min 0.2500 median 0.5000 max 1.5000" in out.getvalue()
    # the budget is on the median (0.5): 0.3 is over it but not the min (0.25); 0.6 is under the mean
    # (0.75) and the max (1.5) but not the median; 1.0 is under the max only
    for budget, over in ((0.3, True), (0.6, False), (1.0, False)):
        ticks, out = runs(), io.StringIO()
        code, _ = S.bench(len, [S.case("a", b"x")], repeat=3, cpu_budget=budget, out=out,
                          clock=lambda: next(ticks))
        assert (code, out.getvalue().startswith("OVER ")) == ((1, True) if over else (0, False)), budget
    ticks = iter([0.0, 0.1])
    code, _ = S.bench(len, [S.case("a", b"x")], repeat=1, cpu_budget=0.4, out=io.StringIO(),
                      clock=lambda: next(ticks))
    assert code == 0


def test_bench_measures_real_cpu_time_and_profiles():
    def burn(n):
        x = 0
        for i in range(n):
            x += i * i
        return x
    out = io.StringIO()
    code, rows = S.bench(burn, [S.case("burn", 300_000)], repeat=1, cpu_budget=0.0, profile=True, top=5, out=out)
    assert code == 1                                    # any real work is over a zero budget
    assert rows[0].cpu[0] > 0                           # a lower bound only
    assert "cumulative" in out.getvalue() and "burn" in out.getvalue()
    code, _ = S.bench(len, [S.case("tiny", b"x")], repeat=2, cpu_budget=5.0, out=io.StringIO())
    assert code == 0
    code, _ = S.bench(fragile, [S.case("empty", b"")], out=io.StringIO())
    assert code == 1


# ============================================================================== generated files, for real

def _run(path, *args, cwd):
    return subprocess.run([sys.executable, str(path), *args], cwd=cwd, capture_output=True, text=True,
                          timeout=600)


TARGET_SRC = '''\
def answers(data):
    if data.count(b"CFG:") != 1:
        return {"q_value": None}
    tail = data.split(b"CFG:", 1)[1][:9]
    if len(tail) != 9 or sum(tail[:8]) % 256 != tail[8]:
        return {"q_value": None}
    return {"q_value": tail[:8].decode("latin-1")}
'''


@pytest.fixture
def work(tmp_path):
    (tmp_path / "tgt.py").write_text(TARGET_SRC)
    (tmp_path / "sample.bin").write_bytes(SAMPLE)
    return tmp_path


def test_generated_repro_runs_saves_and_feeds_the_codemod(work, capsys):
    path = S.write_scaffold("repro", work, target="tgt.py:answers")
    assert path == work / "repro.py"
    text = path.read_text()
    assert str(paths.repo_root()) in text and "@@" not in text
    r = _run(path, "--save", "out.json", cwd=work)
    assert r.returncode == 0, r.stderr
    assert "OUT   base: {'q_value': 'abcdefgh'" in r.stdout
    doc = X.load(work / "out.json")
    assert doc["cases"]["base"]["output"] == {"q_value": "abcdefgh"}
    r = _run(path, "--expect", "out.json", cwd=work)
    assert r.returncode == 0 and "PASS  base" in r.stdout
    (work / "sample.bin").write_bytes(sample(b"ABCDEFGH"))
    r = _run(path, "--expect", "out.json", cwd=work)
    assert r.returncode == 1 and "FAIL  base" in r.stdout
    # the codemod takes the fresh outputs into a test file's pins
    r = _run(path, "--save", "new.json", cwd=work)
    test_file = work / "test_pinned.py"
    test_file.write_text('EXPECTED = {"q_value": "abcdefgh"}\n')
    assert cli.main(["testpin", "--write", "--outputs", str(work / "new.json"), str(test_file)]) == 0
    assert test_file.read_text() == 'EXPECTED = {"q_value": "ABCDEFGH"}\n'


def test_generated_probe_adv_and_bench_run(work):
    probe = S.write_scaffold("probe", work)
    r = _run(probe, "sample.bin", "--find", "CFG:", cwd=work)
    assert r.returncode == 0, r.stderr
    assert "find 'CFG:': 0x10" in r.stdout and "tail_u32: 286331153" in r.stdout
    assert _run(probe, "nope.bin", cwd=work).returncode == 2

    adv = S.write_scaffold("adv", work, target="tgt.py:answers")
    r = _run(adv, "--max", "6", cwd=work)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "adv: same=" in r.stdout and "raised=0" in r.stdout

    bench = S.write_scaffold("bench", work, target="tgt.py:answers", name="prof")
    assert bench.name == "prof.py"
    r = _run(bench, "--repeat", "2", "--cpu-budget", "30", cwd=work)
    assert r.returncode == 0, r.stderr
    assert "base: cpu min" in r.stdout


def test_write_scaffold_refuses_to_overwrite_and_unknown_kinds(work):
    S.write_scaffold("probe", work)
    with pytest.raises(S.ScaffoldError, match="exists"):
        S.write_scaffold("probe", work)
    S.write_scaffold("probe", work, force=True)
    with pytest.raises(S.ScaffoldError, match="unknown scaffold"):
        S.render("nope")
    with pytest.raises(S.ScaffoldError, match="expected FILE.py:FUNCTION"):
        S.render("repro", target="no-colon")


def test_cli_scaffold_writes_and_refuses(work, capsys):
    assert cli.main(["scaffold", "repro", str(work / "r1.py"), "--target", "tgt.py:answers"]) == 0
    assert capsys.readouterr().out.strip() == str(work / "r1.py")
    assert 'TARGET = "tgt.py:answers"' in (work / "r1.py").read_text()
    assert cli.main(["scaffold", "repro", str(work / "r1.py")]) == 2
    assert "exists" in capsys.readouterr().err
    assert cli.main(["scaffold", "list"]) == 0
    assert "racer" in capsys.readouterr().out
