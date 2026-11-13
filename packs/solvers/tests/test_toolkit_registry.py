"""The toolkit registry and the bundle router it feeds (B-001b).

Ported in part from Huntress tests/test_toolkit_registry.py (archived because it drove tools/lane_match.py
and tools/open_day.py, neither of which master carries): the registry checks and the triage-map check
are kept; the lane_match decide/match checks and the opener check are not (no lane_match in master).
New here: bundle routing is on and hands a synthetic sample to its toolkit, and every registry or
toolkit load miss raises a named error instead of a quiet "registry not loaded".

Fixtures are synthetic (tests/toolkit_fixtures.py builds a 4-packet pcap and a 3-hop .eml).
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import labels
import toolkit_fixtures as fx
from ctf import env, packs
from ctf.packs import PackLoadError, PackMissing, RegistryLoadError

REPO = Path(__file__).resolve().parent.parent
REG_PATH = REPO / "solvers" / "toolkits" / "registry.py"


@pytest.fixture()
def reg():
    return packs.toolkit_registry(REPO)


@pytest.fixture()
def ec(reg):
    """The evidence_core toolkit face (solvers/toolkits/evidence_core.py), as the registry loads it."""
    return reg.load("evidence_core")


def _case_input(case):
    qs = [dict(q, qid=q["id"]) for q in case["questions"]]
    return qs, {case["filename"]: case["data"]}


# ------------------------------------------------------------------------------------------ the registry

def test_registry_loads_from_this_tree_under_one_module_name(reg):
    assert Path(reg.__file__).resolve() == REG_PATH.resolve()
    assert sys.modules[packs.REGISTRY_MODULE] is reg
    assert packs.toolkit_registry(REPO) is reg          # loaded once


def test_every_registered_toolkit_has_its_file_page_and_label_prefix(reg):
    keys = [t["key"] for t in reg.TOOLKITS]
    assert len(keys) == len(set(keys)) == 35
    assert [k for k in keys if not reg.path(k).is_file()] == []
    assert [k for k in keys if not reg.doc(k).is_file()] == []
    bad = [k for k in keys if reg.label_prefix(k) not in labels.LANE_DIRS
           or reg.label_prefix(k) not in labels.TOOLKIT_PREFIXES]
    assert bad == []
    assert all(0.3 <= t["threshold"] <= 0.9 for t in reg.TOOLKITS)
    assert [t["key"] for t in reg.entries(match_only=True)] == [t["key"] for t in reg.TOOLKITS if t.get("match")]


def test_readme_carries_the_registry_table_row_for_row(reg):
    assert reg.table() in (REPO / "docs" / "toolkits" / "README.md").read_text(encoding="utf-8")


def test_key_of_accepts_only_registered_toolkit_names(reg):
    assert reg.key_of("toolkit:network") == "network"
    assert reg.key_of("warmups") == reg.key_of("toolkit:nope") == reg.key_of(None) == ""


def test_every_toolkit_loads_in_one_process_beside_the_standard_email_package():
    code = ("import sys\nsys.path.insert(0, %r)\nfrom ctf import packs\nr = packs.toolkit_registry(%r)\n"
            "bad = [t['key'] for t in r.TOOLKITS if not (callable(getattr(r.load(t['key']), 'signals', None)) "
            "and callable(getattr(r.load(t['key']), 'solve_set', None)))]\n"
            "q = [{'qid': 'q', 'answer_id': 'q', 'question': 'What is it?', 'answer_format': {'kind': 'exact_text'}}]\n"
            "s = [r.signal(t['key'], q, {'a.bin': bytes(64)}) for t in r.TOOLKITS]\n"
            "import email, email.parser, mailbox\n"
            "print(bad, max(s), 'email/__init__' in (email.__file__ or ''))\n") % (str(REPO), str(REPO))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=180, cwd=str(REPO))
    assert r.returncode == 0, r.stderr[-800:]
    assert r.stdout.strip().splitlines()[-1] == "[] 0.0 True", r.stdout[-400:] + r.stderr[-400:]


# ------------------------------------------------------------------------------------------ routing is on

@pytest.mark.parametrize("make_case", [fx.pcap_case, fx.eml_case], ids=["pcap->network", "eml->email"])
def test_bundle_routing_hands_a_synthetic_sample_to_its_toolkit(ec, monkeypatch, make_case):
    for name in ("CTF_BUNDLE_ROUTER", *env.legacy_names("CTF_BUNDLE_ROUTER")):
        monkeypatch.delenv(name, raising=False)
    case = make_case()
    qs, files = _case_input(case)
    own = ec._mod.solve_set(qs, files, {})               # the evidence layer alone answers neither question
    assert all(v is None for v in own.values())
    ctx = {}
    out = ec.solve_set(qs, files, ctx)
    want = case["toolkit"]
    assert ctx["evidence_core"]["routed"] == {q["id"]: [want] for q in case["questions"]}
    for qid, key_value in case["key"].items():
        parsed = labels.parse(out[qid])
        assert parsed is not None and parsed.options[0][1] == key_value, out[qid]


def test_bundle_routing_off_switch_routes_nothing(ec, monkeypatch):
    monkeypatch.setenv("CTF_BUNDLE_ROUTER", "off")
    qs, files = _case_input(fx.pcap_case())
    ctx = {}
    out = ec.solve_set(qs, files, ctx)
    assert all(v is None for v in out.values())
    assert "routed" not in ctx.get("evidence_core", {})


def test_triage_map_names_the_matching_toolkit_first():
    sys.path.insert(0, str(REPO / "solvers" / "common"))
    tri = packs.load_module("b001b_common_triage", REPO / "solvers" / "common" / "triage.py")
    for case in (fx.pcap_case(), fx.eml_case()):
        qs, files = _case_input(case)
        rows = tri.toolkits(qs, files)["rows"]
        assert rows and rows[0]["key"] == case["toolkit"] and rows[0]["signal"] >= rows[0]["threshold"], rows


# ------------------------------------------------------------------------------------------ loud misses

def test_an_unregistered_key_raises_pack_missing(reg):
    with pytest.raises(PackMissing, match="toolkit:no_such_toolkit"):
        reg.load("no_such_toolkit")


@pytest.fixture()
def lone_registry(tmp_path, monkeypatch):
    """A temp tree holding only registry.py (a copy): every registered toolkit file is missing. Loaded under
    a module name of its own; the toolkits' module names are cleared for the test and restored after."""
    monkeypatch.setattr(sys, "path", list(sys.path))
    d = tmp_path / "solvers" / "toolkits"
    d.mkdir(parents=True)
    shutil.copy2(REG_PATH, d / "registry.py")
    mod = packs.load_module("b001b_lone_registry", d / "registry.py")
    monkeypatch.delitem(sys.modules, "b001b_lone_registry")
    for t in mod.TOOLKITS:
        monkeypatch.delitem(sys.modules, mod.MODULE_PREFIX + t["key"], raising=False)
    return mod


def test_a_registered_toolkit_whose_file_is_gone_raises_pack_missing(lone_registry):
    with pytest.raises(PackMissing, match=r"toolkit:evidence_core'.*file not there"):
        lone_registry.load("evidence_core")
    with pytest.raises(PackMissing, match="toolkit:evidence_core"):
        lone_registry.entries()                 # never skipped quietly, as the forks' entries() did
    with pytest.raises(PackMissing):
        lone_registry.rank([{"qid": "q", "question": "x"}], {"a.bin": b"x"})


def test_a_toolkit_that_raises_on_import_raises_pack_load_error(lone_registry):
    (Path(lone_registry.HERE) / "network.py").write_text("raise RuntimeError('broken pack for B-001b')\n")
    with pytest.raises(PackLoadError, match="RuntimeError: broken pack for B-001b") as e:
        lone_registry.load("network")
    assert isinstance(e.value.__cause__, RuntimeError)
    assert lone_registry.MODULE_PREFIX + "network" not in sys.modules


def test_a_toolkit_whose_signals_raise_scores_zero_and_says_so(lone_registry, capsys):
    (Path(lone_registry.HERE) / "network.py").write_text(
        "def signals(questions, files):\n    raise ValueError('no signal')\n"
        "def solve_set(questions, files, ctx):\n    return {}\n")
    assert lone_registry.signal("network", [], {}) == 0.0
    assert "toolkit:network signals() raised ValueError: no signal" in capsys.readouterr().err


def test_the_router_raises_registry_load_error_without_its_registry(ec, tmp_path, monkeypatch):
    monkeypatch.setattr(ec, "_ROOT", tmp_path)                 # a tree with no solvers/toolkits/registry.py
    monkeypatch.delitem(sys.modules, packs.REGISTRY_MODULE, raising=False)
    for name in ("CTF_BUNDLE_ROUTER", *env.legacy_names("CTF_BUNDLE_ROUTER")):
        monkeypatch.delenv(name, raising=False)
    qs, files = _case_input(fx.pcap_case())
    with pytest.raises(RegistryLoadError, match="registry.py"):
        ec.route(qs, files)
    with pytest.raises(RegistryLoadError):
        ec.solve_set(qs, files, {})                    # the forks answered on with "registry not loaded"


def test_the_triage_map_raises_registry_load_error_without_its_registry(tmp_path, monkeypatch):
    monkeypatch.delitem(sys.modules, packs.REGISTRY_MODULE, raising=False)
    tri = packs.load_module("b001b_common_triage_moved", REPO / "solvers" / "common" / "triage.py", cache=False)
    monkeypatch.setattr(tri, "HERE", tmp_path / "solvers" / "common")
    with pytest.raises(RegistryLoadError):
        tri.toolkits([{"qid": "q", "question": "x"}], {"a.bin": b"x"})


def test_ctf_triage_identify_files_raises_when_its_reader_is_gone(tmp_path, monkeypatch):
    from ctf import triage as ctf_triage
    monkeypatch.delitem(sys.modules, "ctf_common_triage", raising=False)
    monkeypatch.setattr(ctf_triage, "REPO", tmp_path)
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "a.bin").write_bytes(b"\x7fELF" + bytes(60))
    with pytest.raises(PackMissing, match="solvers/common/triage.py"):
        ctf_triage.identify_files(tmp_path / "files")


def test_ctf_triage_identify_files_reads_with_the_common_reader(tmp_path):
    from ctf import triage as ctf_triage
    (tmp_path / "capture.pcap").write_bytes(fx.pcap_bytes())
    [(name, desc)] = ctf_triage.identify_files(tmp_path)
    assert name == "capture.pcap" and "magic" not in desc and "pcap" in desc.lower(), desc
