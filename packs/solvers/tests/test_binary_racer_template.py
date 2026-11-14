"""B-258: the complex-racer day template (solvers/binary/racer_template.py) and `ctf scaffold racer`.

Synthetic deliveries carry the stated record layout (magic, version, XOR key, u16le length, u32le
CRC-32 of the decoded payload, XOR-ed JSON). The candidate is written to a temp lane folder, put under
a final name there and loaded through the lane dispatcher (evidence.load), as promotion would.
"""
from __future__ import annotations

import importlib.util
import json
import struct
import sys
import zlib

import pytest

import ctf.cli as cli
import evidence
import racer_template as RT
from ctf import paths
from ctf import scaffold as S

TEMPLATE = paths.repo_root() / "solvers" / "binary" / "racer_template.py"


def _binary_generic():
    """solvers/binary/generic.py under binary_generic: never `import generic`, since script-analysis has
    one too and whichever lane folder is first on sys.path wins (integration fix, batch 905)."""
    mod = sys.modules.get("binary_generic")
    if mod is None or not hasattr(mod, "PREFIX"):
        spec = importlib.util.spec_from_file_location(
            "binary_generic", paths.repo_root() / "solvers" / "binary" / "generic.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["binary_generic"] = mod
        spec.loader.exec_module(mod)
    return mod


generic = _binary_generic()


def record(magic: bytes, obj, key: int = 0x5A, crc_fix: int = 0) -> bytes:
    plain = json.dumps(obj).encode()
    enc = bytes(b ^ key for b in plain)
    return magic + bytes([1, key]) + struct.pack("<HI", len(enc), (zlib.crc32(plain) + crc_fix) & 0xFFFFFFFF) + enc


GAU = {"gauntlet": {"config": {"url": "http://x.invalid/a"}, "trace": "decoy"}}


def q(qid, text, **fmt):
    return {"qid": qid, "question": text, "answer_format": fmt or {"kind": "exact_text"}}


def crc_q(day):
    return q(f"d{day}_analysis_gauntlet_crc32_hex",
             "The CRC32-valid HGAU record: submit header bytes 8..11 as eight lowercase hexadecimal digits.")


def prop_q(day, prop="gauntlet.config.url", **fmt):
    return q(f"d{day}_analysis_gauntlet_config_url",
             f"In the CRC32-valid HGAU record, submit the JSON property {prop}.", **fmt)


def test_the_template_is_inert_under_its_name():
    assert RT.PREFIX == "template"
    assert RT.RULES == []
    # the dispatcher never loads it: no prefix of letters and digits names it
    mod, why = evidence.load("racer_template")
    assert mod is None and "no racer_template.py" in why
    assert not evidence.MODULE_NAME.fullmatch("racer_template")
    # generic.py's hook is fields_<prefix>.py only, for a prefix of letters and digits
    assert not generic.PREFIX.fullmatch("racer_template") and not TEMPLATE.name.startswith("fields_")
    assert generic._hook("racer_template") is None
    # and its own answers, with RULES empty, read nothing
    body = b"\x7fELF" + record(b"HGAU", GAU)
    assert RT.answers([crc_q(31)], {"d31--s.elf": body}, {}) == {}


def _candidate(tmp_path, day, monkeypatch, *, rules="EXAMPLE_RULES"):
    path = S.write_racer(day, lane_dir=tmp_path, template=TEMPLATE)
    assert path.name == f"d{day}_cx_dev.py"
    text = path.read_text()
    assert f'PREFIX = "d{day}"' in text and 'PREFIX = "template"' not in text
    final = tmp_path / f"d{day}.py"       # what the promotion step would do after its replay
    final.write_text(text.replace("RULES = []   #", f"RULES = {rules}   #"))
    monkeypatch.setattr(evidence, "MODULES", tmp_path)
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, f"d{day}", raising=False)
    mod, why = evidence.load(f"d{day}")
    assert mod is not None, why
    return mod


def test_a_racer_candidate_answers_the_stated_record_and_leaves_the_rest(tmp_path, monkeypatch):
    mod = _candidate(tmp_path, 91, monkeypatch)
    body = b"\x7fELF" + b"\x00" * 40 + record(b"HGAU", GAU) + b"\x00" * 8
    files = {"d91--sample.elf": body, "d90--other.elf": record(b"HGAU", {"gauntlet": {"config": {"url": "no"}}})}
    other = q("d91_artifact_sha256_1", "SHA-256 of the first file.")
    got = mod.answers([crc_q(91), prop_q(91), other], files, {})
    plain = json.dumps(GAU).encode()
    assert got == {"d91_analysis_gauntlet_crc32_hex": f"0x{zlib.crc32(plain):08x}",
                   "d91_analysis_gauntlet_config_url": "http://x.invalid/a"}
    # an id of another prefix is never answered
    assert mod.answers([crc_q(90)], files, {}) == {}


def test_a_racer_candidate_declines_what_the_bytes_do_not_settle(tmp_path, monkeypatch):
    mod = _candidate(tmp_path, 92, monkeypatch)
    two = record(b"HGAU", GAU) + record(b"HGAU", {"gauntlet": {"config": {"url": "decoy"}}})
    got = mod.answers([crc_q(92), prop_q(92)], {"d92--s.elf": two}, {})
    assert got == {"d92_analysis_gauntlet_crc32_hex": None, "d92_analysis_gauntlet_config_url": None}
    bad_crc = record(b"HGAU", GAU, crc_fix=1)
    assert mod.answers([crc_q(92)], {"d92--s.elf": bad_crc}, {}) == {"d92_analysis_gauntlet_crc32_hex": None}
    one = record(b"HGAU", GAU)
    assert mod.answers([prop_q(92, "gauntlet.config.missing")], {"d92--s.elf": one}, {}) == \
        {"d92_analysis_gauntlet_config_url": None}
    # equal bodies in two members are one record, not two
    assert mod.answers([crc_q(92)], {"d92--a.elf": one, "d92--b.elf": one}, {})[
        "d92_analysis_gauntlet_crc32_hex"] is not None


def test_answer_format_is_enforced(tmp_path, monkeypatch):
    mod = _candidate(tmp_path, 93, monkeypatch)
    one = record(b"HGAU", GAU)
    enum_q = prop_q(93, "gauntlet.trace", kind="enum", accepted_values=["success", "failure"])
    assert mod.answers([enum_q], {"d93--s.elf": one}, {}) == {"d93_analysis_gauntlet_config_url": None}
    ok_q = prop_q(93, "gauntlet.trace", kind="enum", accepted_values=["success", "decoy"])
    assert mod.answers([ok_q], {"d93--s.elf": one}, {}) == {"d93_analysis_gauntlet_config_url": "decoy"}
    int_q = prop_q(93, "gauntlet.config.url", kind="integer")
    assert mod.answers([int_q], {"d93--s.elf": one}, {}) == {"d93_analysis_gauntlet_config_url": None}


def test_leave_falls_through_to_the_next_row(tmp_path, monkeypatch):
    rules = ("[(r'analysis_\\w+', None, lambda q, m, s: LEAVE), "
             "(r'analysis_(\\w+)', None, lambda q, m, s: 'row2:' + m.group(1))]")
    mod = _candidate(tmp_path, 94, monkeypatch, rules=rules)
    assert mod.answers([q("d94_analysis_x", "anything")], {}, {}) == {"d94_analysis_x": "row2:x"}
    mod2 = _candidate(tmp_path, 95, monkeypatch, rules="[(r'analysis_\\w+', None, lambda q, m, s: LEAVE)]")
    assert mod2.answers([q("d95_analysis_x", "anything")], {}, {}) == {}


def test_write_racer_names_and_refusals(tmp_path):
    p = S.write_racer(7, role="helper1", lane_dir=tmp_path, template=TEMPLATE)
    assert p.name == "d07_helper1_dev.py"
    with pytest.raises(S.ScaffoldError, match="exists"):
        S.write_racer(7, role="helper1", lane_dir=tmp_path, template=TEMPLATE)
    for role in ("", "Owner", "a_b", "x" * 17):
        with pytest.raises(S.ScaffoldError, match="--role"):
            S.write_racer(8, role=role, lane_dir=tmp_path, template=TEMPLATE)
    for day in (0, 1000, True):
        with pytest.raises(S.ScaffoldError, match="--day"):
            S.write_racer(day, lane_dir=tmp_path, template=TEMPLATE)
    with pytest.raises(S.ScaffoldError, match="no lane folder"):
        S.write_racer(9, lane_dir=tmp_path / "nope", template=TEMPLATE)
    twice = tmp_path / "t.py"
    twice.write_text('PREFIX = "template"\nPREFIX = "template"\n')
    with pytest.raises(S.ScaffoldError, match="found 2"):
        S.write_racer(9, lane_dir=tmp_path, template=twice)
    assert not (tmp_path / "d09.py").exists() and not (tmp_path / "d07.py").exists()


def test_cli_racer(tmp_path, capsys):
    assert cli.main(["scaffold", "racer", "--day", "31", "--lane-dir", str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip() == str(tmp_path / "d31_cx_dev.py")
    assert cli.main(["scaffold", "racer", "--day", "31", "--lane-dir", str(tmp_path)]) == 2
    assert "exists" in capsys.readouterr().err


def test_the_template_cli_lists_records(tmp_path):
    import subprocess
    f = tmp_path / "template--s.elf"      # the members a module reads carry its prefix
    f.write_bytes(b"\x7fELF" + record(b"HCFG", {"k": 1}))
    r = subprocess.run([sys.executable, "-I", str(TEMPLATE), str(f)], capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr
    assert "record at 0x4 v=1 key=0x5a" in r.stdout and '{"k": 1}' in r.stdout
    qs = tmp_path / "q.json"
    qs.write_text(json.dumps([{"qid": "template_analysis_k_crc32_hex",
                               "question": "The CRC32-valid HCFG record: header bytes 8..11."}]))
    r = subprocess.run([sys.executable, "-I", str(TEMPLATE), "--examples", "--questions", str(qs), str(f)],
                       capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == f"template_analysis_k_crc32_hex = '0x{zlib.crc32(json.dumps({'k': 1}).encode()):08x}'"


# --------------------------------------------------------------------------- round-1 verification additions

def test_members_skip_archive_nested_names():
    # the unpacker names a nested member "<archive> -> <inner path>"; the archive itself is top-level
    files = {"template--a.elf": b"1", "template--o.zip -> template--b.elf": b"2", "dir/template--c.bin": b"3",
             "template--o.zip -> sub/template--e.elf": b"5", "template--o.zip -> x.elf": b"6",
             "other--d.elf": b"4"}
    assert RT.members(files) == [("template--a.elf", b"1"), ("dir/template--c.bin", b"3")]


def test_a_nested_member_never_makes_a_record_ambiguous(tmp_path, monkeypatch):
    mod = _candidate(tmp_path, 96, monkeypatch)
    one = record(b"HGAU", GAU)
    nested = record(b"HGAU", {"gauntlet": {"config": {"url": "nested"}}})
    got = mod.answers([crc_q(96)], {"d96--s.elf": one, "d96--outer.zip -> d96--inner.elf": nested}, {})
    assert got == {"d96_analysis_gauntlet_crc32_hex": f"0x{zlib.crc32(json.dumps(GAU).encode()):08x}"}


def test_select_needs_one_distinct_body():
    a, b = ("x--a.elf", b"\x7fELFa"), ("x--b.elf", b"\x7fELFb")
    assert RT.select([a, b], suffix=".elf") is None                    # two bodies: not one
    assert RT.select([a, ("x--a2.elf", a[1])], suffix=".elf") == a      # equal bodies count once
    assert RT.select([a, ("x--c.bin", b"zz")], suffix=".ELF") == a
    assert RT.select([a, b], magic=b"\x7fELFb") == b
    assert RT.select([a], suffix=".bin") is None


def suffix_q(day, suffix):
    return q(f"d{day}_analysis_gauntlet_crc32_hex",
             f"The CRC32-valid HGAU record in the member whose basename ends {suffix}: submit header bytes "
             "8..11 as eight lowercase hexadecimal digits.")


def test_a_suffix_question_declines_when_two_members_end_that_way(tmp_path, monkeypatch):
    mod = _candidate(tmp_path, 97, monkeypatch)
    one = record(b"HGAU", GAU)
    other = record(b"HGAU", {"gauntlet": {"config": {"url": "other"}}})
    # the suffix picks the one .elf: its record answers although the .bin carries another
    got = mod.answers([suffix_q(97, ".elf")], {"d97--s.elf": one, "d97--t.bin": other}, {})
    assert got == {"d97_analysis_gauntlet_crc32_hex": f"0x{zlib.crc32(json.dumps(GAU).encode()):08x}"}
    # two different .elf members: the suffix names no one member, so nothing is read
    got = mod.answers([suffix_q(97, ".elf")], {"d97--s.elf": one, "d97--u.elf": b"\x00" + other}, {})
    assert got == {"d97_analysis_gauntlet_crc32_hex": None}


@pytest.mark.parametrize("day,role", [(31, "cx"), (7, "helper1"), (999, "x" * 16)])
def test_a_racer_candidate_is_not_an_engine_module_and_is_gitignored(tmp_path, day, role):
    import subprocess
    from ctf.engines import layout
    lane = tmp_path / "solvers" / "binary"
    lane.mkdir(parents=True)
    cand = S.write_racer(day, role=role, lane_dir=lane, template=TEMPLATE)
    final = lane / f"d{day:02d}.py"
    final.write_text(cand.read_text())                      # what promotion writes
    assert not layout.is_engine_module(cand)
    assert layout.engine_modules(tmp_path) == [final]       # the promoted file is an engine, the candidate not
    rel = cand.relative_to(tmp_path).as_posix()
    r = subprocess.run(["git", "check-ignore", "--no-index", "-q", rel], cwd=paths.repo_root(),
                       capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, f"{rel} is not gitignored: {r.stderr}"
    r = subprocess.run(["git", "check-ignore", "--no-index", "-q", f"solvers/binary/d{day:02d}.py"],
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=600)
    assert r.returncode == 1, r.stderr                      # the promoted name is not ignored


def test_layout_skips_only_the_candidate_shape(tmp_path):
    from ctf.engines import layout
    for name, engine in (("d31_cx_dev.py", False), ("d31.py", True), ("d31_cx.py", True),
                         ("d31_cx_dev2.py", True), ("x31_cx_dev.py", True), ("d3_cx_dev.py", True)):
        p = tmp_path / name
        p.write_text("def answers(q, f, c):\n    return {}\n")
        assert layout.is_engine_module(p) is engine, name
