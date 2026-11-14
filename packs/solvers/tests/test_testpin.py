"""B-258: the test-pin codemod (ctf/testpin.py) and `ctf testpin` (ctf/cli/testpin.py).

Each test file here is a synthetic source string; the expected rewrite is spelled out literally.
"""
from __future__ import annotations

import ast
import json

import pytest

import ctf.cli as cli
from ctf import expectations as X
from ctf import testpin as T

SRC = '''\
import pytest

EXPECTED = {
    "d31_analysis_crc": "0x00001111",
    "d31_analysis_count": 3,
    "d31_analysis_kind": "decoy",   # a comment that stays
    "untouched": "same",
}


def test_crc(out):
    assert out["d31_analysis_crc"] == "0x00001111"
    assert 0x10 == out.get("d31_analysis_size")
    assert out["d31_analysis_list"] == (1, 2)
    assert out["d31_analysis_expr"] == compute()
    value = 5  # pin: d31_analysis_marked
'''

NEW = {"d31_analysis_crc": "0xdeadbeef", "d31_analysis_count": 4, "d31_analysis_kind": "decoy",
       "d31_analysis_size": 0x2A, "d31_analysis_list": [3, 4, 5], "d31_analysis_expr": "x",
       "d31_analysis_marked": 6, "not_in_file": 1}

WANT = '''\
import pytest

EXPECTED = {
    "d31_analysis_crc": "0xdeadbeef",
    "d31_analysis_count": 4,
    "d31_analysis_kind": "decoy",   # a comment that stays
    "untouched": "same",
}


def test_crc(out):
    assert out["d31_analysis_crc"] == "0xdeadbeef"
    assert 0x2a == out.get("d31_analysis_size")
    assert out["d31_analysis_list"] == (3, 4, 5)
    assert out["d31_analysis_expr"] == compute()
    value = 6  # pin: d31_analysis_marked
'''


def test_rewrite_replaces_only_the_pinned_literals():
    new, plan = T.rewrite(SRC, NEW)
    assert new == WANT
    assert sorted(e.key for e in plan.edits) == ["d31_analysis_count", "d31_analysis_crc", "d31_analysis_crc",
                                                 "d31_analysis_list", "d31_analysis_marked", "d31_analysis_size"]
    assert plan.unchanged == ["d31_analysis_kind"]
    assert plan.skipped == [("d31_analysis_expr", 15, "the pinned value is not a literal")]


def test_a_dict_not_named_as_expectations_is_not_a_pin():
    src = 'CONFIG = {"k": 1}\nEXPECT_K = {"k": 1}\n'
    new, plan = T.rewrite(src, {"k": 2})
    assert new == 'CONFIG = {"k": 1}\nEXPECT_K = {"k": 2}\n'
    new2, _ = T.rewrite(src, {"k": 2}, names=r"^CONFIG$")
    assert new2 == 'CONFIG = {"k": 2}\nEXPECT_K = {"k": 1}\n'


def test_nested_case_dicts_take_the_case_path_first():
    src = 'GOLDEN = {\n    "base": {"q": "a"},\n    "mastery": {"q": "b"},\n}\n'
    new, plan = T.rewrite(src, {"base/q": "A2", "mastery/q": "B2"})
    assert new == 'GOLDEN = {\n    "base": {"q": "A2"},\n    "mastery": {"q": "B2"},\n}\n'
    # a bare key reaches every nested entry when no path key is given
    new, _ = T.rewrite(src, {"q": "z"})
    assert new.count('"z"') == 2
    # the path key wins over the bare key; the bare key still reaches the entry with no path key
    new, _ = T.rewrite(src, {"q": "z", "base/q": "v"})
    assert new == 'GOLDEN = {\n    "base": {"q": "v"},\n    "mastery": {"q": "z"},\n}\n'
    # the outer dict and its entries are never both rewritten
    new, plan = T.rewrite(src, {"base": {"q": "w"}, "base/q": "v"})
    assert '"base": {"q": "v"}' in new
    assert any(why.startswith("a dict whose entries") for _, _, why in plan.skipped)


GOLDEN_SRC = ('GOLDEN = {\n    "base": {"q": "a"},\n    "mastery": {"q": "b"},\n}\n\n'
              'def test_q(out):\n    assert out["q"] == "a"\n')
TWO_CASES = {"schema": 1, "target": "", "cases": {"base": {"output": {"q": "A2"}},
                                                   "mastery": {"output": {"q": "B2"}}}}


def test_case_pins_never_cross_into_another_case():
    # cases disagree on q: no raise, each case entry takes its own value, the bare pin is skipped
    new, plan = T.rewrite(GOLDEN_SRC, X.pins(TWO_CASES))
    assert new == GOLDEN_SRC.replace('"a"}', '"A2"}').replace('"b"}', '"B2"}')
    assert plan.skipped == [("q", 7, "cases disagree on this key: pick one (--case) or pin the case/key form")]
    # --case base: base's value reaches base's entry and the bare pin, never mastery's entry
    new, plan = T.rewrite(GOLDEN_SRC, X.pins(TWO_CASES, case="base"))
    assert new == GOLDEN_SRC.replace('"a"', '"A2"')
    assert '"mastery": {"q": "b"}' in new and plan.skipped == []
    # the same with plain dicts and explicit case ids
    new, _ = T.rewrite(GOLDEN_SRC, {"q": "A2", "base/q": "A2"}, cases={"base", "mastery"})
    assert '"mastery": {"q": "b"}' in new and '"base": {"q": "A2"}' in new
    # a nested dict whose prefix is not a case id still takes the bare key
    new, _ = T.rewrite('GOLDEN = {"group": {"q": "a"}}\n', {"q": "z"}, cases={"base"})
    assert new == 'GOLDEN = {"group": {"q": "z"}}\n'
    # deeper nesting under a case id is guarded too
    deep = 'GOLDEN = {"mastery": {"sub": {"q": "a"}}}\n'
    assert T.rewrite(deep, {"q": "z"}, cases={"mastery"})[0] == deep
    assert T.rewrite(deep, {"q": "z"}, cases={"mastery/sub"})[0] == deep


def test_an_ambiguous_key_under_a_non_case_dict_is_skipped_not_guessed():
    src = 'GOLDEN = {"group": {"q": "a"}}\n'
    new, plan = T.rewrite(src, {"base/q": 1, "mastery/q": 2}, cases={"base", "mastery"}, ambiguous={"q"})
    assert new == src
    assert plan.skipped == [("q", 1, "cases disagree on this key: pick one (--case) or pin the case/key form")]


def test_read_back_ignores_pins_that_were_already_right():
    # base already holds its path value; mastery is rewritten from the bare key. The read-back check
    # must not mistake base's entry (which the bare key alone would change) for a failed edit.
    src = 'GOLDEN = {\n    "base": {"q": "v"},\n    "mastery": {"q": "b"},\n}\n'
    new, plan = T.rewrite(src, {"base/q": "v", "q": "z"})
    assert new == 'GOLDEN = {\n    "base": {"q": "v"},\n    "mastery": {"q": "z"},\n}\n'
    assert plan.unchanged == ["base/q"]
    # an outer dict skipped as overlapping is no read-back failure either
    new, plan = T.rewrite(src, {"base": {"q": "w"}, "base/q": "w"})
    assert '"base": {"q": "w"}' in new


def test_render_keeps_the_literal_style():
    def one(src_value, new_value):
        node = ast.parse(src_value, mode="eval").body
        return T.render(new_value, node, src_value)
    assert one("'a'", "b") == "'b'"
    assert one('"a"', "b") == '"b"'
    assert one('"a"', 'say "hi"') == "'say \"hi\"'"
    assert one('"a"', "it's") == '"it\'s"'
    assert one("0x00ff", 0x12) == "0x0012"
    assert one("0xFF", 0xABC) == "0xABC"
    assert one("255", 0x12) == "18"
    assert one("(1,)", [7]) == "(7,)"
    assert one("[1]", [7, 8]) == "[7, 8]"
    assert one("None", True) == "True"
    assert one("1", None) == "None"
    assert one("b'x'", b"\x00y") == "b'\\x00y'"
    assert one('r"a"', "b") == '"b"' and one("r'a'", "b") == "'b'"        # a prefix keeps its quote
    assert one("{1}", [7, 8]) == "{7, 8}"                                   # a set stays a set
    assert one("{1}", []) == "[]"                                           # `{}` would be a dict


def test_unicode_before_a_pin_keeps_offsets_right():
    src = 'EXPECTED = {"ünï": "ä", "k": "old"}\n'
    new, _ = T.rewrite(src, {"k": "néw"})
    assert new == 'EXPECTED = {"ünï": "ä", "k": "néw"}\n'


def test_bool_and_int_are_different_values():
    new, plan = T.rewrite('EXPECTED = {"k": 1}\n', {"k": True})
    assert new == 'EXPECTED = {"k": True}\n'
    _, plan = T.rewrite('EXPECTED = {"k": 1}\n', {"k": 1.0})
    assert plan.unchanged == ["k"] and not plan.edits


def test_a_pin_comment_on_a_comparison_names_its_key():
    src = ("def test_f(x):\n"
           "    assert f(x) == 5  # pin: k\n"
           "    assert 'old' == g(x)  # pin: s\n"
           "    assert out['a'] == 1  # pin: b\n"
           "    assert h(x) == other(x)  # pin: e\n")
    new, plan = T.rewrite(src, {"k": 6, "s": "new", "a": 10, "b": 2, "e": 0})
    assert new == ("def test_f(x):\n"
                   "    assert f(x) == 6  # pin: k\n"
                   "    assert 'new' == g(x)  # pin: s\n"
                   "    assert out['a'] == 2  # pin: b\n"            # the comment wins over the subscript key
                   "    assert h(x) == other(x)  # pin: e\n")
    assert plan.skipped == [("e", 5, "the pinned value is not a literal")]


def test_a_multi_line_literal_is_replaced_whole():
    src = 'EXPECTED = {\n    "k": [\n        1,\n        2,\n    ],\n    "z": 0,\n}\n'
    new, _ = T.rewrite(src, {"k": [3]})
    assert new == 'EXPECTED = {\n    "k": [3],\n    "z": 0,\n}\n'


def test_a_rewrite_that_does_not_read_back_is_refused(tmp_path, monkeypatch):
    f = tmp_path / "test_rb.py"
    f.write_text('EXPECTED = {"k": 1}\n')
    monkeypatch.setattr(T, "render", lambda value, node, src: "999")        # a renderer that writes the wrong value
    with pytest.raises(T.TestPinError, match="pins for k do not read back as their new value; nothing written"):
        T.rewrite_file(f, {"k": 2}, write=True)
    assert f.read_text() == 'EXPECTED = {"k": 1}\n'
    monkeypatch.setattr(T, "render", lambda value, node, src: "(")          # one that breaks the file
    with pytest.raises(T.TestPinError, match="does not parse"):
        T.rewrite_file(f, {"k": 2}, write=True)
    assert f.read_text() == 'EXPECTED = {"k": 1}\n'


def test_not_python_is_an_error():
    with pytest.raises(T.TestPinError, match="not Python"):
        T.rewrite("def (:\n", {"k": 1})


def test_rewrite_file_is_a_dry_run_unless_write(tmp_path):
    f = tmp_path / "test_x.py"
    f.write_text(SRC)
    text, plan = T.rewrite_file(f, NEW)
    assert f.read_text() == SRC
    assert text.startswith(f"--- a/{f}\n+++ b/{f}\n")
    assert '\n-    "d31_analysis_count": 3,\n' in text and '\n+    "d31_analysis_count": 4,\n' in text
    assert '\n-    "untouched"' not in text
    T.rewrite_file(f, NEW, write=True)
    assert f.read_text() == WANT
    text, plan = T.rewrite_file(f, NEW, write=True)
    assert text == "" and not plan.edits


# ------------------------------------------------------------------------------------------------- CLI

def test_cli_dry_run_then_write_from_an_expectations_file(tmp_path, capsys):
    f = tmp_path / "test_y.py"
    f.write_text(SRC)
    doc = {"schema": 1, "target": "", "cases": {"base": {"output": {"d31_analysis_crc": "0xdeadbeef",
                                                                   "d31_analysis_count": 4}}}}
    X.write(tmp_path / "exp.json", doc)
    rc = cli.main(["testpin", "--outputs", str(tmp_path / "exp.json"), str(f)])
    out, err = capsys.readouterr()
    assert rc == 0 and f.read_text() == SRC
    assert '+    assert out["d31_analysis_crc"] == "0xdeadbeef"' in out
    assert "would rewrite 3, already pinned 0, skipped 0" in err
    assert cli.main(["testpin", "--check", "--outputs", str(tmp_path / "exp.json"), str(f)]) == 1
    capsys.readouterr()
    rc = cli.main(["testpin", "--write", "--outputs", str(tmp_path / "exp.json"), "--set",
                   "d31_analysis_size=42", str(f)])
    assert rc == 0
    text = f.read_text()
    assert '"d31_analysis_count": 4,' in text and "assert 0x2a == out.get" in text
    assert cli.main(["testpin", "--check", "--outputs", str(tmp_path / "exp.json"), str(f)]) == 0


def test_cli_strict_fails_on_a_skipped_pin_and_errors_are_named(tmp_path, capsys):
    f = tmp_path / "test_z.py"
    f.write_text(SRC)
    (tmp_path / "plain.json").write_text(json.dumps({"d31_analysis_expr": "x"}))
    assert cli.main(["testpin", "--outputs", str(tmp_path / "plain.json"), str(f)]) == 0
    assert cli.main(["testpin", "--strict", "--outputs", str(tmp_path / "plain.json"), str(f)]) == 1
    err = capsys.readouterr().err
    assert "skipped d31_analysis_expr at line 15: the pinned value is not a literal" in err
    assert cli.main(["testpin", str(f)]) == 2
    assert "nothing to pin" in capsys.readouterr().err
    assert cli.main(["testpin", "--outputs", str(tmp_path / "none.json"), str(f)]) == 2
    assert "none.json" in capsys.readouterr().err
    assert cli.main(["testpin", "--set", "k=1", str(tmp_path / "missing.py")]) == 2
    assert "no file" in capsys.readouterr().err
    two = {"schema": 1, "target": "", "cases": {"a": {"output": {"k": 1}}, "b": {"output": {"k": 2}}}}
    X.write(tmp_path / "two.json", two)
    assert cli.main(["testpin", "--outputs", str(tmp_path / "two.json"), str(f)]) == 0
    assert "cases disagree on k: their bare keys are left out" in capsys.readouterr().err
    assert cli.main(["testpin", "--outputs", str(tmp_path / "two.json"), "--case", "b", str(f)]) == 0
    assert "cases disagree" not in capsys.readouterr().err


def test_cli_case_writes_only_its_own_entries(tmp_path, capsys):
    f = tmp_path / "test_g.py"
    f.write_text(GOLDEN_SRC)
    X.write(tmp_path / "two.json", TWO_CASES)
    assert cli.main(["testpin", "--write", "--outputs", str(tmp_path / "two.json"), "--case", "base", str(f)]) == 0
    assert f.read_text() == GOLDEN_SRC.replace('"a"', '"A2"')
    f.write_text(GOLDEN_SRC)
    # no --case: each case's entry takes its own value; the bare pin is skipped, so --strict fails
    assert cli.main(["testpin", "--write", "--strict", "--outputs", str(tmp_path / "two.json"), str(f)]) == 1
    assert f.read_text() == GOLDEN_SRC.replace('"a"}', '"A2"}').replace('"b"}', '"B2"}')
    assert "skipped q at line 7: cases disagree on this key" in capsys.readouterr().err
    # --set on the ambiguous key is the caller's pick: the bare pin takes it, no skip
    f.write_text(GOLDEN_SRC)
    assert cli.main(["testpin", "--write", "--strict", "--outputs", str(tmp_path / "two.json"),
                     "--set", "q=C3", str(f)]) == 0
    assert 'assert out["q"] == "C3"' in f.read_text()
    assert "cases disagree" not in capsys.readouterr().err


def test_set_takes_json_or_a_bare_string(tmp_path, capsys):
    f = tmp_path / "test_s.py"
    f.write_text('EXPECTED = {"a": 1, "b": "x", "c": None}\n')
    assert cli.main(["testpin", "--write", "--set", "a=[1, 2]", "--set", "b=word", "--set", "c=null",
                     str(f)]) == 0
    assert f.read_text() == 'EXPECTED = {"a": [1, 2], "b": "word", "c": None}\n'
    assert cli.main(["testpin", "--set", "novalue", str(f)]) == 2
