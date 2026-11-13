"""B-227: the language-blind plan/descriptor reader of the Script Analysis lane (solvers/script-analysis/blind_reader.py)
and its wiring into generic.read.

Every specimen here is synthetic, built inside the test: a plan, encoded, written into a container of some
language. Nothing is executed. The plan is the Day 8 version-3 shape (all fifteen fields, stage_count equal to
the steps), so descriptor.checked accepts it whole and a cut copy is told apart.
"""
from __future__ import annotations

import base64
import contextlib
import io
import subprocess
import sys
from pathlib import Path

import pytest

import analyze
import blind_reader as br
import plan_codec

# This lane's generic.py, not solvers/binary/generic.py: in a full-suite run another test module may hold
# sys.modules["generic"] with the Binary one first (SH-05), so a bare `import generic` is order-dependent.
generic = plan_codec.own("generic")

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "solvers" / "script-analysis" / "blind_reader.py"

PLAN = ("v=3|language=zig|role=downloader|verdict=malicious|attack=T1105|adapter=http_get|host_profile=cli|"
        "obfuscation_profile=b64|stage_profile=single|next_language=none|stage_count=2|"
        "steps=fetch_url,write_file|campaign_id=CMP-4471|url=https://ex.invalid/a/b.bin|file_path=C:/t/b.bin")
OTHER = PLAN.replace("CMP-4471", "CMP-9999")
B64 = base64.b64encode(PLAN.encode()).decode()
B64_OTHER = base64.b64encode(OTHER.encode()).decode()


def pieces(s: str, n: int = 4) -> list:
    k = len(s) // n + 1
    return [s[i:i + k] for i in range(0, len(s), k)]


def listed(xs, q='"') -> str:
    return ", ".join(q + x + q for x in xs)


def chained(xs, op: str) -> str:
    return f" {op} ".join('"' + x + '"' for x in xs)


P = pieces(B64)

# ---------------------------------------------------------------------------------------------- whole containers

WHOLE = {
    "js array join": ("js", f'const parts_ab = [{listed(P)}].join("");\n'),
    "python str join": ("py", f'parts = "".join([{listed(P)}])\n'),
    "powershell -join @()": ("ps1", f'$p = -join @({listed(P)})\n'),
    "powershell (..) -join ''": ("ps1", f'$p = ({listed(P)}) -join ""\n'),
    "php implode": ("php", f'<?php $p = implode("", [{listed(P)}]); ?>\n'),
    "perl join": ("pl", f'my $p = join("", ({listed(P)}));\n'),
    "lua table.concat": ("lua", f'local p = table.concat({{{listed(P)}}})\n'),
    "ruby join": ("rb", f'p = [{listed(P)}].join\n'),
    "go strings.Join": ("go", f'p := strings.Join([]string{{{listed(P)}}}, "")\n'),
    "c# string.Join": ("csx", f'var p = string.Join("", new[] {{ {listed(P)} }});\n'),
    "kotlin joinToString": ("kts", f'val p = listOf({listed(P)}).joinToString("")\n'),
    "zig ++ chain": ("zig", f'const material_q = {chained(P, "++")};\n'),
    "zig ++ over lines": ("zig", f'const material_q = "{B64[:40]}" ++\n    "{B64[40:]}";\n'),
    "php . chain": ("php", f'<?php $m = {chained(P, ".")};\n'),
    "vb & with _ continuation": ("vbs", f'm = "{B64[:50]}" & _\n    "{B64[50:]}"\n'),
    "clojure (str ..)": ("clj", f'(def material (str {" ".join(chr(34) + x + chr(34) for x in P)}))\n'),
    "r paste0 collapse": ("r", f'm <- paste0(c({listed(P)}), collapse="")\n'),
    "shell side by side": ("sh", 'M="' + '""'.join(P) + '"\n'),
    "an unseen language, one literal": ("nim", f'let material_q = "{B64}"\n'),
}


@pytest.mark.parametrize("label", sorted(WHOLE))
def test_a_join_in_any_idiom_is_read_whole(label):
    ext, text = WHOLE[label]
    v = br.reading(text, ext)
    assert v.plan_text == PLAN, (label, v.why, v.notes)
    assert v.copies == 1


def test_the_value_is_the_pieces_in_written_order_whatever_the_join():
    # the reading is the concatenation: pieces written in another order give no plan at all
    text = f'const m = [{listed(P[1:] + P[:1])}].join("");\n'
    assert br.reading(text, "js").plan_text is None


# ---------------------------------------------------------------------------------------------- escaped hosts

HOSTS = {
    "aspx C# literal with \\\" quotes": ("aspx", '<%@ Page Language="C#" %>\n<script runat="server">\n'
                                                 'string src = "var descriptor_ab12 = \\"' + B64 + '\\";";\n'
                                                 '</script>\n'),
    "csx @-verbatim with \"\" quotes": ("csx", 'var src = @"var descriptor_ab12 = ""' + B64 + '"";";\n'),
    "JSON inside a JS string": ("js", 'const j = "{\\"descriptor\\":\\"' + B64 + '\\"}";\n'),
    # the controls of the interpolated hosts refused below: the same host with nothing interpolated is read
    "ruby host with \\\" quotes": ("rb", 'src = "var d = \\"' + B64 + '\\"; "\n'),
    "php host with \\\" quotes": ("php", '<?php $src = "var d = \\"' + B64 + '\\"; ";\n'),
}


@pytest.mark.parametrize("label", sorted(HOSTS))
def test_an_escaped_string_literal_host_is_read_inside(label):
    ext, text = HOSTS[label]
    v = br.reading(text, ext)
    assert v.plan_text == PLAN, (label, v.why)
    assert v.how.startswith("host:"), v.how


def test_a_host_literal_that_is_itself_a_piece_gives_no_whole_plan():
    text = ('string src = "var descriptor_ab12 = \\"' + B64 + '\\";";\nsrc += more();\n')
    assert br.reading(text, "aspx").plan_text is None


# ---------------------------------------------------------------------------------------------- refusals

# A value that decodes whole on its own and is then grown: only the growth says it is a piece.
MORE = base64.b64encode(b"|note=more").decode()
REFUSED = {
    "grown with +=": ("py", f'm = "{B64}"\nm += "{MORE}"\n'),
    "grown with itself": ("zig", f'var m = "{B64}";\nm = m ++ "{MORE}";\n'),
    "interpolated into another literal": ("php", f'<?php $m = "{B64}";\n$n = "pre$m";\n'),
    "an operand joined on": ("hs", f'buildPlan = "{B64}" ++ suffix\n'),
    "a call joined on": ("js", f'const m = "{B64}" + tail();\n'),
    "pieces reversed before the join": ("js", f'const m = [{listed(P)}].reverse().join("");\n'),
    "reversed()": ("py", f'm = "".join(reversed([{listed(P)}]))\n'),
    "a non-empty separator": ("py", f'm = "-".join([{listed(P)}])\n'),
    "a bare list": ("py", f'm = [{listed(P)}]\n'),
    "a line comment": ("zig", f'// const m = "{B64}";\n'),
    "a block comment": ("js", f'/*\nconst m = "{B64}";\n*/\n'),
    "a Haskell block comment": ("hs", f'{{-\nbuildPlan = "{B64}"\n-}}\n'),
    "a slice": ("py", f'm = "{B64}"[0:100]\n'),
    "a negative slice": ("py", f'm = "{B64}"[-9:]\n'),
    "set again from elsewhere (Lisp)": ("el", f'(defvar m "{B64}")\n(setq m (read-more))\n'),
    "concatenated in place (Ruby)": ("rb", f'm = "{B64}"\nm.concat("{MORE}")\n'),
    "appended in place (Swift)": ("swift", f'var m = "{B64}"\nm.append("{MORE}")\n'),
    "defined again (Lisp)": ("clj", f'(def m "{B64}")\n(def m (str m "{MORE}"))\n'),
    "joined by a Lisp str": ("clj", f'(def m "{B64}")\n(def n (str m "{MORE}"))\n'),
    "an interpolated template": ("js", 'const m = `' + B64[:50] + '${tail}' + B64[50:] + '`;\n'),
    "two whole plans": ("zig", f'const a = "{B64}";\nconst b = "{B64_OTHER}";\n'),
    "assigned twice": ("py", f'm = "{B64}"\nm = "{B64}"\n'),
    "an element written": ("js", f'const p = [{listed(P)}];\np[1] = "x";\nconst m = p.join("");\n'),
    "handed to a mutator": ("py", f'm = "{B64}"\nm2 = m.replace("A", "B")\nappend(m)\n'),
    "joined into another value": ("php", f'<?php $m = "{B64}";\n$n = $m . "tail";\n'),
    # glue BEFORE the mention: the name is the tail of another value
    "glued after other text (PHP .)": ("php", f'<?php $m = "{B64}";\n$n = "tail" . $m;\n'),
    "glued after other text (JS +)": ("js", f'const m = "{B64}";\nconst n = "x" + m;\n'),
    # ... at any distance on its line, and across a line break the way a container continues (round 2)
    "glued after other text, wide spacing (JS +)": ("js", f'const m = "{B64}";\nconst n = "x" +{" " * 24}m;\n'),
    "glued across a line break (JS +)": ("js", f'const m = "{B64}";\nconst n = "x" +\n    m;\n'),
    "glued across a line break (PHP .)": ("php", f'<?php $m = "{B64}";\n$n = "tail" .\n  $m;\n'),
    "glued across a line break (Lua ..)": ("lua", f'local m = "{B64}"\nlocal n = "x" ..\n  m\n'),
    "glued across a VB _ continuation": ("vbs", f'm = "{B64}"\nn = "x" & _\n    m\n'),
    "glued across a backslash continuation": ("py", f'm = "{B64}"\nn = "x" + \\\n    m\n'),
    "glued across a PowerShell backquote": ("ps1", f'$m = "{B64}"\n$n = "x" + `\n    $m\n'),
    "glue on the next line after it (JS +)": ("js", f'const m = "{B64}";\nconst n = m\n    + "x";\n'),
    # a host literal that interpolates has no known value: what its text seems to hold is not read
    "an interpolated host literal (Ruby #{})": ("rb", 'src = "var d = \\"' + B64 + '\\"; #{extra}"\n'),
    "an interpolated host literal (PHP $x)": ("php", '<?php $src = "var d = \\"' + B64 + '\\"; $extra";\n'),
    # in VB "" is a quote inside ONE literal: its value holds a quote, it is not two pieces side by side
    "a VB literal with a doubled quote": ("vbs", f'm = "{B64[:60]}""{B64[60:]}"\n'),
    "a name the file assigns in the container": ("py", f'sep = "-"\nm = sep.join([{listed(P)}])\n'),
    "a number in the container": ("js", f'const m = "{B64}".substr(0, 300);\n'),
    "a cut version-3 plan": ("zig", 'const m = "' + base64.b64encode(PLAN[:PLAN.index("|file_path=")].encode())
                             .decode() + '";\n'),
}


@pytest.mark.parametrize("label", sorted(REFUSED))
def test_what_may_not_be_the_whole_value_is_never_read_whole(label):
    ext, text = REFUSED[label]
    v = br.reading(text, ext)
    assert v.plan_text is None, (label, v.plan_text)


# A head that is a grammar-complete plan on its own (version 12: no field list is known for it) and whose rest
# stands where plan_codec reads one: another value of its dict, a related name, a function's return.
HEAD = "v=12|campaign_id=CMP-9|adapter=raw_tcp|role=launcher|steps=decode_blob,spawn_child|url=https://x.invalid/qqq"
assert len(HEAD) % 3 == 0
HEAD64 = base64.b64encode(HEAD.encode()).decode()
REST64 = base64.b64encode((HEAD + "|file_path=/tmp/qq").encode()).decode()[len(HEAD64):]
CONTINUED = {
    "another value of its dict": f'd = {{"a": "{HEAD64}", "b": "{REST64}"}}\n',
    "a related name": f'material_q = "{HEAD64}"\nmaterial_q_tail = "{REST64}"\n',
    "a function's return": f'm = "{HEAD64}"\ndef rest():\n    return "{REST64}"\n',
}


@pytest.mark.parametrize("label", sorted(CONTINUED))
def test_a_head_whose_rest_stands_elsewhere_is_never_whole(label):
    assert plan_codec.grammar_plan(HEAD) is not None          # the head alone IS a plan by grammar
    assert br.reading(f'm = "{HEAD64}"\n', "py").plan_text == HEAD
    assert br.reading(CONTINUED[label], "py").plan_text is None


def test_doubled_quotes_join_pieces_in_a_shell_word_but_are_one_quote_in_vb():
    text = f'm="{B64[:60]}""{B64[60:]}"\n'
    assert br.reading(text, "sh").plan_text == PLAN            # sh: two words side by side are one value
    assert br.reading(text, "vbs").plan_text is None           # vbs: one literal holding a quote
    assert br.reading(f'm = "{B64}"\n', "vbs").plan_text == PLAN


@pytest.mark.parametrize("label,ext,text", [
    ("a use on a later line", "js", f'const m = "{B64}";\nrun(m);\n'),
    ("a statement with glue ends before the use", "js", f'const m = "{B64}";\nconst k = a + b;\n\nrun(m);\n'),
    ("a VB statement ends before the use", "vbs", f'm = "{B64}"\nk = a & b\nRun m\n'),
    ("a word ending in _ is no continuation", "py", f'm = "{B64}"\nk = a + my_\nrun(m)\n'),
    ("a _ that is a name, not a VB mark", "py", f'm = "{B64}"\nk = a +_\nm.run()\n'),
    ("a backslash on the same line is no continuation", "hs",
     f'buildPlan = "{B64}"\nrun = go . \\ buildPlan -> buildPlan\n'),
])
def test_glue_before_a_mention_is_read_only_across_a_continuation(label, ext, text):
    # the controls of the line-break refusals above: glue that ends a finished statement joins nothing to the name
    assert br.reading(text, ext).plan_text == PLAN, label


# A VB-dialect block in a host file: its doubled quote is one quote inside ONE literal, as in a .vbs file.
VB_HOSTS = {
    "wsf <script language=VBScript>": ("wsf", '<job><script language="VBScript">\n{m}\n</script></job>\n'),
    "hta <script type=text/vbscript>": ("hta", '<html><script type="text/vbscript">\n{m}\n</script></html>\n'),
    "asp without a directive (VBScript)": ("asp", '<%\n{m}\n%>\n'),
    "asp <%@ Language=VBScript %>": ("asp", '<%@ Language=VBScript %>\n<%\n{m}\n%>\n'),
    "aspx Language=VB, runat=server": ("aspx", '<%@ Page Language="VB" %>\n<script runat="server">\n{m}\n'
                                               '</script>\n'),
}


@pytest.mark.parametrize("label", sorted(VB_HOSTS))
def test_a_vb_block_of_a_host_file_reads_with_the_vb_quote_rules(label):
    ext, frame = VB_HOSTS[label]
    doubled = frame.replace("{m}", f'm = "{B64[:60]}""{B64[60:]}"')
    assert br.reading(doubled, ext).plan_text is None, label          # one literal holding a quote: no plan
    assert br.reading(frame.replace("{m}", f'm = "{B64}"'), ext).plan_text == PLAN, label   # control


def test_a_host_block_in_another_language_keeps_the_c_quote_rules():
    js = f'<job><script language="JScript">\nvar m = "{B64[:60]}""{B64[60:]}";\n</script></job>\n'
    assert br.vb_spans(js, "wsf") == []
    assert br.reading(js, "wsf").plan_text == PLAN                # side by side, as the C rules read it
    asp_js = f'<%@ Language=JScript %>\n<%\nvar m = "{B64[:60]}""{B64[60:]}";\n%>\n'
    assert br.vb_spans(asp_js, "asp") == []
    # the markers are read only in a host file: a .js file that quotes one stays C
    assert br.vb_spans('<script language="VBScript">\nx\n</script>', "js") == []


def test_a_mixed_host_file_reads_each_block_in_its_own_dialect():
    text = ('<job>\n<script language="JScript">\nvar a = "p""q";\n</script>\n'
            '<script language="VBScript">\nb = "r""s"\n</script>\n</job>\n')
    vals = [x.value for x in br.scan_dialects(text, br.vb_spans(text, "wsf"))]
    assert "p" in vals and "q" in vals                       # JScript: two literals
    assert 'r"s' in vals and "r" not in vals                 # VBScript: one literal holding a quote


def test_a_vb_literal_ends_on_its_line():
    # an unclosed quote in a VB comment must not pair with the next line's opening quote
    text = f"' note: \"unclosed\nm = \"{B64}\"\n"
    assert [x.value for x in br.scan_literals(text, vb=True)] == [B64]
    assert br.reading(text, "vbs").plan_text == PLAN


def test_vb_literals_know_only_the_double_quote():
    text = 'a = "say ""hi""" \' it\'s a comment\nb = "C:\\t\\n"\nc = "no close\n'
    vals = [x.value for x in br.scan_literals(text, vb=True)]
    assert vals == ['say "hi"', "C:\\t\\n"]                   # "" is a quote; a backslash is itself; ' quotes nothing
    assert [x.value for x in br.scan_literals(text)][:1] == ["say "]   # the C-family reading, for contrast


def test_one_value_that_decodes_to_two_plans_is_refused(monkeypatch):
    # a value the decoder reads two ways, the second the head of the first: the head alone is not complete, so only
    # the value's own refusal (two plans at once, both weighed as whole) keeps the longer reading from being taken
    cut = PLAN[:PLAN.index("|file_path=")]
    assert plan_codec.head_of(cut, PLAN)
    desc = plan_codec.optional("descriptor")
    real = desc.decode

    def two_ways(tag, payload):
        if payload == B64:
            return [(PLAN, "descriptor:b64|identity"), (cut, "descriptor:other|identity")]
        return real(tag, payload)

    text = f'const m = "{B64}";\n'
    assert br.reading(text, "js").plan_text == PLAN            # read one way, it is the plan
    monkeypatch.setattr(desc, "decode", two_ways)
    v = br.reading(text, "js")
    assert v.plan_text is None and "different plans" in v.why


def test_a_keyed_value_alone_in_its_dict_is_whole():
    assert br.reading(f'd = {{"descriptor": "{B64}", "n": "x"}}\n', "py").plan_text == PLAN


def test_a_witness_with_another_plan_refuses_the_file():
    # one whole container and a tagged comment that gives a different plan: two plans, none taken
    text = f'// HUNTRESS_ANALYSIS_V1:B64-{B64_OTHER}\nconst m = {chained(P, "++")};\n'
    v = br.reading(text, "zig")
    assert v.plan_text is None
    assert "another plan" in (v.why or "")


def test_a_wrapped_witness_that_gives_the_head_of_the_plan_agrees():
    head = base64.b64encode(PLAN[:120].encode()).decode()
    text = f'// HUNTRESS_ANALYSIS_V1:B64-{head[:(len(head) // 4) * 4]}\nconst m = {chained(P, "++")};\n'
    v = br.reading(text, "zig")
    assert v.plan_text == PLAN, v.why


def test_a_plan_in_any_field_order_and_any_version_is_read():
    plan = "v=12|campaign_id=CMP-9|adapter=raw_tcp|role=launcher|url=https://x.invalid/q|steps=decode_blob,spawn_child|file_path=/tmp/q"
    text = 'const m = ' + chained(pieces(base64.b64encode(plan.encode()).decode()), "++") + ';\n'
    assert br.reading(text, "zig").plan_text == plan


def test_a_tagged_value_and_a_layered_value_are_decoded_by_their_tags():
    hb64 = base64.b64encode(PLAN.encode()).hex()
    assert br.reading(f'const m = {chained(pieces("HB64-" + hb64), "++")};\n', "zig").plan_text == PLAN
    lyr = "LYR-b64_hex-" + hb64
    assert br.reading(f'const m = {chained(pieces(lyr), "++")};\n', "zig").plan_text == PLAN


def test_the_decode_budget_bounds_the_work():
    junk = "".join(f'const j{i} = "{base64.b64encode(bytes([65 + i % 26, 97 + i // 26]) * 20).decode()}";\n'
                   for i in range(br.MAX_DECODES + 4))
    reader = br._Reader(junk + f'const m = "{B64}";\n', "zig")
    found = reader.copies()
    assert reader.budget["decodes"] == br.MAX_DECODES
    assert found == []                           # the plan stood past the budget: it is not read
    # and the file is refused as a whole: an unread value could have been a second plan (fail closed)
    v = br.reading(f'const m = "{B64}";\n' + junk, "zig")
    assert v.plan_text is None and "not all could be weighed" in v.why
    assert br.reading(f'const m = "{B64}";\n' + junk[:junk.index("const j8 ")], "zig").plan_text == PLAN


def test_many_keyed_entries_are_weighed_in_one_pass():
    # 3000 entries of one dict, each the same material: every one has siblings, none is whole. The sibling check
    # is one pass over the text (a scan per entry took 24 s on this shape); the bound here is generous for load.
    import time
    body = "\n".join(f'"k{i}": "{B64}",' for i in range(3000))
    t0 = time.monotonic()
    v = br.reading("d = {" + body + "}\n", "py")
    assert time.monotonic() - t0 < 10
    assert v.plan_text is None


# ---------------------------------------------------------------------------------------------- literals

def test_literal_scanner_undoes_escapes_and_knows_quote_styles():
    text = ('a = "x\\"y\\x41\\u0042\\u{43}\\101\\n"\n'
            "b = 'it''s'\n"
            'c = @"say ""hi"""\n'
            'd = """tri"ple"""\n'
            'e = r"raw\\n"\n'
            'f = "$name and ${x}"\n'
            'g = "no close\n')
    lits = {text[x.start:x.end][:6]: x for x in br.scan_literals(text)}
    vals = [x.value for x in br.scan_literals(text)]
    assert 'x"yABCA\n' in vals
    assert 'say "hi"' in vals
    assert 'tri"ple' in vals
    assert "raw\\n" in vals
    interp = [x for x in br.scan_literals(text) if x.interp]
    assert [x.value for x in interp] == ["$name and ${x}"]
    assert not any(x.value.startswith("no close") for x in lits.values())


# ---------------------------------------------------------------------------------------------- generic.read wiring

def read(name, text):
    with contextlib.redirect_stderr(io.StringIO()):
        return generic.read(name, text.encode())


def test_generic_read_takes_the_whole_plan_where_plan_codec_read_a_piece():
    text = f'my $p = join("", ({listed(P)}));\n'
    got = read("drop.pl", text)
    assert got["plan"].get("file_path") == "C:/t/b.bin"
    assert got["source"] == "blind_reader" and got["cut"] is False


def test_generic_read_leaves_the_cut_plan_when_the_switch_is_off(monkeypatch):
    monkeypatch.setattr(generic, "BLIND_READER", False)
    got = read("drop.pl", f'my $p = join("", ({listed(P)}));\n')
    assert got["cut"] is True and "file_path" not in got["plan"]


def test_a_split_file_in_an_unknown_join_is_settled_only_by_two_agreeing_copies():
    tagged = chained(pieces("B64-" + B64), "++")
    bare = chained(pieces(B64, 5), "++")
    two = f'// HUNTRESS_ANALYSIS_V1:SPLIT\nconst tagged_ab = {tagged};\nconst enc_ab = {bare};\n'
    got = read("story.zig", two)
    assert got["plan_text"] == PLAN and got["source"] == "blind_reader"
    one = f'// HUNTRESS_ANALYSIS_V1:SPLIT\nconst tagged_ab = {tagged};\n'
    got = read("story.zig", one)
    assert got["plan"] == {} and got["ambiguous"] is True


def test_another_refusal_is_never_settled_by_the_blind_reader():
    # plan_codec's two-plan refusal stands: by_blind is not asked of an ambiguous file without SPLIT_UNREAD
    info = {"text": f'const m = {chained(P, "++")};\n', "ext": ".zig", "plan": {}, "ambiguous": True, "notes": []}
    assert generic.by_blind(info) is False and info["plan"] == {}


def test_a_blind_plan_that_differs_from_the_fields_already_read_is_no_plan():
    cut = dict(list(plan_codec.flatten(OTHER).items())[:-1])
    info = {"text": f'const m = {chained(P, "++")};\n', "ext": ".zig", "plan": cut, "cut": True, "notes": []}
    assert generic.by_blind(info) is False
    assert info["plan"] == {} and info["ambiguous"] is True


def _without(monkeypatch, name):
    real = plan_codec.optional
    monkeypatch.setattr(plan_codec, "optional", lambda n: None if n == name else real(n))


def _open_info():
    return {"text": f'const m = {chained(P, "++")};\n', "ext": ".zig", "plan": {}, "notes": []}


def test_a_missing_blind_reader_fails_loudly(monkeypatch):
    monkeypatch.delenv("CTF_HIDE", raising=False)
    _without(monkeypatch, "blind_reader")
    with pytest.raises(RuntimeError, match="blind_reader.py"):
        generic.by_blind(_open_info())


def test_a_missing_descriptor_fails_loudly_through_by_blind(monkeypatch):
    monkeypatch.delenv("CTF_HIDE", raising=False)
    _without(monkeypatch, "descriptor")
    with pytest.raises(br.MissingModule, match="descriptor.py did not load"):
        generic.by_blind(_open_info())


@pytest.mark.parametrize("hidden", ["blind_reader", "descriptor"])
def test_a_module_hidden_on_purpose_is_a_note(monkeypatch, hidden):
    # the CTF_HIDE rehearsal knob (plan_codec.hidden, with CTF_TESTING=1) makes the module look absent on purpose
    monkeypatch.setenv("CTF_TESTING", "1")
    monkeypatch.setenv("CTF_HIDE", hidden)
    info = _open_info()
    assert generic.by_blind(info) is False
    assert info["plan"] == {} and any("CTF_HIDE" in n for n in info["notes"])


def test_a_one_copy_plan_is_lifted_by_a_whole_blind_reading():
    # a plan read whole from one copy only (one_copy: its last field is unsure) is settled by a whole container
    info = {"text": f'const m = {chained(P, "++")};\n', "ext": ".zig", "plan": plan_codec.flatten(PLAN),
            "one_copy": ("file_path", "C:/t/b.bin"), "one_copy_wrapped": False, "notes": []}
    assert generic.by_blind(info) is True
    assert "one_copy" not in info and "one_copy_wrapped" not in info
    assert info["source"] == "blind_reader" and info["plan"]["file_path"] == "C:/t/b.bin"


def test_a_settled_plan_is_not_read_again():
    # the control: a plan neither cut nor one-copy is closed, by_blind leaves it as it is
    info = {"text": f'const m = {chained(P, "++")};\n', "ext": ".zig", "plan": plan_codec.flatten(PLAN),
            "source": "descriptor", "notes": []}
    assert generic.by_blind(info) is False and info["source"] == "descriptor"


def test_a_blind_plan_that_agrees_with_the_cut_fields_completes_them():
    cut = dict(list(plan_codec.flatten(PLAN).items())[:-1])
    info = {"text": f'const m = {chained(P, "++")};\n', "ext": ".zig", "plan": cut, "cut": True, "notes": []}
    assert generic.by_blind(info) is True
    assert info["plan"]["file_path"] == "C:/t/b.bin" and info["cut"] is False


# ---------------------------------------------------------------------------------------------- the unseen-language drill

def drill_questions(member: str, stem: str) -> list:
    asked = {"campaign": "Recover the exact synthetic campaign identifier.",
             "adapter": "Recover the exact adapter named by the reconstructed plan.",
             "url": "Recover the exact url indicator.",
             "file-path": "Recover the exact file_path indicator."}
    return [{"id": f"{stem}-{f}", "qid": f"{stem}-{f}", "answer_id": f"{stem}-{f}", "member": member,
             "artifact": f"evidence.zip -> {member}", "question": t} for f, t in asked.items()]


@pytest.mark.parametrize("member,stem,text", [
    ("relay.zig", "zig-resource-relay-loader", f'const material_q = {chained(P, "++")};\n'),
    ("story.gleam", "gleam-two-word-name-stage", f'pub const material = {chained(P, "<>")}\n'),
    ("page.aspx", "aspx-managed-bridge", HOSTS["aspx C# literal with \\\" quotes"][1]),
])
def test_a_fifth_language_answers_every_plan_field_including_the_last(member, stem, text):
    """The drill: a language no module was written for, with a multi-word specimen name in its ids (the field is
    read from the end of the id), answered from the plan at second zero, the last field included."""
    with contextlib.redirect_stderr(io.StringIO()):
        got = analyze.solve_set(drill_questions(member, stem), {member: text.encode()}, {})
    assert got == {f"{stem}-campaign": "CMP-4471", f"{stem}-adapter": "http_get",
                   f"{stem}-url": "https://ex.invalid/a/b.bin", f"{stem}-file-path": "C:/t/b.bin"}


# ---------------------------------------------------------------------------------------------- command line

def test_cli_prints_the_plan_and_names_what_it_cannot_read(tmp_path):
    good = tmp_path / "relay.zig"
    good.write_text(f'const material_q = {chained(P, "++")};\n')
    bad = tmp_path / "decoy.zig"
    bad.write_text(f'const a = "{B64}";\nconst b = "{B64_OTHER}";\n')
    r = subprocess.run([sys.executable, "-I", str(SCRIPT), str(good), str(bad), str(tmp_path / "missing.zig")],
                       capture_output=True, text=True, timeout=120, cwd=tmp_path)
    assert r.returncode == 1                     # the missing file
    lines = r.stdout.splitlines()
    assert lines[0].endswith(PLAN) and "1 copy" in lines[0]
    assert "no whole plan (2 whole containers give different plans)" in lines[1]
    assert "cannot be read" in r.stderr
    r = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert r.returncode == 2 and "usage" in r.stderr
