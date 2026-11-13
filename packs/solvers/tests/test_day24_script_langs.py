#!/usr/bin/env python3
"""Permanent break-it battery for the Script Analysis language-identification coverage
(solvers/script-analysis/gdscript_csx_langs.py): Godot GDScript, C# script (.csx and csx-in-a-string),
Terraform HCL and XSLT.

  .venv/bin/python -m pytest tests/test_day24_script_langs.py   # a second, no network, no token

The label ledger is pointed at a throwaway folder, so every language name stays unsure (no seed, no accepted
spelling): the point of the module is that a language-name label is the author's vocabulary and is therefore
NEVER answered plain. The battery asserts:

  clean      a clean specimen of each covered language is identified unambiguously, and its pick is an
             unsure labels answer whose key and best option are the expected ones (never plain).
  decoy      a language's signature cribs sitting in another language's comment or string literal are a
             decoy: they do not make that language identify, and never produce a WRONG plain answer.
  ambiguous  a specimen whose live code carries two covered languages' cribs (an ambiguous polyglot) is
             identified as neither (None), and its pick is None.
  embedded   a host (.aspx/.cshtml) that compiles a C# script held in a string literal is detected
             (embedded_csx), and its `-next-language` pick is the unsure csx candidate; an ordinary C#
             string with no host marker is not mistaken for an embedded script.
  nowrong    over every specimen and every field, no answer is ever plain: everything is unsure or None.
  overrides  overrides() fills only None/unsure language ids, never a plain one, and emits only unsure.

Each check is a pytest test that prints one `pass` line with what it proved.
"""
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
TMP = Path(tempfile.mkdtemp(prefix="test_day24_script_langs_"))
os.environ["CTF_STATE_DIR"] = str(TMP / "state")
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_TESTING"] = "1"
for _n in ("CTF_FAMILY_PRIOR", "CTF_LEDGER_MASK", "CTF_PLATFORM_URL"):
    os.environ.pop(_n, None)
(TMP / "challenges" / "_ledger").mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "script-analysis"))
import labels  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "gdscript_csx_langs", REPO / "solvers" / "script-analysis" / "gdscript_csx_langs.py")
L = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L)


def is_unsure(v) -> bool:
    return isinstance(v, str) and v.startswith("??") and labels.parse(v) is not None


def is_plain(v) -> bool:
    return v is not None and not (isinstance(v, str) and v.startswith("??"))


# --------------------------------------------------------------------------- clean specimens

GD = """extends Node2D

signal spawned(where)

@export var speed := 42
onready var player = get_node("Player")

func _ready():
    var data := PackedByteArray()
    preload("res://scenes/boss.tscn")
    print("hello from gdscript")

func _process(delta):
    emit_signal("spawned", $Enemy.position)
"""

# GDScript whose body is string/const obfuscated, but the structural keywords remain -> still identified.
GD_OBF = """extends Reference

const K = "5a1f0c3e9b2d7a84"
var buf := PackedByteArray()

func _init():
    for c in K:
        buf.append(c.unicode_at(0))
    var s = char(104) + char(105)
    print(s)
"""

CSX = """#r "nuget: Newtonsoft.Json, 13.0.1"
#load "shared.csx"
using System;
using Newtonsoft.Json;

var payload = new { id = 7 };
Console.WriteLine(JsonConvert.SerializeObject(payload));
await System.Threading.Tasks.Task.Delay(1);
"""

HCL = """terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "evidence" {
  bucket = "huntress-${var.name}"
}

data "aws_caller_identity" "current" {}
"""

XSLT = """<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/catalog">
    <html><body>
      <xsl:for-each select="item">
        <p><xsl:value-of select="name"/></p>
      </xsl:for-each>
    </body></html>
  </xsl:template>
</xsl:stylesheet>
"""

CLEAN = {
    "godot_gdscript": [("gd", GD), ("gd", GD_OBF)],
    "csx": [("csx", CSX)],
    "terraform_hcl": [("tf", HCL)],
    "xslt": [("xslt", XSLT)],
}


def t_clean():
    best = {"godot_gdscript": "godot_gdscript", "csx": "csx", "terraform_hcl": "terraform_hcl", "xslt": "xslt"}
    n = 0
    for lang, specimens in CLEAN.items():
        for ext, text in specimens:
            assert L.identify(text) == lang, f"{lang}: identify returned {L.identify(text)!r}"
            v = L.language_pick(f"x.{ext}", text, "language")
            assert is_unsure(v), f"{lang}: pick not unsure: {v!r}"
            parsed = labels.parse(v)
            assert parsed.key == f"script.language/{ext}.cribs_{lang}", f"{lang}: key {parsed.key}"
            opt_names = [o[0] for o in parsed.options]
            assert opt_names[0] == best[lang], f"{lang}: best option {opt_names[0]}"
            n += 1
    return f"{n} clean specimens identified, all unsure, best option = judge-observed spelling"


# --------------------------------------------------------------------------- decoys

# A language's cribs hidden in another language's comment or string: must not identify as the hidden language.
DECOYS = [
    # GDScript signature inside HCL comments; the live code is HCL.
    ("tf", """# extends Node
# signal done
# @export var x := 1
# func _ready(): preload("res://boss.tscn")
terraform {}
resource "aws_s3_bucket" "b" "c" { bucket = var.n }
""", "terraform_hcl"),
    # csx directives inside a C-style block comment of an XSLT-less XML; live code is XSLT.
    ("xslt", """<?xml version="1.0"?>
<!-- #r "x" / #load "y" / using System; Console.WriteLine(1) / CSharpScript.RunAsync -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/"><xsl:value-of select="a"/></xsl:template>
</xsl:stylesheet>
""", "xslt"),
    # HCL block header inside a GDScript string literal; live code is GDScript.
    ("gd", '''extends Node
func _ready():
    var decoy = "resource \\"aws_s3\\" \\"x\\" { bucket = var.n }\\nterraform {}"
    signal_bus()
signal ready_signal
''', "godot_gdscript"),
    # XSLT tags inside a csx string; live code is csx.
    ("csx", '''#r "System.Xml"
using System;
var tpl = "<xsl:stylesheet xmlns:xsl=\\"http://www.w3.org/1999/XSL/Transform\\"><xsl:template/></xsl:stylesheet>";
Console.WriteLine(tpl);
''', "csx"),
]


def t_decoy():
    for ext, text, want in DECOYS:
        got = L.identify(text)
        assert got == want, f"decoy .{ext}: identify={got!r}, want {want!r}"
        # the hidden language never wins, and the pick (for the real language) is unsure or None, never plain
        v = L.language_pick(f"x.{ext}", text, "language")
        assert not is_plain(v), f"decoy .{ext}: produced a plain answer {v!r}"
    return f"{len(DECOYS)} decoys: cribs in comments/strings never identify the hidden language, 0 plain"


# --------------------------------------------------------------------------- ambiguous polyglots

AMBIG = [
    # live HCL block header AND live GDScript module keywords
    ("""extends Node
func _ready(): pass
signal s
resource "aws_s3_bucket" "b" "c" { bucket = x }
terraform {}
provider "aws" { region = var.r }
"""),
    # live csx directives AND live XSLT stylesheet
    ('''#r "x"
#load "y"
using System;
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/"/>
</xsl:stylesheet>
'''),
]


def t_ambiguous():
    for text in AMBIG:
        assert L.identify(text) is None, f"ambiguous polyglot identified as {L.identify(text)!r}: {L.present(text)}"
        v = L.language_pick("x.poly", text, "language")
        assert v is None, f"ambiguous polyglot produced a pick {v!r}"
    return f"{len(AMBIG)} ambiguous polyglots -> identify None, pick None"


# --------------------------------------------------------------------------- csx embedded in a host string

ASPX = '''<%@ Page Language="C#" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    string script = @"#r ""Newtonsoft.Json""
using System;
Console.WriteLine(""staged"");";
    CSharpScript.RunAsync(script);
}
</script>
'''

PLAIN_CS = '''using System;
class Program {
    static void Main() {
        string note = "using System; Console.WriteLine(1); #r";
        Console.WriteLine(note);
    }
}
'''


def t_embedded():
    got = L.embedded_csx(ASPX)
    assert got is not None and got[1] == "csx", f"aspx host: embedded_csx={got!r}"
    v = L.language_pick("page.aspx", ASPX, "next-language")
    assert is_unsure(v), f"aspx next-language pick not unsure: {v!r}"
    parsed = labels.parse(v)
    assert parsed.key == "script.next_language/aspx.embedded_csx", parsed.key
    assert parsed.options[0][0] == "csx", parsed.options[0]
    # an ordinary C# source with a csx-looking string but no host marker is not an embedded script
    assert L.embedded_csx(PLAIN_CS) is None, "plain C# string mistaken for embedded csx"
    return "aspx host -> embedded csx (unsure next-language); plain C# string not mistaken"


# --------------------------------------------------------------------------- never plain, over everything

def t_nowrong():
    plains = []
    everything = []
    for lang, specs in CLEAN.items():
        everything += [(ext, text) for ext, text in specs]
    everything += [(ext, text) for ext, text, _ in DECOYS]
    everything += [("poly", text) for text in AMBIG]
    everything += [("aspx", ASPX), ("cs", PLAIN_CS)]
    for ext, text in everything:
        for field in ("language", "next-language", "next-stage-language", "embedded-language"):
            v = L.language_pick(f"x.{ext}", text, field)
            if is_plain(v):
                plains.append((ext, field, v))
    assert not plains, f"plain answers emitted: {plains[:3]}"
    return f"{len(everything)} specimens x 4 language fields: 0 plain answers (all unsure or None)"


# --------------------------------------------------------------------------- overrides() contract

def t_overrides():
    member = "boss.gd"
    files = {member: GD.encode()}
    questions = [
        {"qid": "polyglot-godot-aa-language", "field": "language"},
        {"qid": "polyglot-godot-aa-role", "field": "role"},            # not a language field: untouched
        {"qid": "polyglot-godot-aa-next-language", "field": "next-language"},
    ]
    # role already plain, language already plain (a decoded plan): both must be left alone.
    answers = {"polyglot-godot-aa-role": "dropper", "polyglot-godot-aa-language": "godot_gdscript"}
    got = L.overrides(member, questions, answers, files)
    assert "polyglot-godot-aa-role" not in got, "overrides touched a non-language field"
    assert "polyglot-godot-aa-language" not in got, "overrides replaced a PLAIN language answer"
    # with no prior answer, the language id is filled with an unsure pick
    got2 = L.overrides(member, questions, {}, files)
    v = got2.get("polyglot-godot-aa-language")
    assert is_unsure(v), f"overrides did not fill an open language id with an unsure pick: {v!r}"
    assert all(not is_plain(val) for val in got2.values()), "overrides emitted a plain answer"
    # next-language has no embedded csx host here -> left None (not guessed)
    assert "polyglot-godot-aa-next-language" not in got2, "overrides guessed a next-language with no host"
    return "overrides fills only open language ids, never a plain one, never plain itself"


# The battery: each t_* check asserts and returns a one-line summary of what it proved.


def test_clean():
    print(f"pass  clean: {t_clean()}")


def test_decoy():
    print(f"pass  decoy: {t_decoy()}")


def test_ambiguous():
    print(f"pass  ambiguous: {t_ambiguous()}")


def test_embedded():
    print(f"pass  embedded: {t_embedded()}")


def test_nowrong():
    print(f"pass  nowrong: {t_nowrong()}")


def test_overrides():
    print(f"pass  overrides: {t_overrides()}")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
