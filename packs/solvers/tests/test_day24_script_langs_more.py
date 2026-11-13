#!/usr/bin/env python3
"""Day 24 build night, script-analysis T5: solvers/script-analysis/lang_names_more.py (language-name cribs, part 2).
Every language identifies from a clean specimen (unsure pick only, one key per language), signatures hidden in a
comment, a string or another format's host are NOT read, ambiguous mixes give None, nothing is ever plain.
  .venv/bin/python -m pytest tests/test_day24_script_langs_more.py"""
import os, sys, tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SA = REPO / "solvers" / "script-analysis"
sys.dont_write_bytecode = True
TMP = Path(tempfile.mkdtemp(prefix="test_day24_langs_more_"))
os.environ["CTF_STATE_DIR"] = str(TMP / "state")
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_TESTING"] = "1"
(TMP / "challenges" / "_ledger").mkdir(parents=True, exist_ok=True)
sys.path[:0] = [str(REPO / "solvers" / "common"), str(SA)]
import labels  # noqa: E402
import lang_names_more as M  # noqa: E402
import gdscript_csx_langs as OLD  # noqa: E402


S = {
    "zig": 'const std = @import("std");\npub fn main() !void {\n    comptime var i = 0;\n    std.debug.print("x", .{});\n}\n',
    "nim": 'import os, strutils\nproc run(x: int): int =\n  discard x\n  result = x\nwhen isMainModule:\n  echo run(1)\n',
    "crystal": 'require "http/client"\ndef fetch(url : String, n : Int32)\n  puts url.as(String)\nend\nmacro m\nend\n',
    "vlang": 'module main\nimport os\nfn main() {\n\tmut x := 1\n\tprintln(x)\n}\n',
    "haxe": 'import haxe.Http;\nclass Main {\n  static function main() {\n    trace("x");\n  }\n}\n',
    "odin": 'package main\nimport "core:fmt"\nmain :: proc() {\n\tfmt.println("x")\n\tdefer fmt.println("y")\n}\n',
    "dart": "import 'dart:io';\nvoid main() async {\n  final r = await Process.run('id', []);\n  Future<int> f() async => 1;\n}\n",
    "kotlin": 'package a.b\nfun main(args: Array<String>) {\n    val x = 1\n    data class P(val a: Int)\n}\n',
    "swift": 'import Foundation\nfunc run(_ a: String) -> Int {\n    guard let x = Int(a) else { return 0 }\n    return x\n}\n',
    "scala": 'import scala.io.Source\nobject Main extends App {\n  case class P(a: Int)\n  val x = 1\n}\n',
    "ballerina": 'import ballerina/io;\npublic function main() {\n    io:println("x");\n}\nfunction f(int a) returns int {\n    return a;\n}\n',
    "bicep": "param name string\nresource st 'Microsoft.Storage/storageAccounts@2021-01-01' = {\n  name: name\n}\noutput id string = st.id\n",
    "racket": '#lang racket\n(require net/url)\n(provide f)\n(define (f x) (displayln x))\n',
    "clojure": '(ns app.core\n  (:require [clojure.string :as s]))\n(defn run [x]\n  (println x))\n',
    "tcl": 'package require http\nproc run {x} {\n  puts $x\n  set y [expr {$x + 1}]\n}\n',
    "r_lang": 'library(httr)\nrun <- function(x) {\n  df <- data.frame(a = x)\n  cat(x)\n}\n',
    "julia": 'using Printf, Dates\nfunction run(x::Int64)\n    println(x)\nend\n',
    "ocaml": 'open Printf\nlet run x = print_endline x\nlet () = run "a";;\n',
    "fsharp": 'open System\n[<EntryPoint>]\nlet main argv =\n    printfn "x"\n    0\n',
    "erlang": '-module(app).\n-export([run/1]).\nrun(X) ->\n    io:format("~p", [X]).\n',
    "elixir": 'defmodule App do\n  def run(x) do\n    IO.puts(x)\n  end\nend\n',
    "haskell": 'module Main where\nimport Data.List\nmain :: IO ()\nmain = putStrLn "x"\n',
    "cobol": '       IDENTIFICATION DIVISION.\n       PROGRAM-ID. HELLO.\n       PROCEDURE DIVISION.\n           STOP RUN.\n',
    "vba": 'Attribute VB_Name = "Module1"\nOption Explicit\nSub Auto_Open()\n  Dim s As String\n  CreateObject("WScript.Shell")\nEnd Sub\n',
    "jxa": 'ObjC.import("Foundation");\nconst app = Application.currentApplication();\napp.includeStandardAdditions = true;\napp.doShellScript("id");\n',
    "starlark": 'load("@rules//:defs.bzl", "x")\ncc_binary(\n    name = "a",\n)\ngenrule(\n    name = "g",\n)\n',
    "nix": '{ pkgs ? import <nixpkgs> {} }:\nwith pkgs;\nstdenv.mkDerivation {\n  buildInputs = [ curl ];\n}\n',
    "jsonnet": 'local a = std.extVar("x");\n{ b: std.length(a), c:: 1 }\n',
    "dhall": 'let f = \\(x : Natural) -> x + 1\nin  f 2\n',
    "cue": '#Config: {\n\tport: int & >=1 & <=65535\n}\ncfg: #Config & {port: 80}\n',
    "puppet": "class app {\n  exec { 'x':\n    command => '/bin/id',\n  }\n}\n",
    "innosetup": '[Setup]\nAppName=Demo\nDefaultDirName={pf}\n[Files]\nSource: "a.exe"; DestDir: "{app}"\n[Run]\nFilename: "a.exe"\n',
    "wix": '<?xml version="1.0"?>\n<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">\n  <Product Id="*">\n    <CustomAction Id="X" />\n  </Product>\n</Wix>\n',
    "xaml": '<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"\n  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" x:Class="A.B">\n</Window>\n',
    "wsf": '<job id="a">\n<script language="VBScript">\nWScript.Echo 1\n</script>\n</job>\n',
    "hta": '<html><head><hta:application id="a" />\n<script language="VBScript">x=1</script></head></html>\n',
    "sct": '<?xml version="1.0"?>\n<scriptlet>\n<registration progid="A.B" />\n<script language="JScript"></script>\n</scriptlet>\n',
    "k8s_yaml": 'apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: a\nspec:\n  containers:\n    - command: ["id"]\n',
    "gitlab_ci": 'stages:\n  - build\nbuild:\n  stage: build\n  script:\n    - make\n',
    "azure_pipelines": "trigger:\n  - main\npool:\n  vmImage: ubuntu-latest\nsteps:\n  - task: Bash@3\n  - script: echo $(Build.BuildId)\n",
    "saltstack": "app:\n  cmd.run:\n    - name: id\nfoo:\n  pkg.installed:\n    - name: curl\n",
    "cloud_init": "#cloud-config\nruncmd:\n  - id\nwrite_files:\n  - path: /a\n",
    "systemd_unit": "[Unit]\nDescription=a\n[Service]\nExecStart=/bin/a\n[Install]\nWantedBy=multi-user.target\n",
    "crontab": "MAILTO=a\n*/5 * * * * /bin/a\n@reboot /bin/b\n",
    "reg_file": 'Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\A]\n"x"="y"\n',
    "inf_file": "[Version]\nSignature=\"$CHICAGO$\"\n[DefaultInstall]\nRunPreSetupCommands=a.bat\n",
    "cmake": "cmake_minimum_required(VERSION 3.5)\nproject(a)\nadd_executable(a a.c)\n",
    "gradle_groovy": "plugins {\n  id 'java'\n}\ndependencies {\n  implementation 'a:b:1'\n}\ntask hi {\n  doLast { println 'x' }\n}\n",
    "gradle_kts": 'plugins {\n  kotlin("jvm")\n}\nval a = 1\ntasks.register<Exec>("hi") {\n}\ndependencies {\n  implementation("a:b:1")\n}\n',
    "packer_hcl": 'packer {\n  required_version = "1"\n}\nbuild {\n  sources = ["source.amazon-ebs.a"]\n  provisioner "shell" {\n  }\n}\n',
    "powershell_dsc": 'Configuration Demo {\n  Import-DscResource -ModuleName X\n  Node "a" {\n    Script S { SetScript = {} }\n  }\n}\n',
    "vimscript": 'function! Run()\n  echo "x"\nendfunction\naugroup a\naugroup END\n',
    "awk": 'BEGIN { FS="," }\nNR > 1 { print $1 }\nEND { print NR }\n',
}
COMMENT = {"cs": "//", "hash": "#", "hashblock": "#", "ml": None, "fs": "//", "dash": "--", "pct": "%", "semi": ";", "vb": "'", "slash": "//"}


def unsure(v):
    return isinstance(v, str) and v.startswith("??") and labels.parse(v) is not None


def t_covered():
    assert set(S) == set(M.L), (set(M.L) ^ set(S))
    assert len(M.L) >= 48, len(M.L)
    return f"{len(M.L)} languages have a sample"


def t_identify():
    bad = []
    for k, t in S.items():
        got = M.identify(t)
        if got != k:
            bad.append((k, got, M.present(t), OLD.present(t)))
    assert not bad, bad
    return f"{len(S)} clean specimens identify"


def t_pick_unsure_own_key():
    for k, t in S.items():
        v = M.language_pick("x", t, "language")
        assert unsure(v), (k, v)
        parsed = labels.parse(v)
        assert parsed.key == f"script.language/x.{k}", parsed.key
        assert M.language_pick("x", t, "next-language") is None
    return "unsure only, one key per language, next-language never"


def t_never_plain_even_when_accepted():
    # one language's accepted name must never answer another language's id
    labels.record_for_test = getattr(labels, "record_for_test", None)
    keys = {labels.parse(M.language_pick("x", t, "language")).key for t in S.values()}
    assert len(keys) == len(S)
    return "per-language keys are distinct"


def t_decoys():
    bad = []
    for k, t in S.items():
        prof = M.L[k]["prof"]
        # a host in another language holding the specimen in a triple-quoted/double-quoted string
        host = 'import os\nx = """' + t.replace('"""', "'") + '"""\nprint(x)\n'
        if M.identify(host) is not None:
            bad.append((k, "py string host"))
        js = "var s = " + repr(t).replace("\\'", "'") + ";\nconsole.log(s);\n"
        if M.identify(js) is not None:
            bad.append((k, "js string host"))
        cm = COMMENT.get(prof)
        if cm and M.L[k]["first"] is None:
            dead = "\n".join(cm + " " + ln for ln in t.splitlines()) + "\n"
            if M.identify(dead) is not None:
                bad.append((k, "comment"))
        c = "/* " + t.replace("*/", "") + " */\nint main(){return 0;}\n"
        if M.identify(c) is not None:
            bad.append((k, "c block comment"))
    assert not bad, bad
    return "signatures in strings and comments are not read"


def t_ambiguous():
    pairs = [("lua", "zig"), ("zig", "nim"), ("k8s_yaml", "gitlab_ci"), ("systemd_unit", "crontab")]
    n = 0
    keys = list(S)
    for a in keys:
        for b in ("zig", "kotlin", "tcl", "haskell", "systemd_unit", "innosetup"):
            if a == b:
                continue
            t = S[a] + "\n" + S[b]
            got = M.identify(t)
            if M.L[a]["first"] is None and M.L[b]["first"] is None:
                assert got is None, (a, b, got)
            else:
                assert got in (None, a, b), (a, b, got)
            n += 1
    # mix with the older module's languages
    for lk in ("lua", "terraform_hcl", "xslt", "godot_gdscript"):
        old = {"lua": "local function f(x)\n  if x then\n    print(string.format('%d', x))\n  end\nend\n",
               "terraform_hcl": 'resource "a" "b" {\n  x = var.y\n}\nprovider "a" {\n}\n',
               "xslt": '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">\n<xsl:template match="/"/>\n</xsl:stylesheet>\n',
               "godot_gdscript": "extends Node\nsignal a\nfunc _ready():\n  pass\n"}[lk]
        assert OLD.identify(old) == lk, lk
        assert M.identify(old) is None, lk
        for k in ("zig", "tcl", "elixir", "cmake"):
            assert M.identify(S[k] + "\n" + old) is None, (k, lk)
    return f"{n} mixes and the older module's languages: None"


def t_misses():
    for t in ("", "hello world\n", "print('x')\n", "SELECT 1;\n", "int main(){return 0;}\n", "echo hi\n", "# just a comment\n",
              "function f(){ return 1 }\n", "<html><body>x</body></html>\n", "{\"a\": 1}\n", "a=1\nb=2\n", "def f():\n    return 1\n",
              "$x = 1\nWrite-Host $x\n", "@echo off\r\necho x\r\n", "x = 5\ny = x + 1\nz = y\n"):
        assert M.identify(t) is None, t
    return "ordinary text and common languages: None"


def t_overrides():
    t = S["zig"].encode()
    qs = [{"qid": "p-a1-language", "field": "language"}, {"qid": "p-a1-next-language", "field": "next-language"},
          {"qid": "p-a1-role", "field": "role"}]
    out = M.overrides("a.zig", qs, {"p-a1-language": None, "p-a1-next-language": None, "p-a1-role": None}, {"a.zig": t})
    assert list(out) == ["p-a1-language"] and unsure(out["p-a1-language"]), out
    assert M.overrides("a.zig", qs, {"p-a1-language": "plain"}, {"a.zig": t}) == {}
    assert M.overrides("a.zig", qs, {"p-a1-language": "??x"}, {"a.zig": t}) == {}
    return "language ids only, never over an existing answer"


def t_bounded():
    import time
    t0 = time.time()
    big = ("(* " * 60000) + "\n" + ("\"" * 100000) + ("/*" * 50000) + "x" * 200000
    M.present(big)
    M.present("[Unit]\n" + "a=" * 300000)
    M.present(("    " * 5000 + "\n") * 100)
    assert time.time() - t0 < 12, time.time() - t0
    return f"adversarial input {time.time() - t0:.2f}s"


# The battery: each t_* check asserts and returns a one-line summary of what it proved.


def test_covered():
    print(f"pass  covered: {t_covered()}")


def test_identify():
    print(f"pass  identify: {t_identify()}")


def test_pick_unsure_own_key():
    print(f"pass  pick_unsure_own_key: {t_pick_unsure_own_key()}")


def test_never_plain_even_when_accepted():
    print(f"pass  never_plain_even_when_accepted: {t_never_plain_even_when_accepted()}")


def test_decoys():
    print(f"pass  decoys: {t_decoys()}")


def test_ambiguous():
    print(f"pass  ambiguous: {t_ambiguous()}")


def test_misses():
    print(f"pass  misses: {t_misses()}")


def test_overrides():
    print(f"pass  overrides: {t_overrides()}")


def test_bounded():
    print(f"pass  bounded: {t_bounded()}")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
