#!/usr/bin/env python3
"""Script Analysis language-name cribs, part 2 (Day 24 build night, ticket T5): about fifty more languages,
installer / CI / config formats and host profiles a polyglot day may name, for the `language` and
`next-language` ids only, and only as UNSURE picks.

Never wrong (AGENTS.md "Uncertain answers"):
  - nothing here is ever plain: no spelling has been judged, so the answer is `labels.pick` under a key of its
    OWN per language (`script.language/<ext>.<lang>`: one accepted name must never answer another language's id;
    the older gdscript_csx_langs shared one key, now also per language), or None;
  - cribs are counted on LIVE code only: comments and string literals are blanked first, in the comment syntax of
    the language's own profile (`PROFILES`), so a signature sitting in another language's comment, string or
    here-doc is a decoy and is not read;
  - a format (YAML, INI, XML, systemd, reg) must also START like its format (`first`), so a python host that
    carries a unit file in a string is not that format;
  - a language is named only when EXACTLY ONE language of this table AND of gdscript_csx_langs reaches its
    threshold and its structural `need`; two or more is an ambiguous mix: None;
  - a language no crib matched: None. The extension is never the answer.

Bounded and linear: the input is cut at MAX_TEXT characters, blanking is one left-to-right scan, every crib is a
single-line pattern over character classes (no nested quantifiers).

Entry points (loaded live by analyze.py by name, after gdscript_csx_langs, picks only):
    identify(text) -> key | None        present(text) -> {key: weight}        options_for(key)
    language_pick(ext, text, field) -> labels.pick string | None
    overrides(member, questions, answers, files, find=None) -> {qid: pick}
CLI:  .venv/bin/python solvers/script-analysis/lang_names_more.py <file> ...
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
try:
    import labels  # noqa: E402
except Exception:   # noqa: BLE001
    labels = None

MAX_TEXT = 1 << 18

# comment / string profiles: (line comment starters, block comment pairs, string quotes)
PROFILES = {
    "cs": (("//",), (("/*", "*/"),), '"\''),
    "hash": (("#",), (), '"\''),
    "hashblock": (("#",), (("/*", "*/"),), '"\''),
    "ml": ((), (("(*", "*)"),), '"\''),
    "fs": (("//",), (("(*", "*)"),), '"\''),
    "dash": (("--",), (("{-", "-}"),), '"\''),
    "pct": (("%",), (), '"\''),
    "semi": ((";",), (), '"\''),
    "xml": ((), (("<!--", "-->"),), ""),
    "vb": (("'", "REM "), (), '"'),
    "slash": (("//",), (), '"\''),
}


def blank(text, prof):
    """`text` with comments and string literals of the profile blanked to spaces, newlines kept (one scan)."""
    line, block, quotes = PROFILES[prof]
    xml = prof == "xml"
    if not xml:
        block = block + (("/*", "*/"),)       # a host's block comment, whatever the language's own syntax
    triples = () if xml or prof == "vb" else ('"""', "'''")
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        j = -1
        for a, b in block:
            if text.startswith(a, i):
                k = text.find(b, i + len(a))
                j = n if k < 0 else k + len(b)
                break
        if j < 0:
            for a in line:
                if text.startswith(a, i) and (a != "REM " or i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
                    k = text.find("\n", i)
                    j = n if k < 0 else k
                    break
        if j < 0:
            for t in triples:
                if text.startswith(t, i):
                    k = text.find(t, i + 3)
                    j = n if k < 0 else k + 3
                    break
        if j < 0 and c == "`" and not xml and prof != "vb":
            k = text.find("`", i + 1)
            j = n if k < 0 else k + 1
        if j >= 0:
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
            continue
        if c in quotes:
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j, n)
            if j < n and text[j] == c:
                j += 1
            out.append(" " * (j - i))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _first_line(text):
    for ln in text.lstrip("﻿").splitlines():
        if ln.strip():
            return ln.strip()
    return ""


# Each language: prof, min weight, cribs [(regex, weight)], need (any must match), neg (none may match), first
# (regex on the file's first non-blank raw line; formats), ci (ignore case), options (spellings, snake_case first).
L = {}


def _sp(p):
    """Same-line whitespace only: a bare `\\s` would let a line-start crib scan across blank lines (quadratic)."""
    return p.replace("\\s", "[ \\t]")


_LAZY = {}       # key -> (cribs, need, neg, first, flags) as written, until the first score compiles them


def lang(key, prof, mn, cribs, options, need=(), neg=(), first=None, ci=False):
    """One language of the table. Perf (Day 27 speed build): its patterns are compiled on the first score of any
    text (_compile_all, called by _score), not at import: analyze.py loads this file for every delivery and asks it
    only about a `-language` id a reader left None, so a solve with none such pays nothing for the ~300 patterns.
    Once compiled, L holds exactly the compiled patterns it always held."""
    cribs = [(_sp(p), w) for p, w in cribs]
    need = [_sp(p) for p in need]
    neg = [_sp(p) for p in neg]
    L[key] = dict(prof=prof, min=mn, cribs=None, need=None, neg=None, first=first, options=list(options))
    _LAZY[key] = (cribs, need, neg, first, re.M | (re.I if ci else 0))


def _compile_all():
    """Compile every language's patterns into L, once (see lang)."""
    while _LAZY:
        key, (cribs, need, neg, first, flags) = next(iter(_LAZY.items()))
        spec = L[key]
        spec["cribs"] = [(re.compile(p, flags), w) for p, w in cribs]
        spec["need"] = [re.compile(p, flags) for p in need]
        spec["neg"] = [re.compile(p, flags) for p in neg]
        spec["first"] = re.compile(first, re.I) if first else None
        del _LAZY[key]


# ---- systems / modern languages
lang("zig", "cs", 4, [(r"@import\(", 3), (r"\bconst\s+\w+\s*=\s*@import\(", 1), (r"\bstd\.(?:debug|mem|fs|heap|io|process)\.", 2),
     (r"\b(?:comptime|errdefer|anytype|usingnamespace)\b", 2), (r"^\s*(?:pub\s+)?fn\s+\w+\(", 1)],
     ["zig", "zig_lang", "ziglang"], need=[r"@import\(|\bcomptime\b|\berrdefer\b"], neg=[r"^\s*use\s+\w+", r"^\s*package\s"])
lang("nim", "hash", 4, [(r"^\s*(?:proc|func|iterator|template|macro)\s+\w+\*?\s*(?:\[[^\]]*\])?\(.*=\s*$", 3), (r"\bwhen\s+isMainModule\b", 3),
     (r"\bdiscard\b", 1), (r"^\s*import\s+[a-z]\w*(?:\s*,\s*\w+)*\s*$", 1), (r"\becho\s", 1), (r"^\s*(?:let|var|const)\s+\w+\s*(?::\s*\w+)?\s*=", 1)],
     ["nim", "nim_lang", "nimlang"], need=[r"^\s*(?:proc|func|iterator|template|macro)\s+\w+\*?\s*(?:\[[^\]]*\])?\(.*=\s*$|\bwhen\s+isMainModule\b|\bdiscard\b"],
     neg=[r"^\s*def\s+\w+.*:\s*$", r";\s*$", r"\bfunction\b"])
lang("crystal", "hash", 4, [(r"^\s*def\s+\w+[?!]?\((?:\w+\s*:\s*[\w:]+(?:,\s*)?)+\)", 3), (r"\.as\(|\.as\?\(", 2), (r"^\s*macro\s+\w+", 2),
     (r"^\s*@\[\w+", 2), (r"\bProcess\.run\b|\bSTDIN\.|\bFile\.read\b", 1), (r"^\s*require\s+", 1), (r"^\s*end\s*$", 1)],
     ["crystal", "crystal_lang", "cr"], need=[r"^\s*def\s+\w+[?!]?\((?:\w+\s*:\s*[\w:]+(?:,\s*)?)+\)|\.as\(|^\s*macro\s+\w+|^\s*@\[\w+"], neg=[r";\s*$"])
lang("vlang", "cs", 4, [(r"^\s*module\s+main\s*$", 2), (r"^\s*fn\s+(?:\(\w+\s+&?\w+\)\s*)?\w+\(.*\)", 2), (r"\bmut\s+\w+\s*:=", 3),
     (r"^\s*fn\s+main\(\)", 2), (r"\bos\.(?:execute|read_file|exec)\b", 1), (r"^\s*import\s+(?:os|net|json|time|net\.http)\b", 1)],
     ["vlang", "v", "v_lang"], need=[r"\bmut\s+\w+\s*:=|^\s*module\s+main\s*$"], neg=[r"^\s*use\s", r"\blet\s+(?:mut\s+)?\w+", r"^\s*package\s", r"\bfunc\b"])
lang("haxe", "cs", 4, [(r"\bstatic\s+function\s+main\s*\(\s*\)", 3), (r"^\s*import\s+haxe\.", 3), (r"@:\w+", 2), (r"\btrace\s*\(", 1),
     (r"^\s*(?:public\s+|private\s+)?(?:static\s+)?function\s+\w+\s*\([^)]*\)\s*:\s*\w+", 2), (r"^\s*package\s+[\w.]*\s*;", 1)],
     ["haxe", "haxe_lang"], need=[r"\bstatic\s+function\s+main\b|^\s*import\s+haxe\.|@:\w+"])
lang("odin", "cs", 4, [(r"\w+\s*::\s*proc\s*\(", 3), (r"^\s*package\s+\w+\s*$", 1), (r"^\s*import\s+\w*\s*  *", 0), (r"\bfmt\.println\b", 1),
     (r":\s*=\s*\w", 0), (r"\bcontext\.\w+", 1), (r"\bdefer\b", 1), (r"-> *\(?\w", 0)],
     ["odin", "odin_lang"], need=[r"\w+\s*::\s*proc\s*\("], neg=[r"\bfunc\b", r"^\s*fn\s"])
lang("dart", "cs", 4, [(r"^\s*import\s+  *;", 0), (r"\bvoid\s+main\s*\(\s*\)\s*(?:async\s*)?\{", 2), (r"\bFuture<\w+>", 2), (r"\bStream<\w+>", 1),
     (r"@override\b", 1), (r"\bfinal\s+\w+\s+\w+\s*=|\bfinal\s+\w+\s*=", 1), (r"\bProcess\.(?:run|start)\b|\bHttpClient\b", 2), (r"\bimport\s+(?:'|\"|  )", 0)],
     ["dart", "dart_lang", "flutter"], need=[r"\bFuture<\w+>|\bProcess\.(?:run|start)\b|\bStream<\w+>"], neg=[r"\bfunction\b", r"^\s*package\s", r"\bnamespace\b"])
lang("kotlin", "cs", 4, [(r"^\s*fun\s+(?:\w+\.)?\w+\s*\(", 2), (r"\bval\s+\w+(?:\s*:\s*[\w<>?]+)?\s*=", 1), (r"\bvar\s+\w+\s*:\s*[\w<>?]+", 1),
     (r"\bfun\s+main\s*\(", 2), (r"\bdata\s+class\b|\bcompanion\s+object\b|\bwhen\s*\(|\blateinit\b", 2), (r"^\s*package\s+[\w.]+\s*$", 1)],
     ["kotlin", "kotlin_script", "kts"], need=[r"^\s*fun\s+(?:\w+\.)?\w+\s*\(|\bfun\s+main\b"], neg=[r"\bfunc\b", r"\bregister<", r"^\s*plugins\s*\{"])
lang("swift", "cs", 4, [(r"^\s*import\s+(?:Foundation|UIKit|SwiftUI|Cocoa|AppKit|Darwin)\b", 3), (r"^\s*func\s+\w+\s*\(.*\)\s*(?:->\s*\w+\s*)?\{", 2),
     (r"\bguard\s+let\b|\bif\s+let\b", 2), (r"\blet\s+\w+\s*:\s*\w+\s*=|\bvar\s+\w+\s*:\s*\w+\s*=", 1), (r"\bProcess\(\)|\bFileManager\b|\bCommandLine\.arguments\b", 2)],
     ["swift", "swift_lang"], need=[r"^\s*import\s+(?:Foundation|UIKit|SwiftUI|Cocoa|AppKit|Darwin)\b|\bguard\s+let\b|\bif\s+let\b"], neg=[r"\bfunction\b"])
lang("scala", "cs", 4, [(r"^\s*object\s+\w+\s+extends\s+App\b", 3), (r"^\s*def\s+\w+\s*\(.*\)\s*(?::\s*[\w\[\], ]+)?\s*=", 2), (r"\bcase\s+class\b|\bsealed\s+trait\b", 2),
     (r"^\s*val\s+\w+\s*(?::\s*[\w\[\]]+)?\s*=", 1), (r"\bimplicit\s+(?:val|def|class)\b|\bmatch\s*\{", 2), (r"^\s*import\s+scala\.", 2)],
     ["scala", "scala_script", "sbt"], need=[r"^\s*object\s+\w+\s+extends\s+App\b|\bcase\s+class\b|\bsealed\s+trait\b|\bimplicit\s+(?:val|def|class)\b|^\s*import\s+scala\."], neg=[r"^\s*fun\s"])
lang("ballerina", "cs", 4, [(r"^\s*import\s+ballerina/\w+", 3), (r"\bio:println\b", 2), (r"^\s*(?:public\s+)?function\s+\w+\s*\(.*\)\s+returns\b", 3),
     (r"\bcheck\s+\w", 1), (r"^\s*service\s+/", 2), (r"^\s*import\s+wso2/", 2)],
     ["ballerina", "ballerina_lang", "bal"], need=[r"^\s*import\s+ballerina/|\)\s+returns\s+\w+\??\s*\{|\bio:println\b"])
lang("bicep", "cs", 4, [(r"^\s*resource\s+\w+\s+=\s*(?:\{|if\b|\[)", 3), (r"^\s*param\s+\w+\s+(?:string|int|bool|object|array|secureString)\b", 3),
     (r"^\s*output\s+\w+\s+(?:string|int|bool|object|array)\b", 2), (r"^\s*targetScope\s*=", 2), (r"^\s*var\s+\w+\s*=", 1), (r"^\s*module\s+\w+\s+=", 2)],
     ["bicep", "azure_bicep", "bicep_template"], need=[r"^\s*resource\s+\w+\s+=\s*(?:\{|if\b|\[)|^\s*param\s+\w+\s+(?:string|int|bool|object|array|secureString)\b|^\s*targetScope\s*="], neg=[r"^\s*(?:def|class)\s"])
lang("racket", "semi", 4, [(r"^\s*\(define\b", 2), (r"^\s*\(require\b", 2), (r"\(displayln\b|\(printf\b", 1), (r"\blambda\b|\(let\*?\s*\(", 1),
     (r"^\s*\(provide\b", 2)],
     ["racket", "racket_lang", "scheme"], need=[r"^\s*\(require\b|^\s*\(provide\b|\(displayln\b"], first=r"^#lang\s+(?:racket|typed/racket|scheme|r5rs)")
lang("clojure", "semi", 4, [(r"^\s*\(ns\s+[\w.-]+", 3), (r"^\s*\(defn-?\s+\S+", 2), (r"\(println\b", 1), (r"\(let\s*\[", 2), (r"\bclojure\.\w+", 2), (r"\(:require\b", 2)],
     ["clojure", "clojure_script", "clj"], need=[r"^\s*\(ns\s+[\w.-]+|^\s*\(defn-?\s+\S+"], neg=[r"^\s*\(define\b", r"^#lang\b"])
lang("tcl", "hash", 4, [(r"^\s*proc\s+[\w:]+\s*\{", 3), (r"^\s*package\s+require\b", 3), (r"^\s*puts\s+\S", 1), (r"^\s*set\s+\w+\s+\S", 1),
     (r"\[\s*(?:lindex|expr|string|file|llength|dict)\s", 2), (r"^\s*foreach\s+\w+\s+", 1), (r"^\s*namespace\s+eval\b", 2)],
     ["tcl", "tcl_script", "tk"], need=[r"^\s*proc\s+[\w:]+\s*\{|^\s*package\s+require\b|\[\s*(?:lindex|expr|llength|dict)\s"], neg=[r"^\s*(?:def|class)\s", r"\bfunction\b", r";\s*$"])
lang("r_lang", "hash", 4, [(r"\w\s*<-\s*function\s*\(", 3), (r"\blibrary\(\s*\w+\s*\)", 3), (r"\bdata\.frame\(|\bread\.csv\(|\bsystem\(|\bSys\.getenv\(", 2),
     (r"%>%|\|>", 1), (r"\w\s*<-\s*\S", 1), (r"\bcat\(", 1), (r"\bsource\(", 1)],
     ["r", "r_lang", "rscript"], need=[r"\w\s*<-\s*function\s*\(|\blibrary\(\s*\w+\s*\)|\bdata\.frame\(|\bread\.csv\("],
     neg=[r"\$\w+\s*=", r"\bvar\s", r"\bconst\s", r"\blet\s", r";\s*$", r"^\s*def\s"])
lang("julia", "hash", 4, [(r"^\s*using\s+[A-Z]\w*(?:\s*,\s*[A-Z]\w*)*\s*$", 3), (r"^\s*using\s+\w+\s*:", 3), (r"::\s*(?:Int64|Int|Float64|String|Vector\{|Any|Bool)\b", 2),
     (r"^\s*function\s+\w+\(.*\)(?:::\w+)?\s*$", 1), (r"^\s*end\s*$", 1), (r"\bprintln\(", 1), (r"^\s*module\s+\w+\s*$", 1), (r"@\w+\s", 1)],
     ["julia", "julia_lang", "jl"], need=[r"^\s*using\s+[A-Z]\w*(?:\s*,\s*[A-Z]\w*)*\s*$|^\s*using\s+\w+\s*:|::\s*(?:Int64|Float64|Vector\{)"], neg=[r";\s*$", r"\bdef\b", r"\blocal\b", r"\$\w"])
lang("ocaml", "ml", 4, [(r"^\s*let\s+(?:rec\s+)?\w+[^=\n]*=", 1), (r"^\s*open\s+[A-Z]\w*", 2), (r"\bprint_endline\b|\bPrintf\.printf\b|\bSys\.command\b", 2),
     (r"\bmatch\s+.+\s+with\s*$", 2), (r";;\s*$", 2), (r"\bUnix\.\w+|\bList\.(?:iter|map|fold_left)\b|\bString\.\w+", 1)],
     ["ocaml", "ocaml_lang", "ml"], need=[r";;\s*$|\bprint_endline\b|\bPrintf\.printf\b|\bmatch\s+.+\s+with\s*$|\bSys\.command\b"], neg=[r"^\s*(?:def|class)\s", r"\bfunction\s*\w*\s*\(", r"\{\s*$"])
lang("fsharp", "fs", 4, [(r"^\s*let\s+(?:rec\s+|mutable\s+)?\w+[^=\n]*=", 1), (r"^\s*open\s+System\b", 2), (r"\bprintfn\b", 3), (r"\|>", 1),
     (r"^\s*module\s+\w+\s*=|^\s*namespace\s+\w+\s*$", 1), (r"\[<EntryPoint>\]", 3), (r"\bmatch\s+.+\s+with\s*$", 1)],
     ["fsharp", "fsharp_script", "fsx"], need=[r"\bprintfn\b|\[<EntryPoint>\]|^\s*open\s+System\b"], neg=[r";;\s*$", r"\bprint_endline\b", r"\bfunction\s*\w*\s*\(", r"^\s*(?:def|class)\s"])
lang("erlang", "pct", 4, [(r"^-module\(\w+\)\.", 3), (r"^-export\(\[", 3), (r"^\w+\(.*\)\s*(?:when\s+.+)?->\s*$", 2), (r"\bio:format\(", 2), (r"^-include", 1),
     (r"\bos:cmd\(|\bhttpc:request\(|\bfile:read_file\(", 2)],
     ["erlang", "erlang_lang", "erl"], need=[r"^-module\(\w+\)\.|^-export\(\[|\bio:format\("], neg=[r"^\s*(?:def|class)\s"])
lang("elixir", "hash", 4, [(r"^\s*defmodule\s+[\w.]+\s+do\b", 3), (r"^\s*def(?:p)?\s+\w+[?!]?\(.*\)\s+do\b", 3), (r"\bIO\.puts\b|\bSystem\.cmd\b|\bEnum\.\w+", 2),
     (r"\|>", 1), (r"^\s*(?:import|alias|use|require)\s+[A-Z]\w*", 1), (r"^\s*end\s*$", 1)],
     ["elixir", "elixir_lang", "exs"], need=[r"^\s*defmodule\s+[\w.]+\s+do\b|^\s*def(?:p)?\s+\w+[?!]?\(.*\)\s+do\b|\bIO\.puts\b|\bSystem\.cmd\b"])
lang("haskell", "dash", 4, [(r"^module\s+[\w.]+(?:\s*\(.*\))?\s+where\s*$", 3), (r"^import\s+(?:qualified\s+)?[A-Z][\w.]*", 2), (r"^\w+\s*::\s*[\w\[\](), ->]+\s*$", 3),
     (r"\bmain\s*::\s*IO\b", 3), (r"^\s*where\s*$", 1), (r"<\$>|>>=|\bputStrLn\b", 2)],
     ["haskell", "haskell_lang", "hs"], need=[r"^module\s+[\w.]+(?:\s*\(.*\))?\s+where\s*$|\bmain\s*::\s*IO\b|\bputStrLn\b|^\w+\s*::\s*[\w\[\](), ->]+\s*$"], neg=[r"^\s*(?:def|class)\s", r";\s*$"])
lang("cobol", "cs", 6, [(r"^\s*IDENTIFICATION\s+DIVISION\.", 4), (r"^\s*PROCEDURE\s+DIVISION\b", 3), (r"^\s*DATA\s+DIVISION\.", 2), (r"^\s*PROGRAM-ID\.", 3),
     (r"\bWORKING-STORAGE\s+SECTION\.", 2), (r"\bDISPLAY\s+", 0), (r"\bSTOP\s+RUN\b", 1)],
     ["cobol", "cobol_lang"], need=[r"^\s*IDENTIFICATION\s+DIVISION\.|^\s*PROGRAM-ID\.|^\s*PROCEDURE\s+DIVISION\b"])
lang("vba", "vb", 4, [(r"^\s*(?:Public\s+|Private\s+)?(?:Sub|Function)\s+\w+\s*\(", 2), (r"^\s*Attribute\s+VB_Name\b", 4), (r"\bAuto_Open\b|\bDocument_Open\b|\bWorkbook_Open\b", 3),
     (r"\bCreateObject\s*\(|\bShell\s*\(|\bWScript\.Shell\b", 2), (r"^\s*Option\s+Explicit\b", 2), (r"^\s*Dim\s+\w+\s+As\s+\w+", 1), (r"^\s*End\s+(?:Sub|Function)\b", 1)],
     ["vba", "vba_macro", "vba_module"], need=[r"^\s*Attribute\s+VB_Name\b|\bAuto_Open\b|\bDocument_Open\b|\bWorkbook_Open\b|^\s*Option\s+Explicit\b"], neg=[r"^\s*On\s+Error\s+Resume\s+Next\b.*WScript\.Echo"],
     first=r"^(?:Attribute\s+VB_|Option\s+Explicit|(?:Public\s+|Private\s+)?(?:Sub|Function)\s|Dim\s|Const\s|Declare\s|Rem\s|')", ci=True)
lang("jxa", "cs", 4, [(r"\bObjC\.import\(", 3), (r"\bApplication\(", 3), (r"\.doShellScript\(", 3), (r"\bapp\.includeStandardAdditions\b", 3), (r"\$\.NS\w+", 2)],
     ["jxa", "javascript_for_automation", "osa_javascript", "jxa_script"], need=[r"\bObjC\.import\(|\.doShellScript\(|\bapp\.includeStandardAdditions\b"])
lang("starlark", "hash", 4, [(r"^\s*load\(\s*  *", 0), (r"^\s*(?:cc_|py_|java_|go_)(?:binary|library|test)\(", 3), (r"^\s*(?:genrule|filegroup|sh_binary|http_archive)\(", 3),
     (r"^\s*workspace\(", 3), (r"\bnative\.\w+\(", 2), (r"^\s*load\(", 1)],
     ["starlark", "bazel", "bazel_build", "skylark"], need=[r"^\s*(?:cc_|py_|java_|go_)(?:binary|library|test)\(|^\s*(?:genrule|filegroup|sh_binary|http_archive)\(|^\s*workspace\(|\bnative\.\w+\("])
lang("nix", "hashblock", 4, [(r"^\s*\{[^}\n]*\}\s*:\s*$", 2), (r"\bwith\s+pkgs\s*;", 3), (r"\bpkgs\.\w+", 1), (r"\bmkDerivation\b|\bbuildInputs\b|\bfetchurl\b|\bwriteShellScript", 3),
     (r"^\s*let\s*$", 1), (r"^\s*in\s*$", 1), (r"\binherit\s+\(?\w+", 1), (r"\bwith\s+import\s+<nixpkgs>|<nixpkgs>", 3)],
     ["nix", "nix_expression", "nixos"], need=[r"\bmkDerivation\b|\bbuildInputs\b|\bfetchurl\b|\bwith\s+pkgs\s*;|<nixpkgs>|\bwriteShellScript"], neg=[r"^\s*(?:def|class)\s"])
lang("jsonnet", "hash", 4, [(r"\bstd\.\w+\s*\(", 3), (r"^\s*local\s+\w+\s*=.*;\s*$", 2), (r"\w+\s*::\s", 2), (r"\bself\.\w+", 1), (r"\bimport\s+  *", 0), (r"\bimport\s+[\"']|\bimport\s+ ", 1)],
     ["jsonnet", "jsonnet_lang"], need=[r"\bstd\.\w+\s*\("], neg=[r"^\s*(?:def|class)\s", r"\bfunction\s+\w+\s*\("])
lang("dhall", "dash", 4, [(r"\\\(\w+\s*:\s*[\w ]+\)\s*->", 3), (r"λ\(\w+\s*:", 3), (r"\b(?:Natural|Text|List\s+Text|Optional\s+Text)\b", 2), (r"^\s*let\s+\w+\s*(?::\s*[\w ]+)?\s*=", 1),
     (r"^\s*in\s+", 1), (r"https://\S+\.dhall\b", 3)],
     ["dhall", "dhall_lang"], need=[r"\\\(\w+\s*:\s*[\w ]+\)\s*->|λ\(\w+\s*:|\bNatural\b"], neg=[r"^module\s", r"::", r";\s*$"])
lang("cue", "slash", 4, [(r"^#\w+\s*:\s*\{", 3), (r"^\s*\w+\??\s*:\s*(?:string|int|bool|number|float|\[\.\.\.\w+\])\s*(?:\||&|$)", 2), (r"\b(?:string|int|bool|number)\s*&\s*", 2),
     (r"\b>=?\d+\s*&\s*<=?\d+", 3), (r"\bstrings\.\w+\(|\bexec\.Run\b|\bencoding/json\b", 2), (r"^\s*package\s+\w+\s*$", 1)],
     ["cue", "cuelang", "cue_lang"], need=[r"^#\w+\s*:\s*\{|\b>=?\d+\s*&\s*<=?\d+|\b(?:string|int|bool|number)\s*&\s*|\bexec\.Run\b"], neg=[r"^\s*(?:def|class)\s", r";\s*$", r"\bfunc\b"])
lang("puppet", "hash", 4, [(r"^\s*(?:class|define|node)\s+['\w:.]+.*\{\s*$", 2), (r"\b(?:exec|file|package|service|cron|user|notify)\s*\{\s*:", 3), (r"\w+\s*=>\s", 1),
     (r"\$\w+\s*=\s", 0), (r"\bhiera\(|\bnotify\s*\{", 2), (r"^\s*include\s+\w+", 1)],
     ["puppet", "puppet_manifest", "puppet_dsl"], need=[r"\b(?:exec|file|package|service|cron|user|notify)\s*\{\s*:"], neg=[r"^\s*(?:def|class)\s+\w+.*:\s*$", r"<\?php"])
# ---- config / CI / packaging formats (must start like their format)
lang("innosetup", "semi", 4, [(r"^\s*\[(?:Setup|Files|Run|Code|Icons|Registry|Tasks|INI|Messages|Languages|Types|Components|UninstallRun|Dirs)\]\s*$", 2),
     (r"^\s*AppName\s*=", 2), (r"^\s*Source\s*:", 2), (r"^\s*Filename\s*:", 2), (r"^\s*procedure\s+\w+\s*;|^\s*function\s+\w+\(", 1), (r"^\s*DefaultDirName\s*=", 2)],
     ["innosetup", "inno_setup", "iss", "inno"], need=[r"^\s*\[(?:Setup|Files|Run|Code)\]\s*$"], first=r"^(?:\[(?:Setup|Files|Run|Code|Icons|Registry|Tasks)\]|#(?:define|include|ifdef))")
lang("wix", "xml", 4, [(r"<Wix\b", 3), (r"<(?:Product|Package|Fragment)\b", 1), (r"<CustomAction\b", 3), (r"<(?:Component|Directory|Feature|InstallExecuteSequence)\b", 1),
     (r"xmlns\s*=\s*\"http://(?:schemas\.microsoft\.com/wix|wixtoolset\.org/schemas)", 3)],
     ["wix", "wix_installer", "wxs", "wix_toolset"], need=[r"<Wix\b"], first=r"^(?:<\?xml\b|<Wix\b|<Include\b)")
lang("xaml", "xml", 4, [(r"<(?:Window|Page|UserControl|ResourceDictionary|Application)\b", 2), (r"xmlns\s*=\s*\"http://schemas\.microsoft\.com/winfx/2006/xaml/presentation", 3),
     (r"xmlns:x\s*=\s*\"http://schemas\.microsoft\.com/winfx/2006/xaml", 2), (r"\bx:(?:Class|Name|Key)\s*=", 2), (r"\{(?:Binding|StaticResource)\b", 1)],
     ["xaml", "xaml_markup", "wpf_xaml"], need=[r"winfx/2006/xaml"], first=r"^(?:<\?xml\b|<(?:Window|Page|UserControl|ResourceDictionary|Application)\b)")
lang("wsf", "xml", 4, [(r"<job\b", 3), (r"<package\b", 2), (r"<script\s+language\s*=\s*\"(?:VBScript|JScript)\"", 3), (r"<resource\b|<reference\b|<object\b", 1)],
     ["wsf", "windows_script_file", "wsh_wsf"], need=[r"<job\b|<package\b"], first=r"^(?:<\?xml\b|<job\b|<package\b)", ci=True)
lang("hta", "xml", 4, [(r"<hta:application\b", 4), (r"<html\b", 1), (r"<script\s+language\s*=\s*\"?(?:VBScript|JScript)\"?", 1), (r"\bwindow\.(?:resizeTo|moveTo)\b", 1)],
     ["hta", "hta_application", "html_application"], need=[r"<hta:application\b"], first=r"^<(?:!doctype|html|head|hta:application|\?xml)", ci=True)
lang("sct", "xml", 4, [(r"<scriptlet\b", 4), (r"<registration\b", 3), (r"progid\s*=", 1), (r"<script\s+language", 1), (r"<implements\b", 1)],
     ["sct", "windows_scriptlet", "scriptlet"], need=[r"<scriptlet\b|<registration\b"], first=r"^(?:<\?xml\b|<scriptlet\b)", ci=True)
lang("k8s_yaml", "hash", 4, [(r"^apiVersion\s*:\s*\S+", 2), (r"^kind\s*:\s*(?:CronJob|Job|Pod|Deployment|DaemonSet|ConfigMap|Secret|Service|StatefulSet)\b", 3), (r"^metadata\s*:\s*$", 1),
     (r"^spec\s*:\s*$", 1), (r"^\s*containers\s*:\s*$", 2), (r"^\s*(?:command|args)\s*:", 1)],
     ["k8s_yaml", "kubernetes_yaml", "k8s", "kubernetes", "yaml"], need=[r"^apiVersion\s*:\s*\S+", r"^kind\s*:\s*\w+"], first=r"^(?:---|apiVersion\s*:|kind\s*:|#)")
lang("gitlab_ci", "hash", 4, [(r"^stages\s*:\s*$", 2), (r"^\s*script\s*:", 3), (r"^\s*stage\s*:\s*\w", 2), (r"^(?:image|before_script|after_script|variables)\s*:", 1),
     (r"^\s*(?:only|except|rules)\s*:", 1)],
     ["gitlab_ci", "gitlab_ci_yaml", "gitlab_pipeline", "gitlab"], need=[r"^\s*script\s*:", r"^\s*stage\s*:\s*\w|^stages\s*:"],
     neg=[r"^jobs\s*:", r"\bruns-on\s*:", r"^trigger\s*:", r"^pool\s*:", r"\bvmImage\s*:", r"^\s*-\s*task\s*:", r"^\s*tasks\s*:\s*$", r"^\s*hosts\s*:", r"^apiVersion\s*:"], first=r"^(?:---|[\w.-]+\s*:|#)")
lang("azure_pipelines", "hash", 4, [(r"^trigger\s*:", 1), (r"^pool\s*:", 2), (r"\bvmImage\s*:", 3), (r"^\s*-\s*task\s*:", 3), (r"\$\((?:Build|Agent|System)\.\w+\)", 2),
     (r"^\s*-\s*(?:script|bash|pwsh|powershell)\s*:", 2), (r"^steps\s*:", 1)],
     ["azure_pipelines", "azure_pipelines_yaml", "azure_devops", "azure_yaml"], need=[r"\bvmImage\s*:|^pool\s*:|^\s*-\s*task\s*:|\$\((?:Build|Agent)\.\w+\)"],
     neg=[r"\bruns-on\s*:", r"^\s*uses\s*:", r"^apiVersion\s*:", r"^\s*hosts\s*:"], first=r"^(?:---|[\w.-]+\s*:|#)")
lang("saltstack", "hash", 4, [(r"^\s*[\w.-]+\s*:\s*$\n^\s+(?:cmd|pkg|file|service|user|git|cron)\.\w+\s*:", 4), (r"^\s+(?:cmd\.(?:run|script)|pkg\.installed|file\.managed|service\.running)\s*:", 3),
     (r"\{\{\s*(?:pillar|salt|grains)\b", 2), (r"^\s*-\s*(?:name|source|require|watch)\s*:", 1), (r"^\s*include\s*:", 1)],
     ["saltstack", "salt_state", "salt_sls", "salt"], need=[r"^\s+(?:cmd\.(?:run|script)|pkg\.installed|file\.managed|service\.running)\s*:"], neg=[r"^\s*hosts\s*:", r"^apiVersion\s*:"])
lang("cloud_init", "hash", 3, [(r"^#cloud-config\b", 5), (r"^(?:runcmd|write_files|packages|users|bootcmd|ssh_authorized_keys|package_update)\s*:", 2), (r"^\s*-\s*(?:path|content|owner|permissions)\s*:", 1)],
     ["cloud_init", "cloud_config", "cloudinit"], need=[r"^(?:runcmd|write_files|bootcmd|users|packages)\s*:"], first=r"^#cloud-config\b")
lang("systemd_unit", "hash", 4, [(r"^\[Unit\]\s*$", 2), (r"^\[Service\]\s*$", 2), (r"^\[Install\]\s*$", 1), (r"^ExecStart\s*=", 2), (r"^WantedBy\s*=", 1), (r"^Description\s*=", 1),
     (r"^\[Timer\]\s*$", 2), (r"^OnCalendar\s*=", 2)],
     ["systemd_unit", "systemd", "systemd_service", "unit_file"], need=[r"^\[(?:Unit|Service|Timer)\]\s*$"], first=r"^\[(?:Unit|Service|Timer|Install)\]")
lang("crontab", "hash", 4, [(r"^(?:[\d*/,-]+\s+){4}[\d*/,-]+\s+\S", 3), (r"^@(?:reboot|hourly|daily|weekly|monthly|yearly)\s+\S", 3), (r"^(?:MAILTO|SHELL|PATH)\s*=", 1),
     (r"^(?:[\d*/,-]+\s+){5}\w+\s+\S", 1)],
     ["crontab", "cron", "cron_file", "cron_job"], need=[r"^(?:[\d*/,-]+\s+){4}[\d*/,-]+\s+\S|^@(?:reboot|hourly|daily|weekly|monthly|yearly)\s+\S"],
     neg=[r"^\s*(?:def|class|import|function)\b", r"[{};]\s*$", r"^\[\w+\]"], first=r"^(?:[\d*/,-]+\s+[\d*/,-]+\s+|@\w+\s+|(?:MAILTO|SHELL|PATH)\s*=)")
lang("reg_file", "semi", 4, [(r"^Windows Registry Editor Version 5\.00\s*$", 5), (r"^REGEDIT4\s*$", 5), (r"^\[HKEY_[A-Z_]+\\", 3), (r"^\"[^\"]*\"\s*=\s*(?:dword|hex|\")", 1)],
     ["reg_file", "registry_file", "reg", "windows_registry"], need=[r"^Windows Registry Editor Version 5\.00|^REGEDIT4|^\[HKEY_[A-Z_]+\\"], first=r"^(?:Windows Registry Editor Version 5\.00|REGEDIT4)")
lang("inf_file", "semi", 4, [(r"^\[Version\]\s*$", 2), (r"^Signature\s*=", 2), (r"^\[(?:DefaultInstall|DefaultUninstall|Strings|SourceDisksNames|DestinationDirs|Manufacturer)\]", 2),
     (r"^(?:RunPreSetupCommands|RunPostSetupCommands|UnRegisterOCXs|RegisterOCXs|AddReg|CustomDestination)\s*=", 3), (r"^\[(?:Install|Setup)[^\]]*\]\s*$", 1)],
     ["inf_file", "windows_inf", "setup_information", "inf"], need=[r"^\[Version\]\s*$|^\[DefaultInstall\]"], first=r"^\[(?:Version|DefaultInstall|Strings|Manufacturer)\]", ci=True)
lang("cmake", "hash", 4, [(r"^\s*cmake_minimum_required\s*\(", 3), (r"^\s*(?:add_executable|add_library|add_custom_command|add_custom_target|execute_process)\s*\(", 3),
     (r"^\s*(?:project|target_link_libraries|find_package|include_directories)\s*\(", 1), (r"^\s*set\s*\(\s*\w+", 1), (r"^\s*(?:if|foreach|endif|endforeach)\s*\(", 1)],
     ["cmake", "cmake_lists", "cmakelists"], need=[r"^\s*cmake_minimum_required\s*\(|^\s*(?:add_executable|add_library|add_custom_command|add_custom_target|execute_process)\s*\("], ci=True)
lang("gradle_groovy", "cs", 4, [(r"^\s*plugins\s*\{", 2), (r"^\s*(?:dependencies|repositories|buildscript|allprojects)\s*\{", 2), (r"^\s*task\s+\w+", 2), (r"\bapply\s+plugin\s*:", 2),
     (r"^\s*(?:implementation|compileOnly|testImplementation|api)\s*$", 2), (r"\bdoLast\s*\{|\bdoFirst\s*\{", 2)],
     ["gradle_groovy", "gradle", "gradle_dsl", "build_gradle"], need=[r"^\s*task\s+\w+|\bapply\s+plugin\s*:|\bdoLast\s*\{|^\s*(?:implementation|compileOnly|testImplementation|api)\s*$"],
     neg=[r"\bval\s+\w+\s*=", r"\bregister<\w+>", r"\bid\s*\(", r"^\s*pipeline\s*\{", r"^\s*fun\s"])
lang("gradle_kts", "cs", 4, [(r"^\s*plugins\s*\{", 1), (r"\bid\s*\(\s*\)?", 0), (r"\bregister<\w+>\s*\(", 3), (r"\bval\s+\w+\s*=", 1), (r"\bkotlin\s*\(", 2), (r"^\s*(?:dependencies|repositories)\s*\{", 1),
     (r"\btasks\.(?:register|named)\s*(?:<\w+>)?\s*\(", 2), (r"\b(?:implementation|testImplementation)\s*\(", 2), (r"\bdoLast\s*\{", 1)],
     ["gradle_kts", "gradle_kotlin_dsl", "build_gradle_kts", "kts"], need=[r"\bregister<\w+>\s*\(|\bkotlin\s*\(|\b(?:implementation|testImplementation)\s*\(|\bval\s+\w+\s*="], neg=[r"^\s*task\s+\w+", r"\bapply\s+plugin\s*:", r"^\s*pipeline\s*\{"])
lang("packer_hcl", "hashblock", 4, [(r"^\s*source\s+\s*\s*\{", 0), (r"^\s*packer\s*\{", 3), (r"^\s*build\s*\{", 2), (r"^\s*provisioner\s+  *\{|^\s*provisioner\s+\"[^\"]*\"\s*\{", 3),
     (r"^\s*source\s*  *\s*\{", 0), (r"^\s*locals\s*\{", 1), (r"\bsource\.\w+\.\w+", 2)],
     ["packer_hcl", "packer", "packer_template", "pkr_hcl"], need=[r"^\s*packer\s*\{|^\s*provisioner\s+[\"']?\w|\bsource\.\w+\.\w+"], neg=[r"^\s*resource\s+\S", r"^\s*(?:def|class)\s"])
lang("powershell_dsc", "hash", 4, [(r"^\s*Configuration\s+\w+\s*\{?\s*$", 3), (r"^\s*Import-DscResource\b", 3), (r"^\s*Node\s+[\w$\"'\[\]]+\s*\{?\s*$", 2), (r"^\s*(?:Script|File|Registry|Service|Package|WindowsFeature)\s+\w+\s*\{", 2),
     (r"\bSetScript\s*=|\bGetScript\s*=|\bTestScript\s*=", 3)],
     ["powershell_dsc", "dsc", "dsc_configuration"], need=[r"^\s*Configuration\s+\w+\s*\{?\s*$|^\s*Import-DscResource\b|\bSetScript\s*="], ci=True)
lang("vimscript", "hash", 4, [(r"^\s*function!?\s+[\w#:]+\(.*\)", 2), (r"^\s*(?:let|set|call|echo|autocmd|augroup|nnoremap|inoremap|syntax)\s+\S", 1), (r"^\s*endfunction\b|^\s*endif\b|^\s*endfor\b", 2),
     (r"\bsystem\(|\bexpand\(|\bsubstitute\(", 1), (r"^\s*\"", 0), (r"^\s*augroup\s+\w+", 2)],
     ["vimscript", "vim_script", "viml", "vim"], need=[r"^\s*endfunction\b|^\s*augroup\s+\w+|^\s*function!\s"], neg=[r"^\s*(?:def|class)\s", r"\{\s*$"])
lang("awk", "hash", 4, [(r"^\s*BEGIN\s*\{", 3), (r"^\s*END\s*\{", 2), (r"\$[0-9NF]+\b", 1), (r"\bNR\s*[=<>]|\bNF\b", 2), (r"\bsplit\s*\(.*,.*\)", 1), (r"\bgsub\s*\(|\bsprintf\s*\(", 1)],
     ["awk", "awk_script", "gawk"], need=[r"^\s*BEGIN\s*\{|\bNR\s*[=<>]"], neg=[r"^\s*(?:def|class|import|function)\b", r"\$\w+\s*=", r"<\?php"])

# the languages of the older module count too: an ambiguous mix with them is also None
try:
    import gdscript_csx_langs as _OLD
except Exception:  # noqa: BLE001
    _OLD = None


def _old_shadow(text):
    """True when a language of gdscript_csx_langs reaches its threshold by cribs and need but one of its own
    `neg` markers withheld it (another language's code is in the file): a mix, so ambiguous."""
    code = _OLD.live_code(_norm(text[:MAX_TEXT]))
    for name, spec in _OLD.LANGS.items():
        need = spec.get("need")
        if need and not any(re.search(p, code, re.M) for p in need):
            continue
        rxs, mn = _OLD._COMPILED[name]
        if sum(w for rx, w in rxs if rx.search(code)) >= mn:
            return True
    return False


def _norm(text):
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _score(key, raw, cache):
    if _LAZY:
        _compile_all()
    spec = L[key]
    if spec["first"] is not None and not spec["first"].search(_first_line(raw)):
        return 0
    code = cache.get(spec["prof"])
    if code is None:
        code = cache[spec["prof"]] = blank(raw, spec["prof"])
    if spec["need"] and not all(rx.search(code) for rx in spec["need"]):
        return 0
    s = sum(w for rx, w in spec["cribs"] if w and rx.search(code))
    if s and any(rx.search(code) for rx in spec["neg"]):
        return -s            # reached by its cribs but another family's marker is there: a shadow, see identify()
    return s


def present(text, shadows=False):
    """{key: weight} for every language of this table that reaches its threshold on `text`; with shadows=True
    also the languages a `neg` marker withheld (weight negative)."""
    if not isinstance(text, str) or not text:
        return {}
    raw = _norm(text[:MAX_TEXT])
    cache, out = {}, {}
    for key, spec in L.items():
        s = _score(key, raw, cache)
        if s >= spec["min"] or (shadows and -s >= spec["min"]):
            out[key] = s
    return out


def identify(text):
    """The one language of this table the text is written in, or None (no hit, or an ambiguous mix, the older
    module's languages counted)."""
    allp = present(text, shadows=True)
    hits = {k: v for k, v in allp.items() if v > 0}
    if not hits or len(allp) != len(hits):
        return None          # nothing, or a language withheld by a neg marker is also in the file: ambiguous
    if _OLD is not None:
        try:
            if _OLD.present(text) or _old_shadow(text):
                return None
        except Exception:  # noqa: BLE001
            return None
    return next(iter(hits)) if len(hits) == 1 else None


def options_for(key):
    spec = L.get(key)
    return tuple(spec["options"]) if spec else ()


def _ext_of(member):
    return re.sub(r"[^a-z0-9]+", "_", Path(str(member or "")).suffix.lower().lstrip(".")).strip("_") or "unknown"


def language_pick(ext, text, field="language"):
    """An unsure labels.pick for a `-language` id (what the specimen is written in), or None. `-next-language`
    is the next stage's language, which cribs of THIS file do not establish: None."""
    fld = (field or "").replace("_", "-")
    if fld != "language" or labels is None:
        return None
    key = identify(text)
    if key is None:
        return None
    ext = _ext_of(ext) if ("." in str(ext) or "/" in str(ext)) else re.sub(r"[^a-z0-9]+", "_", str(ext or "").lower()).strip("_")
    try:
        return labels.pick(f"script.language/{ext}.{key}", list(options_for(key)))
    except Exception as e:  # noqa: BLE001
        print(f"[lang_names_more] labels.pick raised {type(e).__name__}: {e}", file=sys.stderr)
        return None


def _field_of(q):
    field = q.get("field") if isinstance(q, dict) else None
    if not (isinstance(field, str) and field):
        qid = re.sub(r"^set\d+\.", "", str((q or {}).get("qid") or (q or {}).get("id") or ""))
        parts = qid.split("-", 2)
        field = parts[2] if len(parts) == 3 else qid
    return field


def _text_of(data):
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    try:
        b = bytes(data)
    except Exception:  # noqa: BLE001
        return ""
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    return b.decode("utf-8", "replace")


def overrides(member, questions, answers, files, find=None):
    """{qid: pick} for the `-language` ids of one specimen a reader left None. Never touches a plain answer or an
    answer that is already an unsure pick (the older module's, or a reader's)."""
    data = None
    if isinstance(files, dict):
        data = files.get(member)
        if data is None and member:
            base = str(member).rsplit("/", 1)[-1]
            data = next((v for k, v in files.items() if "->" not in str(k) and str(k).rsplit("/", 1)[-1] == base), None)
    text = _text_of(data)
    if not text:
        return {}
    out = {}
    for q in questions or ():
        if not isinstance(q, dict) or _field_of(q) != "language":
            continue
        qid = q.get("qid") or q.get("id")
        if (answers or {}).get(qid) is not None:
            continue
        v = language_pick(_ext_of(member), text, "language")
        if v is not None:
            out[qid] = v
            print(f"[lang_names_more] {qid}: language offered an unsure crib-based pick", file=sys.stderr)
    return out


def main(argv):
    if argv and argv[0] in ("-h", "--help"):
        print("usage: lang_names_more.py <script> [...]")
        return 0
    if not argv:
        print("lang_names_more.py: expected at least one script", file=sys.stderr)
        return 2
    try:
        for p in argv:
            t = Path(p).read_text(errors="replace")
            print(p, identify(t), present(t))
    except Exception as exc:
        print(f"lang_names_more.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
