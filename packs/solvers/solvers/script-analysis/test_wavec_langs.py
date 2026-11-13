#!/usr/bin/env python3
"""Offline test of backlog row 78 (wave C, group "langs"): the general Script Analysis path on the string forms
of fifteen more languages (C# script, F# script, Swift, Kotlin script, Dart, Julia, Elixir, Clojure, Scheme,
Racket, Nim, zsh, fish, awk, single-file Java).

Usage:
  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python solvers/script-analysis/test_wavec_langs.py [-v]

No Game Master request, no token, no saved attempt: every fixture is synthetic and held in memory. The label
ledger is pointed at an empty scratch folder, so labels.pick answers from the tracked seed alone.

What it proves:

  whole      each language's whole-value forms (verbatim, raw and triple-quoted strings, a here-string, its
             concatenation operator, its list joins, its character and byte-array calls, interpolation,
             escapes in its own dialect) give the whole plan with no note
  pieces     each language's ways of building a value over statements (*=, <>, .add(..), (set! ..),
             set NAME "$NAME".., awk's NAME = NAME "..", a short second variable) give the plan whole or
             without its last field, never a shortened last value
  guards     a Python triple-quoted block with its line ends kept stays a piece (rows 56 to 58 unchanged); a
             literal beside a word is never read whole; a decoded `\\u{..}` escape is never read for the
             numbers of its spelling (label_plan)
  labels     the codec label behind (def ..), (define ..), set -l and a typed `::` assignment
  techniques the own-interpreter options of the new extensions: unsure, T1059 first, T1127 for .csx/.fsx,
             never AppleScript's T1059.002 first for Swift

Last line: `TEST_WAVEC_LANGS passed=<n> failed=<n>`. Exit 0 when nothing failed, 1 otherwise.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SCRATCH = Path(tempfile.mkdtemp(prefix="test_wavec_langs_"))
for _name in ("ONLY", "CTF_HIDE", "CTF_LEDGER_MASK", "CTF_PLATFORM_URL"):
    os.environ.pop(_name, None)
os.environ["CTF_TESTING"] = "1"
os.environ["CTF_STATE_DIR"] = str(SCRATCH / "state")
os.environ["CTF_WORKDIR"] = str(SCRATCH / "challenges")      # an empty label ledger
for _p in (HERE.parent / "common", HERE):
    sys.path.insert(0, str(_p))

import generic      # noqa: E402
import label_plan   # noqa: E402
import labels       # noqa: E402
import plan_codec   # noqa: E402

VERBOSE = "-v" in sys.argv[1:]
results = []

PLAN = ("v=1|steps=acquire_remote,write_file|adapter=fixture_fetch|stage_count=2|campaign_id=LAB-78A1|"
        "url=https://lab-78a1.example.invalid/stage|")
HX = PLAN.encode().hex()
HEAD, TAIL = HX[:-10], HX[-10:]
C6 = [ord(c) for c in HX[:6]]          # the material's first characters, as a character or byte call takes them
REST = HX[6:]


def check(name: str, ok: bool, detail: str = ""):
    results.append((name, bool(ok)))
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and (VERBOSE or not ok) else ""))


def nums(xs, sep=", "):
    return sep.join(map(str, xs))


def wrapped(text, width=48):
    return [text[i:i + width] for i in range(0, len(text), width)]


def whole_or_cut(got) -> bool:
    return bool(got) and (got[0] == PLAN or (got[0].endswith("|") and PLAN.startswith(got[0])))


def test_whole():
    """Every whole-value form of the fifteen languages reads the whole plan with no note."""
    lines = wrapped(HX)
    a, b, c = HX[:40], HX[40:80], HX[80:]
    forms = {
        # C# script
        ("csx", "verbatim @\"..\""): f'var m = @"{HX}";\n',
        ("csx", "raw \"\"\"..\"\"\" on one line"): f'var m = """{HX}""";\n',
        ("csx", "raw string over lines, line ends replaced"): 'var m = """\n' + "\n".join("    " + x for x in lines)
        + '\n    """.Replace("\\n", "");\n',
        ("csx", "string.Concat(new[] { .. })"): f'var m = string.Concat(new[] {{ "{a}", "{b}", "{c}" }});\n',
        ("csx", "new string(new[] { (char)n, .. }) + rest"): "var m = new string(new[] { " + ", ".join(f"(char){n}" for n in C6)
        + f' }}) + "{REST}";\n',
        ("csx", "Encoding.ASCII.GetString(new byte[] { .. })"): "var m = Encoding.ASCII.GetString(new byte[] { "
        + nums(map(ord, HX)) + " });\n",
        ("csx", "\\u escapes"): 'var m = "' + "".join(f"\\u{ord(ch):04x}" for ch in HX[:6]) + REST + '";\n',
        ("csx", "interpolated $\"{a}{b}\""): f'var p0 = "{HX[:60]}";\nvar p1 = "{HX[60:]}";\nvar m = $"{{p0}}{{p1}}";\n',
        # F# script
        ("fsx", "let mutable, then <- m +"): f'let mutable m = "{HX[:60]}"\nm <- m + "{HX[60:]}"\n',
        ("fsx", "String.concat \"\" [ ..; .. ]"): f'let m = String.concat "" [ "{a}"; "{b}"; "{c}" ]\n',
        ("fsx", "decimal trigraphs"): 'let m = "' + "".join(f"\\{n:03d}" for n in C6) + REST + '"\n',
        ("fsx", "Encoding.ASCII.GetString [| ..uy |]"): "let m = Encoding.ASCII.GetString [| "
        + "; ".join(f"{ord(ch)}uy" for ch in HX) + " |]\n",
        ("fsx", "String(Array.map char [| .. |]) + rest"): f'let m = String(Array.map char [| {nums(C6, "; ")} |]) + "{REST}"\n',
        # Swift
        ("swift", "raw #\"..\"#"): f'let m = #"{HX}"#\n',
        ("swift", "multi-line, a backslash ending each line"): 'var m = """\n' + "\\\n".join("    " + x for x in lines)
        + '\n    """\n',
        ("swift", "[..].joined()"): f'let m = ["{a}", "{b}", "{c}"].joined()\n',
        ("swift", "\\u{..} escapes"): 'let m = "' + "".join(f"\\u{{{n:x}}}" for n in C6) + REST + '"\n',
        ("swift", "String(decoding:as:) + rest"): f'let m = String(decoding: [{nums(C6)}] as [UInt8], as: UTF8.self) + "{REST}"\n',
        ("swift", "interpolated \\(a)\\(b)"): f'let p0 = "{HX[:60]}"\nlet p1 = "{HX[60:]}"\nlet m = "\\(p0)\\(p1)"\n',
        # Kotlin script
        ("kts", "raw \"\"\"..\"\"\""): f'val m = """{HX}"""\n',
        ("kts", "listOf(..).joinToString(\"\")"): f'val m = listOf("{a}", "{b}", "{c}").joinToString("")\n',
        ("kts", "byteArrayOf(..).decodeToString()"): f"val m = byteArrayOf({nums(map(ord, HX))}).decodeToString()\n",
        ("kts", "String(charArrayOf(Char(n), ..)) + rest"): "val m = String(charArrayOf(" + ", ".join(f"Char({n})" for n in C6)
        + f')) + "{REST}"\n',
        ("kts", "template \"$a$b\""): f'val p0 = "{HX[:60]}"\nval p1 = "{HX[60:]}"\nval m = "$p0$p1"\n',
        # Dart
        ("dart", "adjacent literals"): f"var m = '{a}' '{b}' '{c}';\n",
        ("dart", "String.fromCharCodes([..]) + rest"): f"var m = String.fromCharCodes([{nums(C6)}]) + '{REST}';\n",
        ("dart", "'''..''' over lines, replaceAll"): "final m = '''\n" + "\n".join(lines) + "\n'''.replaceAll('\\n', '');\n",
        ("dart", "interpolated '${a}${b}'"): f"var p0 = '{HX[:60]}';\nvar p1 = '{HX[60:]}';\nvar m = '${{p0}}${{p1}}';\n",
        # Julia
        ("jl", "* joins"): f'm = "{a}" * "{b}" * "{c}"\n',
        ("jl", "*= appends"): f'm = "{HX[:60]}"\nm *= "{HX[60:]}"\n',
        ("jl", "raw\"..\""): f'm = raw"{HX}"\n',
        ("jl", "Char(n) * .. * Char(n)"): "m = " + " * ".join(f"Char({ord(ch)})" for ch in HX) + "\n",
        ("jl", "String(UInt8[..]) * rest"): f'm = String(UInt8[{nums(C6)}]) * "{REST}"\n',
        # Elixir
        ("exs", "<> joins"): f'm = "{a}" <> "{b}" <> "{c}"\n',
        ("exs", "<<n, ..>> <> rest"): f'm = <<{nums(C6)}>> <> "{REST}"\n',
        ("exs", "sigil ~S(..)"): f"m = ~S({HX})\n",
        ("exs", "Enum.join([..])"): f'm = Enum.join(["{a}", "{b}", "{c}"])\n',
        ("exs", "heredoc piped to String.replace"): 'm = """\n' + "\n".join(lines) + '\n""" |> String.replace("\\n", "")\n',
        ("exs", "interpolated #{a}#{b}"): f'p0 = "{HX[:60]}"\np1 = "{HX[60:]}"\nm = "#{{p0}}#{{p1}}"\n',
        # Clojure
        ("clj", "(str ..)"): f'(def m (str "{a}" "{b}" "{c}"))\n',
        ("clj", "(apply str (map char [..])) in a (str ..)"): f'(def m (str (apply str (map char [{nums(C6, " ")}])) "{REST}"))\n',
        ("clj", "(String. (byte-array [..]))"): f'(def m (String. (byte-array [{nums(map(ord, HX), " ")}])))\n',
        ("clj", "(format \"%s%s\" a b)"): f'(def p0 "{HX[:60]}")\n(def p1 "{HX[60:]}")\n(def m (format "%s%s" p0 p1))\n',
        # Scheme, Racket
        ("scm", "(string-append ..)"): f'(define m (string-append "{a}" "{b}" "{c}"))\n',
        ("scm", "\\x..; escapes"): '(define m "' + "".join(f"\\x{n:02x};" for n in C6) + REST + '")\n',
        ("scm", "(set! m (string-append m ..))"): f'(define m "{HX[:60]}")\n(set! m (string-append m "{HX[60:]}"))\n',
        ("rkt", "here string #<<EOT"): f"#lang racket\n(define m #<<EOT\n{HX}\nEOT\n  )\n",
        ("rkt", "(bytes->string/utf-8 (bytes ..))"): f"(define m (bytes->string/utf-8 (bytes {nums(map(ord, HX), ' ')})))\n",
        ("rkt", "(string-join (list ..) \"\")"): f'(define m (string-join (list "{a}" "{b}" "{c}") ""))\n',
        # Nim
        ("nim", "& joins"): f'let m = "{a}" & "{b}" & "{c}"\n',
        ("nim", ".add appends"): f'var m = "{HX[:60]}"\nm.add("{HX[60:]}")\n',
        ("nim", "$chr(n) & chr(n) .."): "let m = $chr(" + str(ord(HX[0])) + ")" + "".join(f" & chr({ord(ch)})" for ch in HX[1:]) + "\n",
        ("nim", "&\"{a}{b}\""): f'let p0 = "{HX[:60]}"\nlet p1 = "{HX[60:]}"\nlet m = &"{{p0}}{{p1}}"\n',
        # zsh, fish
        ("zsh", "$'\\x..' quoting"): "m=$'" + "".join(f"\\x{n:02x}" for n in C6) + REST + "'\n",
        ("zsh", "\"$(printf '\\ooo')\" touching the rest"): "m=\"$(printf '" + "".join(f"\\{n:03o}" for n in C6) + f"')\"\"{REST}\"\n",
        ("zsh", "${a}${b} unquoted"): f'p0="{HX[:60]}"\np1="{HX[60:]}"\nm=${{p0}}${{p1}}\n',
        ("zsh", "$(tr -d '\\n' <<'EOF' ..)"): "m=$(tr -d '\\n' <<'EOF'\n" + "\n".join(lines) + "\nEOF\n)\n",
        ("fish", "set -l, $a$b"): f'set -l p0 "{HX[:60]}"\nset -l p1 "{HX[60:]}"\nset -l m $p0$p1\n',
        ("fish", "set m \"$m\"..  appends"): f'set -l m "{HX[:60]}"\nset m "$m""{HX[60:]}"\n',
        ("fish", "(string join \'\' ..)"): f"set -l m (string join '' '{a}' '{b}' '{c}')\n",
        ("fish", "\\x.. escapes outside quotes"): "set -l m " + "".join(f"\\x{n:02x}" for n in C6) + f'"{REST}"\n',
        # awk
        ("awk", "literals side by side"): f'BEGIN {{\n    m = "{a}" "{b}" "{c}"\n}}\n',
        ("awk", "sprintf(\"%c..\") then the rest"): f'BEGIN {{\n    m = sprintf("{"%c" * 6}", {nums(C6)}) "{REST}"\n}}\n',
        ("awk", "m = m \"..\" appends"): f'BEGIN {{\n    m = "{HX[:60]}"\n    m = m "{HX[60:]}"\n}}\n',
        # Java
        ("java", "text block, a backslash ending each line"): 'String m = """\n' + "\\\n".join("    " + x for x in lines)
        + '""";\n',
        ("java", "String.join(\"\", ..)"): f'String m = String.join("", "{a}", "{b}", "{c}");\n',
        ("java", "new String(new byte[] { .. }, US_ASCII)"): "String m = new String(new byte[] { " + nums(map(ord, HX))
        + " }, StandardCharsets.US_ASCII);\n",
        ("java", "String.valueOf(new char[] { .. }) + rest"): f'String m = String.valueOf(new char[] {{ {nums(C6)} }}) + "{REST}";\n',
    }
    for (ext, name), text in forms.items():
        got, note = plan_codec.reading(text, "." + ext)
        check(f"whole: .{ext} {name} reads the whole plan", bool(got) and got[0] == PLAN and note is None,
              f"{str(got)[:100]} {note}")


def test_pieces():
    """Values built over statements whose head is a literal: never read whole from the head alone."""
    pieces = {
        ("jl", "*= a short tail"): f'm = "{HEAD}"\nm *= "{TAIL}"\n',
        ("jl", "two variables joined by *"): f'p0 = "{HEAD}"\np1 = "{TAIL}"\nm = p0 * p1\n',
        ("exs", "m = m <> a short tail"): f'm = "{HEAD}"\nm = m <> "{TAIL}"\n',
        ("exs", "two variables joined by <>"): f'p0 = "{HEAD}"\np1 = "{TAIL}"\nm = p0 <> p1\n',
        ("nim", ".add(a short tail)"): f'var m = "{HEAD}"\nm.add("{TAIL}")\n',
        ("fsx", "m <- m + a short tail"): f'let mutable m = "{HEAD}"\nm <- m + "{TAIL}"\n',
        ("clj", "two variables in (str ..)"): f'(def p0 "{HEAD}")\n(def p1 "{TAIL}")\n(def m (str p0 p1))\n',
        ("clj", "(def m (str m ..))"): f'(def m "{HEAD}")\n(def m (str m "{TAIL}"))\n',
        ("scm", "(set! m (string-append m ..))"): f'(define m "{HEAD}")\n(set! m (string-append m "{TAIL}"))\n',
        ("rkt", "two variables in (string-append ..)"): f'(define p0 "{HEAD}")\n(define p1 "{TAIL}")\n'
                                                         f'(define m (string-append p0 p1))\n',
        ("fish", "set -l, then $p0$p1"): f'set -l p0 "{HEAD}"\nset -l p1 "{TAIL}"\nset -l m $p0$p1\n',
        ("fish", "set m \"$m\" and a short tail"): f'set -l m "{HEAD}"\nset m "$m""{TAIL}"\n',
        ("awk", "m = m and a short tail"): f'BEGIN {{\n    m = "{HEAD}"\n    m = m "{TAIL}"\n}}\n',
        ("awk", "two variables side by side"): f'BEGIN {{\n    p0 = "{HEAD}"\n    p1 = "{TAIL}"\n    m = p0 p1\n}}\n',
        ("csx", "interpolated, the second short"): f'var p0 = "{HEAD}";\nvar p1 = "{TAIL}";\nvar m = $"{{p0}}{{p1}}";\n',
        ("swift", "interpolated, the second short"): f'let p0 = "{HEAD}"\nlet p1 = "{TAIL}"\nlet m = "\\(p0)\\(p1)"\n',
        ("exs", "interpolated, the second short"): f'p0 = "{HEAD}"\np1 = "{TAIL}"\nm = "#{{p0}}#{{p1}}"\n',
        ("jl", "String(UInt8[..]) * the rest"): f'm = String(UInt8[{nums(C6)}]) * "{REST}"\n',
        ("exs", "<<..>> <> the rest"): f'm = <<{nums(C6)}>> <> "{REST}"\n',
    }
    for (ext, name), text in pieces.items():
        got = plan_codec.decode(text, "." + ext)
        check(f"pieces: .{ext} {name}: the plan whole or without its last field, never a shortened value",
              whole_or_cut(got), str(got)[:120])
    # label_plan: a material whose variable grows elsewhere is a piece (its last field left out).
    for ext, text in {
        "jl": f'const Codec_ab = "hex_compact|identity|"\nMaterial_ab = "{HEAD}"\nMaterial_ab *= "{TAIL}"\n',
        "nim": f'const Codec_ab = "hex_compact|identity|"\nvar Material_ab = "{HEAD}"\nMaterial_ab.add("{TAIL}")\n',
        "awk": f'BEGIN {{\nCodec_ab = "hex_compact|identity|"\nMaterial_ab = "{HEAD}"\nMaterial_ab = Material_ab "{TAIL}"\n}}\n',
    }.items():
        t, cut = label_plan.reading(text, "." + ext)
        check(f"pieces: label_plan on .{ext}: an appended material comes without its last field",
              t is None or (cut and PLAN.startswith(t)), f"{str(t)[:100]} cut={cut}")


def test_guards():
    """What rows 56 to 58 and the Day 5 retro settled stays settled."""
    b64 = __import__("base64").b64encode(PLAN.encode()).decode()
    py = 'M = """\n' + "\n".join(b64[i:i + 40] for i in range(0, len(b64), 40)) + '\n"""\n'
    got, note = plan_codec.reading(py, ".py")
    check("guards: a Python triple-quoted block whose line ends stay is still a piece (a plan without its last field)",
          bool(got) and got[0] != PLAN and PLAN.startswith(got[0]) and note is not None, f"{got} {note}")
    # A literal beside a short word (the retro's "material and a word"): the join only lengthens the last value,
    # so the plan comes whole only where the literal alone ends it (`|`), else without its last field.
    for ext in (".py", ".awk"):
        for k in range(3):
            stored = bytes(b ^ (0x21 + k) for b in PLAN[:-1].encode())     # no `|` at its end: a last value to lengthen
            t = __import__("base64").b64encode(stored).decode()
            word = (f'Codec_ab = "base64|single_byte_xor|{0x21 + k:02x}"\n'
                    f'm = "{t.rstrip("=")}" "{"QUJD"[:2 + k]}"\n')
            got = plan_codec.decode(word, ext)
            ok = got is None or (PLAN.startswith(got[0]) and got[0].endswith("|"))
            check(f"guards: {ext} literal beside a {2 + k}-letter word: never a lengthened last value", ok, str(got)[:100])
    # label_plan reads an escaped literal for its value, never for the numbers of its spelling.
    dec = ",".join(str(b ^ 0x3d) for b in PLAN.encode()[::-1])
    swift = ('let Codec_ab: String = "reversed_decimal|single_byte_xor|61"\nvar Material_ab = "'
             + "".join(f"\\u{{{ord(ch):x}}}" for ch in dec[:6]) + dec[6:] + '"\n')
    t, cut = label_plan.reading(swift, ".swift")
    check("guards: label_plan reads \\u{..} escapes as their characters", t == PLAN and not cut, f"{str(t)[:100]} {cut}")
    fsx = ('let Codec_ab = "reversed_decimal|single_byte_xor|61"\nlet Material_ab = "'
           + "".join(f"\\{ord(ch):03d}" for ch in dec[:6]) + dec[6:] + '"\n')
    t, cut = label_plan.reading(fsx, ".fsx")
    check("guards: label_plan reads F#'s decimal trigraphs as decimal", t == PLAN and not cut, f"{str(t)[:100]} {cut}")
    check("guards: unescaped() keeps its old readings",
          plan_codec.unescaped("\\x41\\102\\u0043d\\n") == [65, 66, 67, 100, 10] and plan_codec.unescaped("plain") is None
          and plan_codec.unescaped("\\x41\\q") is None and plan_codec.unescaped("C:\\Users\\Public\\x41") is None)
    check("guards: the new dialects", plan_codec.unescaped("\\u{76}a") == [118, 97]
          and plan_codec.unescaped("\\118\\061", "decimal") == [118, 61]
          and plan_codec.unescaped("\\x76;a", "scheme") == [118, 97]
          and plan_codec.escape_dialect(".fsx") == "decimal" and plan_codec.escape_dialect(".scm") == "scheme"
          and plan_codec.escape_dialect(".rkt") == "")
    # Two plans stay two plans in the new forms too.
    other = PLAN.replace("LAB-78A1", "LAB-OLD9").encode().hex()
    two = f'(def old "{other}")\n(def m (str "{HX[:60]}" "{HX[60:]}"))\n'
    got, note = plan_codec.reading(two, ".clj")
    check("guards: an older plan beside the material: neither is taken", got is None and note is not None, f"{got} {note}")
    # A JavaScript object shorthand is no interpolation: the Day 7 forms keep their grade.
    js = f'const m = "{HX}";\nmodule.exports = {{ m }};\n'
    got, note = plan_codec.reading(js, ".mjs")
    check("guards: `{ m }` outside a string is no interpolation", bool(got) and got[0] == PLAN and note is None, f"{got} {note}")
    # A printf fold gives the whole material where the text alone gives its piece (reversed, rolling xor: the
    # piece's plan differs in its last value only): the whole plan, never "two plans".
    out = [PLAN.encode()[0] ^ 0x3b]
    for byte in PLAN.encode()[1:]:
        out.append(byte ^ out[-1])
    value = ",".join(map(str, bytes(out)[::-1]))
    sh = ("readonly Material_ab=\"$(printf '" + "".join(f"\\x{ord(ch):02x}" for ch in value[:8]) + "')\"'"
          + value[8:] + "'\nreadonly Codec_ab='reversed_decimal|rolling_xor|59'\n")
    got, note = plan_codec.reading(sh, ".sh")
    check("guards: a printf fold's whole plan stands over the piece the text alone gives",
          bool(got) and got[0] == PLAN and note is None, f"{str(got)[:100]} {note}")
    for name, use in (("\"${m}\" alone", 'read -r -a parts <<< "${m}"\n'), ("${m} alone", "raw=${m}\n"),
                      ("$\"{m}\" alone", 'var copy = $"{m}";\n')):
        text = f"m='{HX}'\n" + use
        got, note = plan_codec.reading(text, ".sh")
        check(f"guards: an interpolation that is its string's whole value ({name}) joins nothing",
              bool(got) and got[0] == PLAN and note is None, f"{got} {note}")


def test_labels():
    texts = {
        "(def Codec_x ..)": '(def Codec_ab "hex_compact|identity")\n',
        "(define Codec_x ..)": '(define Codec_ab "hex_compact|identity")\n',
        "set -l Codec_x ..": 'set -l Codec_ab "hex_compact|identity"\n',
        "Codec_x::String = ..": 'Codec_ab::String = "hex_compact|identity"\n',
        "const string Codec_x = ..": 'const string Codec_ab = "hex_compact|identity";\n',
        "let Codec_x: String = ..": 'let Codec_ab: String = "hex_compact|identity"\n',
    }
    for name, text in texts.items():
        check(f"labels: the codec label behind {name} is read", plan_codec.label_of(text) == ["hex_compact", "identity"],
              str(plan_codec.label_of(text)))
    late = "v=1|adapter=fixture_adapter|campaign_id=LAB-78|steps=decode_configuration,return_configuration"
    for name, text in {
        "clojure (def ..)": f'(def Codec_ab "hex_compact|identity")\n(def Material_ab "{late.encode().hex()}")\n',
        "scheme (define ..)": f'(define Codec_ab "hex_compact|identity")\n(define Material_ab "{late.encode().hex()}")\n',
        "fish set -l": f'set -l Codec_ab "hex_compact|identity"\nset -l Material_ab "{late.encode().hex()}"\n',
        "elixir lower case": f'codec_ab = "hex_compact|identity"\nmaterial_ab = "{late.encode().hex()}"\n',
    }.items():
        got = label_plan.read_text(text)
        check(f"labels: label_plan reads the {name} material by its label", got == late, str(got)[:120])


def test_techniques():
    for ext, first in ((".csx", ["T1059", "T1127"]), (".fsx", ["T1059", "T1127"]), (".swift", ["T1059"]),
                       (".kts", ["T1059"]), (".dart", ["T1059"]), (".jl", ["T1059"]), (".exs", ["T1059"]),
                       (".clj", ["T1059"]), (".scm", ["T1059"]), (".rkt", ["T1059"]), (".nim", ["T1059"]),
                       (".java", ["T1059"]), (".fish", ["T1059.004"]), (".zsh", ["T1059.004"]), (".awk", ["T1059.004"])):
        own = generic.techniques(ext)
        name = plan_codec.ext_name(ext)
        got = generic.pick(f"script.attack/{name}", own)
        check(f"techniques: {ext} offers {first} first, unsure", own[:len(first)] == first and labels.is_unsure(got)
              and len(own) <= generic.MAX_OPTIONS, f"{own} {str(got)[:80]}")
    check("techniques: Swift never offers AppleScript's T1059.002 first", generic.techniques(".swift")[0] != "T1059.002")


def test_review():
    """Review blockers B1, B2 and the decoy in every language: a whole plan that differs from a piece's plan only in
    its last value is never taken for it, and an append of anything but one literal keeps a chain a piece."""
    real = PLAN
    decoy = PLAN.replace("lab-78a1.example.invalid/stage", "decoy.example.invalid/other")
    rh, dh = real.encode().hex(), decoy.encode().hex()
    cut = len(rh) - 30
    kept = real[:real.rfind("url=")]
    for name, (ext, text) in {
        "py piece + tail() then decoy": (".py", f'm = "{rh[:cut]}"\nm += tail()\nd = "{dh}"\nrun(m)\n'),
        "jl piece *= tail() then decoy": (".jl", f'm = "{rh[:cut]}"\nm *= tail()\nd = "{dh}"\nrun(m)\n'),
        "rb chunk + load() then decoy": (".rb", f'a = "{rh[:cut]}"\nb = load()\nd = "{dh}"\nrun(a + b)\n'),
        "py real + argv, decoy whole": (".py", f'import sys\nreal = "{rh}" + sys.argv[1]\ndecoy = "{dh}"\n'),
        "js real + Arguments, decoy whole": (".js", f'var real = "{rh}" + WScript.Arguments(0);\nvar decoy = "{dh}";\n'),
        "ps1 decoy + args, real whole": (".ps1", f'$decoy = "{dh}" + $args[0]\n$real = "{rh}"\n'),
    }.items():
        got, note = plan_codec.reading(text, ext)
        check(f"review: {name} gives no plan", got is None and note and "two different plans" in note,
              f"{str(got)[:100]} {note}")
    a, b = rh[:100], rh[100:cut]
    for name, (ext, text) in {
        "nim m.add(tail)": (".nim", f'var m = "{a}"\nm.add("{b}")\nm.add(tail)\nrun(m)\n'),
        "nim m.add(chr(65))": (".nim", f'var m = "{a}"\nm.add("{b}")\nm.add(chr(65))\nrun(m)\n'),
        "java m.append(tail)": (".java", f'var m = "{a}";\nm.append("{b}");\nm.append(tail);\nrun(m);\n'),
        "jl m *= tail": (".jl", f'm = "{a}"\nm *= "{b}"\nm *= tail\nrun(m)\n'),
        "py m.append(tail)": (".py", f'm = "{a}"\nm += "{b}"\nm.append(tail)\nrun(m)\n'),
    }.items():
        got, note = plan_codec.reading(text, ext)
        check(f"review: {name} leaves the last field out", got is not None and got[0] == kept and note
              and "left out" in note, f"{str(got)[:100]} {note}")


def main() -> int:
    test_whole()
    test_pieces()
    test_guards()
    test_labels()
    test_techniques()
    test_review()
    failed = [name for name, ok in results if not ok]
    print(f"TEST_WAVEC_LANGS passed={len(results) - len(failed)} failed={len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
