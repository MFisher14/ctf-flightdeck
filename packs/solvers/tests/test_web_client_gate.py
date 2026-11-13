"""B-127: the client-side-check opener and client-JS custom-encoding recognizer (solvers/web/client_gate.py)
and its bounded JavaScript-subset evaluator (solvers/web/_jsmini.py).

Every page, script, key and flag below is invented here; only the shapes are the 2026 Spooky challenges'
(a comment naming a text file and the flag's shape, a script comparing a 53-bit hash of the lowercased input
with a constant; a script listing path tokens that are base64 of two-letter bit text of 16-bit character
codes). The live tests run against a fake HTTP server this test starts on 127.0.0.1; no other host is
contacted, and the refused-scope test proves no request is sent at all. No challenge file is read.
"""
from __future__ import annotations

import base64
import datetime as dt
import math
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import _jsmini as J
import client_gate as cg
from ctf import event, flagfmt


def profile(scope=(), prefixes=("spooky",), slug="b127-test"):
    return event.parse({
        "slug": slug, "name": "client gate test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"},
        "flag": {"prefixes": list(prefixes)},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(scope)},
    }, src="<test>")


SAVED = profile()                           # no live scope: a manual event
LIVE = profile(scope=("127.0.0.1",), slug="b127-live")
FF = flagfmt.for_profile(SAVED)
STEPS = 3_000_000                           # an explicit evaluator budget (steps, never seconds)

CYRB53_JS = """
const cyrb53 = (str, seed = 0) => {
  let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
  for (let i = 0, ch; i < str.length; i++) {
    ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1  = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2  = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
};
"""


def program(src):
    """An evaluator holding a source's top-level functions and constants."""
    it = J.Interp(2_000_000)
    for st in J.parse_program(src):
        if st[0] == "fndecl":
            it.define(st[1], st[2])
        elif st[0] == "var":
            for target, init in st[2]:
                it.define(target[1], it.eval(init) if init[0] != "fn" else init)
    return it


def ev(src, it=None):
    it = it or J.Interp(200_000)
    return it.eval(J.parse_expression(src))


def ee_token(key, zero="E", one="e"):
    """The Gelotophobia shape, computed independently of the engine: 16 bits per character, 0/1 written as
    two letters, then standard base64."""
    bits = "".join(f"{ord(c):016b}" for c in key)
    return base64.b64encode(bits.translate(str.maketrans("01", zero + one)).encode()).decode()


# ---- the tokenizer and parser ----------------------------------------------------------------------

def test_tokenizer_strings_templates_regex_and_numbers():
    toks = J.tokenize(r"""var a = 'it\'s\x41B\u{43}'; // gone
      /* block */ let b = `x${1 + 2}y`, c = 0x1F + 1e3 + 1_000 + .5;
      const r = /a\/b[/]c/gi; const d = a / 2 / c;""")
    kinds = [(t.kind, t.value) for t in toks if t.kind in ("str", "tmpl", "num", "regex")]
    assert ("str", "it'sABC") in kinds
    assert ("tmpl", (["x", "y"], ["1 + 2"])) in kinds
    assert [v for k, v in kinds if k == "num"] == [31.0, 1000.0, 1000.0, 0.5, 2.0]
    assert [v for k, v in kinds if k == "regex"] == [("a\\/b[/]c", "gi")]     # `a / 2 / c` stays division
    assert not any(t.kind == "punct" and t.value == "/*" for t in toks)
    with pytest.raises(J.JsSyntax):
        J.tokenize("var s = 'unterminated")
    with pytest.raises(J.JsSyntax):
        J.tokenize("/* never closed")


def test_parser_handles_asi_arrows_destructuring_and_refuses_unsupported():
    it = program("""function f(a, b = 2) { return a + b }
      const g = x => x * 3
      const h = ({k, j = 4}, [p, , q]) => k + j + p + q
      let total = 0
      for (const ch of "abc") total += ch.charCodeAt(0)""")
    assert ev("f(1)", it) == 3 and ev("f(1, 5)", it) == 6 and ev("g(7)", it) == 21
    assert ev("h({k: 1}, [10, 99, 100])", it) == 115
    with pytest.raises(J.JsUnsupported):
        J.parse_program("class A {}")
    with pytest.raises(J.JsSyntax):
        J.parse_expression("1 +")


# ---- evaluator semantics ---------------------------------------------------------------------------

def test_js_integer_and_bitwise_semantics():
    assert ev("Math.imul(0xffffffff, 5)") == -5
    assert ev("Math.imul(2654435761, 2654435761)") == float((2654435761 * 2654435761 & 0xFFFFFFFF) - (1 << 32))
    assert ev("-1 >>> 0") == 4294967295 and ev("-1 >>> 28") == 15
    assert ev("1 << 31") == -2147483648 and ev("1 << 32") == 1          # shift count is mod 32
    assert ev("(2147483647 + 1) | 0") == -2147483648
    assert ev("~5") == -6 and ev("7 % -3") == 1 and ev("-7 % 3") == -1
    assert ev("5 / 0") == math.inf and math.isnan(ev("0 / 0"))
    assert ev("2 ** 10") == 1024 and ev("2 ** 3 ** 2") == 512          # right-associative


def test_js_string_and_equality_semantics():
    assert ev("'a' + 1 + 2") == "a12" and ev("1 + 2 + 'a'") == "3a"
    assert ev("(255).toString(16)") == "ff" and ev("(-10).toString(2)") == "-1010"
    assert ev("String.fromCharCode(102, 108, 97, 103)") == "flag"
    assert ev("'galf'.split('').reverse().join('')") == "flag"
    assert ev("atob('ZmxhZw==') + btoa('x')") == "flageA=="
    assert ev("'7' == 7") is True and ev("'7' === 7") is False and ev("null == undefined") is True
    assert ev("[1, 2] + ''") == "1,2" and ev("`n=${3 * 4}`") == "n=12"
    assert ev("'abc'.charCodeAt(5)") != ev("'abc'.charCodeAt(5)")      # NaN
    assert ev("[3, 1, 2].map(x => x * 2).reduce((a, b) => a + b, 0)") == 12
    assert ev("'5'.padStart(3, '0') + 'AbC'.toLowerCase()") == "005abc"
    assert ev("parseInt('ff', 16) + parseInt('12px')") == 267
    assert ev("1e21 + ''") == "1e+21" and ev("0.1 + ''") == "0.1"


def test_known_hashes_through_the_evaluator_match_the_native_ones():
    it = program(CYRB53_JS + """
      function djb2(s) { let h = 5381; for (let i = 0; i < s.length; i++) { h = ((h << 5) + h + s.charCodeAt(i)) | 0 } return h >>> 0 }
      function javaHash(s) { let h = 0; for (const c of s) h = (Math.imul(31, h) + c.charCodeAt(0)) | 0; return h }
      function fnv1a(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) } return h >>> 0 }""")
    # the public cyrb53 reference vectors, and the native implementation the engine uses
    for word, want in (("a", 7929297801672961), ("b", 8684336938537663), ("revenge", 4051478007546757),
                       ("revenue", 8309097637345594)):
        assert ev(f"cyrb53('{word}')", it) == want == cg.cyrb53(word)
    assert ev("cyrb53('revenge', 1)", it) == cg.cyrb53("revenge", 1) != cg.cyrb53("revenge")
    h = 5381
    for c in "hello":
        h = (h * 33 + ord(c)) & 0xFFFFFFFF
    assert ev("djb2('hello')", it) == h
    j = 0
    for c in "flag":
        j = (31 * j + ord(c)) & 0xFFFFFFFF
    assert ev("javaHash('flag')", it) == (j - (1 << 32) if j & 0x80000000 else j)
    f = 0x811C9DC5
    for c in b"flag":
        f = ((f ^ c) * 16777619) & 0xFFFFFFFF
    assert ev("fnv1a('flag')", it) == f
    assert ev("sha256('x')") == "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
    assert ev("CryptoJS.MD5('x').toString()") == "9dd4e461268c8034f5c8564e155c67a6"


def test_evaluator_is_bounded_and_has_no_host_objects():
    with pytest.raises(J.JsLimit):
        program("function f() { while (true) {} }").eval(J.parse_expression("f()"))
    with pytest.raises(J.JsLimit):
        program("function f(n) { return f(n + 1) }").eval(J.parse_expression("f(0)"))
    with pytest.raises(J.JsLimit):
        ev("'x'.repeat(1 << 30)")
    for host in ("document.cookie", "window.location", "fetch('/x')", "eval('1')", "Function('return 1')()",
                 "require('fs')", "process.env", "XMLHttpRequest", "localStorage.getItem('k')", "import_('x')"):
        with pytest.raises(J.Unresolved):
            ev(host)
    with pytest.raises(J.JsUnsupported):
        ev("({}).constructor = 1")
    with pytest.raises(J.JsUnsupported):
        ev("this.value")


# ---- the client-side gate (Hemophobia shape) ---------------------------------------------------------

def hemo_site(folder: Path, answer="spooky{wolfhowl}", text_file=None, extra_js="", check=None):
    """A saved page whose comment names a text file and the flag's shape, and whose script lowercases the
    input and compares cyrb53 of it with the answer's hash."""
    files = folder / "files"
    files.mkdir(parents=True, exist_ok=True)
    (files / "index.html").write_text(
        "<html><head><title>lost tune</title></head><!-- The tune is gone, but I wrote its name in "
        "lullaby.txt. The flag looks like spooky{beast} --><body><input id='flag'><button id='go'>go</button>"
        "<script src='script.js'></script></body></html>")
    check = check or "cyrb53(v) === FLAG_HASH"
    (files / "script.js").write_text(CYRB53_JS + f"""
const FLAG_HASH = {cg.cyrb53(answer)};
document.getElementById('go').addEventListener('click', () => {{
  const v = document.getElementById('flag').value.trim().toLowerCase();
  if ({check}) {{ alert('you escaped'); }} else {{ alert('still dreaming'); }}
}});
{extra_js}
""")
    if text_file is not None:
        (files / "lullaby.txt").write_text(text_file)
    return folder


def test_hash_gate_without_the_answer_is_unsure_and_says_what_to_do(tmp_path):
    res = cg.solve(hemo_site(tmp_path), SAVED, gate_steps=STEPS)
    assert res.status == "unsure" and res.flags == ()
    assert "gate in /script.js: cyrb53(<input>.trim().toLowerCase()) === " in res.notes
    assert "[cyrb53]" in res.notes
    assert "named but not read (fetch these next): /lullaby.txt" in res.notes
    # the flag-shaped placeholder in the comment fails the gate: it is a template, never a candidate
    assert "'spooky{beast}' is flag-shaped but every gate of the page rejects it" in res.notes
    assert "--opt candidates=" in res.notes


def test_hash_gate_confirms_an_explicit_candidate_inside_the_template(tmp_path):
    res = cg.solve(hemo_site(tmp_path), SAVED, gate_steps=STEPS, candidates="Lantern, WolfHowl")
    assert res.status == "solved" and res.flags == ("spooky{wolfhowl}",)
    assert res.evidence[0].kind == "oracle" and "near-misses fail it" in res.evidence[0].detail
    assert res.engine == "web.client_gate"


def test_hash_gate_finds_the_answer_in_a_saved_text_file_with_no_hint(tmp_path):
    site = hemo_site(tmp_path, answer="spooky{grey_wolf}", text_file="Last night's song: Grey Wolf (b-side)\n")
    res = cg.solve(site, SAVED, gate_steps=STEPS)
    assert res.status == "solved" and res.flags == ("spooky{grey_wolf}",)


def test_a_wrong_candidate_is_never_confirmed(tmp_path):
    res = cg.solve(hemo_site(tmp_path), SAVED, gate_steps=STEPS, candidates="wolfhowls,wolfhow,volfhowl")
    assert res.status == "unsure" and res.flags == ()


def test_a_non_discriminating_gate_never_proves_a_flag(tmp_path):
    # a length check accepts every 16-character input: a candidate it accepts is not proven
    site = hemo_site(tmp_path, check="v.length === 16")
    res = cg.solve(site, SAVED, gate_steps=STEPS, candidates="wolfhowl")
    assert res.status != "solved"
    assert "the gate also accepts near-misses of it" in res.notes


def test_the_evaluator_runs_an_unrecognized_hash_and_a_bent_cyrb53(tmp_path):
    # a bespoke hash no catalog knows: only the evaluator can run it
    files = tmp_path / "files"
    files.mkdir()
    (files / "index.html").write_text("<html><body><script>"
                                      "function mix(s){let h=7;for(let i=0;i<s.length;i++){h=(h*131+s.charCodeAt(i)*(i+1))%1000000007}return h}"
                                      "function check(guess){ return mix(guess) === TARGET }"
                                      f"const TARGET = {_mix('spooky{own_hash}')};"
                                      "</script><!-- answer: own hash --></body></html>")
    res = cg.solve(tmp_path, SAVED, gate_steps=STEPS)
    assert res.status == "solved" and res.flags == ("spooky{own_hash}",)
    # cyrb53's constants with a changed finalization: the native hash disagrees, the evaluator decides
    bent = CYRB53_JS.replace("h1 ^ (h1 >>> 16)", "h1 ^ (h1 >>> 15)")
    assert bent != CYRB53_JS
    target = int(program(bent).eval(J.parse_expression("cyrb53('spooky{bent}')")))
    assert target != cg.cyrb53("spooky{bent}")      # the native hash would never match this gate
    (files / "index.html").write_text(f"<html><body><script>{bent} const T = {target};"
                                      "function ok(x){ return cyrb53(x) == T }</script></body></html>")
    res = cg.solve(tmp_path, SAVED, gate_steps=STEPS, candidates="bent")
    assert res.status == "solved" and res.flags == ("spooky{bent}",)
    assert "the native cyrb53 disagreed with the evaluator" in res.notes


def _mix(s):
    h = 7
    for i, c in enumerate(s):
        h = (h * 131 + ord(c) * (i + 1)) % 1000000007
    return h


MIX_JS = "function mix(s){let h=7;for(let i=0;i<s.length;i++){h=(h*131+s.charCodeAt(i)*(i+1))%1000000007}return h}"


def _gate_report(js, explicit):
    return cg.analyze([cg.Source("/g.js", "script", js)], FF, SAVED, explicit=explicit, steps=STEPS)


def test_the_input_normalization_is_followed_through_a_variable_and_a_match_reported_normalized():
    # the page reads the field into a variable, normalizes it there, and hashes the variable
    js = (MIX_JS + "\nconst v = document.querySelector('#f').value.trim().toLowerCase();\n"
          f"if (mix(v) === {_mix('spooky{mixed_case}')}) ok()")
    rep = _gate_report(js, ["  spooky{MiXed_CaSe} "])
    gate = rep.gates[0]
    assert gate.norm == ("toLowerCase", "trim")
    assert cg.show(gate.probe) == "mix(<input>.trim().toLowerCase())"
    assert [(m.value, m.proof) for m in rep.matches] == [("spooky{mixed_case}", True)]


def test_near_misses_survive_a_case_folding_gate():
    # an upper-casing gate folds a letter near-miss (x -> X) back onto the value; digits do not fold
    js = MIX_JS + f"\nif (mix(inp.value.toUpperCase()) === {_mix('ABXCD')}) ok()"
    rep = _gate_report(js, ["abXcd"])
    assert [(m.value, m.proof) for m in rep.matches] == [("ABXCD", True)]


def test_string_operations_on_the_input_stay_in_the_probe():
    js = "if (inp.value.toLowerCase().split('').reverse().join('') === 'galf') ok()"
    rep = _gate_report(js, ["FLAG", "flag"])
    gate = rep.gates[0]
    assert gate.kind == "transform"
    assert cg.show(gate.probe).startswith("<input>.toLowerCase().split(")
    assert [m.value for m in rep.matches] == ["flag"]


def test_script_comments_and_a_source_map_are_harvested(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "index.html").write_text("<html><script src='app.js'></script></html>")
    (files / "app.js").write_text("// TODO move the key out of vault.txt\nvar a=1;\n//# sourceMappingURL=app.js.map\n")
    res = cg.solve(tmp_path, SAVED, gate_steps=STEPS)
    assert "comment /app.js: 'TODO move the key out of vault.txt'" in res.notes
    assert "/vault.txt" in res.notes and "/app.js.map" in res.notes.split("named but not read")[1]
    # the saved map carries the original source, and the gate is in it
    import json
    original = MIX_JS + f"\nexport function check(x) {{ return mix(x) === {_mix('spooky{from_the_map}')} }}"
    (files / "app.js.map").write_text(json.dumps({"version": 3, "sources": ["webpack://src/check.js"],
                                                  "sourcesContent": [original], "mappings": ""}))
    res = cg.solve(tmp_path, SAVED, gate_steps=STEPS, candidates="from_the_map")
    assert res.status == "solved" and res.flags == ("spooky{from_the_map}",)
    assert "gate in /app.js.map!" in res.evidence[0].detail


def test_equality_gates_give_their_constant(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "a.html").write_text("<html><script>function go(){ if (document.forms[0].pw.value === "
                                  "atob('c3Bvb2t5e3BsYWluX3NpZ2h0fQ==')) unlock() }</script></html>")
    res = cg.solve(tmp_path, SAVED, gate_steps=STEPS)
    assert res.status == "solved" and res.flags == ("spooky{plain_sight}",)
    assert res.evidence[0].kind == "match"
    (files / "a.html").write_text("<html><script>function go(){ if (input.value.toLowerCase() == 'letmein') "
                                  "show() }</script></html>")
    res = cg.solve(tmp_path, SAVED, gate_steps=STEPS)
    assert res.status == "candidate" and res.flags == ("letmein",)
    assert "equality gate in /a.html#script1: the expected input is 'letmein'" in res.notes


def _one_page(tmp_path, html):
    files = tmp_path / "files"
    files.mkdir(exist_ok=True)
    (files / "index.html").write_text(html)
    return tmp_path


def test_a_flag_revealed_after_a_password_check_is_kept_not_called_a_decoy(tmp_path):
    # the page checks a password and then shows the flag: the flag is not the gate's input
    site = _one_page(tmp_path, "<html><script>function go(){ if (pw.value === 'letmein') "
                               "body.innerHTML = 'spooky{revealed_after_check}' }</script></html>")
    res = cg.solve(site, SAVED, gate_steps=STEPS)
    assert res.status == "candidate"
    assert set(res.flags) == {"letmein", "spooky{revealed_after_check}"}
    assert "every gate of the page rejects it" not in res.notes
    # the same password gate with the flag left in a comment: the gate does not check the flag either
    _one_page(tmp_path, "<html><!-- spooky{left_in_a_comment} --><script>function go(){ "
                        "if (pw.value === 'letmein') unlock() }</script></html>")
    res = cg.solve(site, SAVED, gate_steps=STEPS)
    assert set(res.flags) == {"letmein", "spooky{left_in_a_comment}"}


def test_a_flag_revealed_after_a_hash_check_is_kept_and_the_comment_template_refuted(tmp_path):
    # a hash gate on the flag: the comment's placeholder fails it (refuted), but the flag the script
    # writes on success, in a string or base64 in a string, is the page's output and stays a candidate
    reveal = base64.b64encode(b"spooky{decoded_reveal}").decode()
    site = _one_page(tmp_path, "<html><!-- the flag looks like spooky{beast} --><script>" + CYRB53_JS
                     + f"if (cyrb53(f.value) === {cg.cyrb53('spooky{not_here}')}) {{ out.textContent = "
                       f"'spooky{{script_reveal}}'; note.textContent = atob('{reveal}') }}</script></html>")
    res = cg.solve(site, SAVED, gate_steps=STEPS)
    assert {"spooky{script_reveal}", "spooky{decoded_reveal}"} <= set(res.flags)
    assert "spooky{beast}" not in res.flags
    assert "'spooky{beast}' is flag-shaped but every gate of the page rejects it" in res.notes
    # a flag that is in a comment and also in the script's code is the script's output: kept
    _one_page(tmp_path, "<html><!-- shows spooky{both_places} --><script>" + CYRB53_JS
              + f"if (cyrb53(f.value) === {cg.cyrb53('spooky{not_here}')}) out.textContent = 'spooky{{both_places}}'"
              "</script></html>")
    res = cg.solve(site, SAVED, gate_steps=STEPS)
    assert "spooky{both_places}" in res.flags and "rejects it" not in res.notes


def test_a_hash_gate_proven_on_a_password_refutes_no_flag(tmp_path):
    # the hash gate accepts 'letmein' (not flag-shaped): it checks a password, so the comment flag stands
    site = _one_page(tmp_path, "<html><!-- spooky{the_real_one} --><p>try letmein</p><script>" + MIX_JS
                     + f"if (mix(pw.value) === {_mix('letmein')}) unlock()</script></html>")
    res = cg.solve(site, SAVED, gate_steps=STEPS)
    assert "letmein" in res.flags and "spooky{the_real_one}" in res.flags
    assert "rejects it" not in res.notes


def test_an_equality_gate_on_a_flag_refutes_the_other_comment_flags(tmp_path):
    site = _one_page(tmp_path, "<html><!-- spooky{fake_one} --><script>function go(){ "
                               "if (pw.value === 'spooky{true_one}') ok() }</script></html>")
    res = cg.solve(site, SAVED, gate_steps=STEPS)
    assert res.status == "solved" and res.flags == ("spooky{true_one}",)
    assert "'spooky{fake_one}' is flag-shaped but every gate of the page rejects it" in res.notes


def test_a_flag_shaped_string_with_no_gate_is_a_candidate_not_solved(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "index.html").write_text("<html><!-- old: spooky{maybe_this} --><script>var x = 1;</script></html>")
    res = cg.solve(tmp_path, SAVED, gate_steps=STEPS)
    assert res.status == "candidate" and res.flags == ("spooky{maybe_this}",)


def test_numeric_arrays_go_through_the_b094_reader_and_the_gate(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    codes = [ord(c) + 3 for c in "spooky{shifted}"]
    (files / "index.html").write_text(f"<html><script>const k = [{', '.join(map(str, codes))}];</script></html>")
    res = cg.solve(tmp_path, SAVED, gate_steps=STEPS)
    assert res.status == "candidate" and "spooky{shifted}" in res.flags
    # with a gate the decode must pass it: here it does, so it is solved
    (files / "index.html").write_text(f"<html><script>const k = [{', '.join(map(str, codes))}];"
                                      + CYRB53_JS + f"if (cyrb53(inp.value) === {cg.cyrb53('spooky{shifted}')}) ok()"
                                      "</script></html>")
    res = cg.solve(tmp_path, SAVED, gate_steps=STEPS)
    assert res.status == "solved" and res.flags == ("spooky{shifted}",)


# ---- the custom-encoding recognizer (Gelotophobia shape) -------------------------------------------

JOKES = ("pirate", "oven", "doctor", "coffee", "ghost")


def geloto_site(folder: Path, encode=ee_token, keys=JOKES, prefix="/jokes/"):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "index.html").write_text("<html><body><ul id='jokes'></ul><script src='testindex.js'></script></body></html>")
    toks = ", ".join(f"'{encode(k)}'" for k in keys)
    (folder / "testindex.js").write_text(f"const jokes = [{toks}];\n"
                                         f"function show(t) {{ return fetch('{prefix}' + t).then(r => r.text()); }}\n"
                                         "jokes.forEach(t => show(t));\n")
    return folder


def test_two_letter_bit_encoding_is_recognized_inverted_and_the_hidden_key_routed(tmp_path):
    res = cg.solve(geloto_site(tmp_path), SAVED)
    assert res.status == "unsure"
    assert "recognized encoding b64(pad)+sym2lo(pair)+bin16(16): 5 token(s) decode to keys" in res.notes
    for k in JOKES:
        assert repr(k) in res.notes
    flag_tok = ee_token("flag")
    assert f"hidden key 'flag' -> {flag_tok[:90]} -> try /jokes/{flag_tok}" in res.notes


def test_the_inverse_is_chosen_to_reproduce_the_observed_tokens(tmp_path):
    # the other polarity (0 written as the higher letter) and unpadded base64
    def enc(k):
        return ee_token(k, zero="x", one="Q").rstrip("=")
    sources = [cg.Source("/a.js", "script", "const t = [" + ",".join(f"'{enc(k)}'" for k in JOKES) + "];"
                         " const u = '/api/' + t[0];")]
    rep = cg.analyze(sources, FF, SAVED, steps=STEPS)
    enc_ = [e for e in rep.encodings if e.verified]
    assert len(enc_) == 1 and enc_[0].chain == ("b64", "sym2hi", "bin16")
    assert enc_[0].how == "b64(nopad)+sym2hi(pair)+bin16(16)"
    hidden = {k: (tok, routes) for k, tok, routes in enc_[0].hidden}
    assert hidden["flag"][0] == enc("flag")
    assert "/api/" + enc("flag") in hidden["flag"][1]


def test_hidden_keys_follow_the_case_of_the_observed_keys():
    def tokens(keys):
        return [cg.Source("/a.js", "script", "const t = [" + ",".join(f"'{ee_token(k)}'" for k in keys) + "];")]
    upper = cg.analyze(tokens([k.upper() for k in JOKES]), FF, SAVED, steps=STEPS)
    hidden = {k: tok for e in upper.encodings if e.verified for k, tok, _ in e.hidden}
    assert hidden and "FLAG" in hidden and "flag" not in hidden
    assert hidden["FLAG"] == ee_token("FLAG")
    lower = cg.analyze(tokens(JOKES), FF, SAVED, steps=STEPS)
    hidden = {k: tok for e in lower.encodings if e.verified for k, tok, _ in e.hidden}
    assert "flag" in hidden and "FLAG" not in hidden and hidden["flag"] == ee_token("flag")
    mixed = cg.analyze(tokens(["Pirate", "Oven", "Doctor"]), FF, SAVED, steps=STEPS)
    hidden = {k for e in mixed.encodings if e.verified for k, _, _ in e.hidden}
    assert "flag" in hidden and "admin_panel" in hidden      # mixed case: the default keys as written


def test_invert_refuses_when_no_variant_reproduces_every_token():
    samples = [(base64.b64encode(b"abcdef").decode(), "abcdef"), ("bm90IGl0", "pirate")]
    enc, why = cg.invert(("b64",), samples, C_CODECS, ())
    assert enc is None and "re-encodes every observed token" in why
    enc, how = cg.invert(("b64",), samples[:1], C_CODECS, ())
    assert enc("flag") == "ZmxhZw==" and how == "b64(pad)"


C_CODECS = cg.engine_codecs() + tuple(__import__("ctf.codec", fromlist=["core"]).core())


def test_a_custom_base64_alphabet_in_the_script_is_used_and_inverted(tmp_path):
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alpha = std[13:] + std[:13]
    table = str.maketrans(std, alpha)

    def enc(k):
        return base64.b64encode(k.encode()).decode().rstrip("=").translate(table)
    src = cg.Source("/m.js", "script", f"const ALPHA = '{alpha}';\nconst keys = ["
                    + ",".join(f"'{enc(k)}'" for k in ("treasure", "scarecrow", "pumpkins")) + "];")
    rep = cg.analyze([src], FF, SAVED, steps=STEPS)
    verified = [e for e in rep.encodings if e.verified]
    assert verified and verified[0].chain == ("b64alpha0",)
    assert dict((k, t) for k, t, _ in verified[0].hidden)["flag"] == enc("flag")


def test_keylike_accepts_keys_and_refuses_encoded_intermediates():
    for ok in (b"pirate", b"coffee", b"admin_panel", b"secretKey", b"flag"):
        assert cg.keylike(ok) == ok.decode()
    for bad in (b"EEEEeeeEEEEeeeEe", b"RUVFRUVF", b"aGVsbG8=", b"x", b"\x00flag", b"zzzz", b"bcdfghjk",
                b" flag", b"a" * 41, b"ZmxhZ3tlbmNvZGVkfQ"):
        assert not cg.keylike(bad), bad


def test_decode_tokens_reports_a_flag_hidden_in_a_script_string():
    tok = base64.b64encode(base64.b64encode(b"spooky{double_wrapped}")).decode()
    decoded, _ = cg.decode_tokens([("/s.js", ["harmless words", tok, "addEventListener"])], SAVED)
    assert [(d.answer, d.chain, d.oracle) for d in decoded] == [("spooky{double_wrapped}", ("b64", "b64"), "flag")]


# ---- live (fake loopback server) -------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.server.seen.append(("GET", self.path))
        page = self.server.pages.get(self.path.split("?")[0])
        if page is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"no such joke")
            return
        ctype, body = page
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.server.seen.append(("POST", self.path))
        self.send_response(405)
        self.end_headers()


@contextmanager
def serve(pages):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.pages, server.seen = pages, []
    server.handle_error = lambda *_a: None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


HTML, JS, TXT = "text/html", "application/javascript", "text/plain"


def test_live_mirror_reads_the_named_file_and_confirms_the_gate():
    answer = "spooky{night_choir}"
    pages = {
        "/": (HTML, b"<html><!-- the song is written in nightsong.txt; the flag looks like spooky{band} -->"
                    b"<script src='/static/check.js'></script></html>"),
        "/static/check.js": (JS, (CYRB53_JS + f"if (cyrb53(q.value.toLowerCase()) === {cg.cyrb53(answer)}) win()").encode()),
        "/nightsong.txt": (TXT, b"It was sung by the Night Choir, long ago."),
    }
    with serve(pages) as (server, url):
        res = cg.solve(Path("."), LIVE, url=url + "/", gap=0, gate_steps=STEPS)
        seen = list(server.seen)
    assert res.status == "solved" and res.flags == (answer,)
    assert {m for m, _ in seen} == {"GET"}
    assert [p for _, p in seen][:1] == ["/"] and "/nightsong.txt" in [p for _, p in seen]


def test_live_hidden_key_route_is_requested_and_its_flag_banked_as_solved():
    flag = "spooky{the_unlisted_one}"
    toks = [ee_token(k) for k in JOKES]
    js = ("const jokes = [" + ",".join(f"'{t}'" for t in toks) + "];\n"
          "const load = k => fetch('/jokes/' + k).then(r => r.text());\n").encode()
    pages = {"/": (HTML, b"<html><script src='/app.js'></script></html>"), "/app.js": (JS, js)}
    pages.update({f"/jokes/{t}": (TXT, b"why did the ghost cross the road?") for t in toks})
    pages[f"/jokes/{ee_token('flag')}"] = (TXT, flag.encode())
    with serve(pages) as (server, url):
        res = cg.solve(Path("."), LIVE, url=url + "/", gap=0, gate_steps=STEPS)
        seen = list(server.seen)
    assert res.status == "solved" and res.flags == (flag,)
    assert res.evidence[0].kind == "wire" and "the hidden key 'flag'" in res.evidence[0].detail
    assert ("GET", f"/jokes/{ee_token('flag')}") in seen
    assert {m for m, _ in seen} == {"GET"}


def test_live_is_refused_when_the_event_does_not_allow_the_host_and_nothing_is_sent():
    with serve({"/": (HTML, b"<html></html>")}) as (server, url):
        res = cg.solve(Path("."), SAVED, url=url + "/", gap=0)
        seen = list(server.seen)
    assert res.status == "blocked" and "rules.live_service_scope" in res.notes
    assert "Save the page" in res.notes
    assert seen == []


def test_live_request_budget_is_kept():
    pages = {"/": (HTML, b"<html><!-- see a.txt b.txt c.txt d.txt e.txt --></html>")}
    pages.update({f"/{c}.txt": (TXT, b"nothing") for c in "abcde"})
    with serve(pages) as (server, url):
        res = cg.solve(Path("."), LIVE, url=url + "/", gap=0, max_requests=3, gate_steps=STEPS)
        seen = list(server.seen)
    assert len(seen) == 3
    assert "referenced route(s) not mirrored: the request budget (3) ran out" in res.notes


def _geloto_pages(prefix="/jokes/", flag_page=False):
    toks = [ee_token(k) for k in JOKES]
    js = ("const jokes = [" + ",".join(f"'{t}'" for t in toks) + "];\n"
          f"const load = k => fetch('{prefix}' + k).then(r => r.text());\n").encode()
    pages = {"/": (HTML, b"<html><script src='/app.js'></script></html>"), "/app.js": (JS, js)}
    if flag_page:
        pages[f"{prefix}{ee_token('flag')}"] = (TXT, b"spooky{never_fetched}")
    return pages


def test_live_hidden_routes_share_the_request_budget_with_the_mirror():
    # the mirror spends 2 GETs (/ and /app.js); 15 default keys x 2 route templates want far more
    with serve(_geloto_pages()) as (server, url):
        res = cg.solve(Path("."), LIVE, url=url + "/", gap=0, max_requests=5, gate_steps=STEPS)
        seen = list(server.seen)
    assert [p for _, p in seen][:2] == ["/", "/app.js"]
    assert len(seen) == 5                                  # 2 mirror + 3 hidden, never more
    assert "the hidden-route budget ran out before every encoded key was requested" in res.notes


def test_live_hidden_probe_stops_on_a_key_once_its_first_route_answers_a_flag():
    # the script gives two route templates (/jokes/<tok> and /<tok>); 'flag' answers on the first, so its
    # second route is never requested and that GET goes to the next key instead
    flag = "spooky{first_template_hit}"
    pages = _geloto_pages()
    pages[f"/jokes/{ee_token('flag')}"] = (TXT, flag.encode())
    with serve(pages) as (server, url):
        res = cg.solve(Path("."), LIVE, url=url + "/", gap=0, max_requests=40, gate_steps=STEPS)
        seen = [p for _, p in server.seen]
    every = [r for k in cg.DEFAULT_KEYS if k not in JOKES for r in (f"/jokes/{ee_token(k)}", f"/{ee_token(k)}")]
    expected = [r for r in every if r != f"/{ee_token('flag')}"][:cg.MAX_HIDDEN_ROUTES]
    assert seen[:2] == ["/", "/app.js"]
    assert f"/{ee_token('flag')}" not in seen
    assert seen[2:] == expected                            # exactly the hidden-route budget, the hit's twin skipped
    assert res.status == "solved" and res.flags == (flag,)
    wire = [e for e in res.evidence if e.kind == "wire"]
    assert len(wire) == 1 and f"GET /jokes/{ee_token('flag')}" in wire[0].detail


def test_live_never_requests_a_state_changing_route():
    # a comment names a destructive file, and the script puts its tokens under /logout/: the mirror and
    # the hidden-key probe both skip them, and say so; the root template /<token> is still tried
    pages = _geloto_pages(prefix="/logout/", flag_page=True)
    pages["/"] = (HTML, b"<html><!-- cleanup: delete_all.txt; notes in readme.txt --><script src='/app.js'>"
                        b"</script></html>")
    pages["/delete_all.txt"] = (TXT, b"gone")
    pages["/readme.txt"] = (TXT, b"nothing here")
    with serve(pages) as (server, url):
        res = cg.solve(Path("."), LIVE, url=url + "/", gap=0, max_requests=40, gate_steps=STEPS)
        seen = [p for _, p in server.seen]
    assert "/readme.txt" in seen                           # the harmless reference is mirrored
    assert "/delete_all.txt" not in seen
    assert not any(p.startswith("/logout/") for p in seen)
    assert f"/{ee_token('flag')}" in seen                  # the hidden key went to the safe template
    assert "/delete_all.txt: not requested (names a state-changing action)" in res.notes
    assert "hidden route(s) not requested (they name a state-changing action): /logout/" in res.notes
    assert "spooky{never_fetched}" not in res.flags


def test_live_mirror_follows_references_two_links_deep_and_no_further():
    pages = {
        "/": (HTML, b"<html><script src='/a.js'></script></html>"),
        "/a.js": (JS, b"const notes = fetch('/x.txt');"),
        "/x.txt": (TXT, b"the rest is in /y.txt"),
        "/y.txt": (TXT, b"spooky{too_deep}"),
    }
    with serve(pages) as (server, url):
        res = cg.solve(Path("."), LIVE, url=url + "/", gap=0, gate_steps=STEPS)
        seen = [p for _, p in server.seen]
    assert seen == ["/", "/a.js", "/x.txt"]
    assert "named but not read (fetch these next): /y.txt" in res.notes


# ---- saved-run plumbing and wiring -------------------------------------------------------------------

def test_no_saved_pages_is_blocked_with_a_named_reason(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "pic.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 32)
    res = cg.solve(tmp_path, SAVED)
    assert res.status == "blocked" and "no saved page, script or text file under" in res.notes
    res = cg.solve(tmp_path, SAVED, saved=str(tmp_path / "missing"))
    assert res.status == "blocked" and "no saved-pages folder at" in res.notes


def test_the_saved_folder_option_reads_pages_elsewhere(tmp_path):
    site = hemo_site(tmp_path / "elsewhere")
    res = cg.solve(tmp_path, SAVED, saved=str(site), candidates="wolfhowl", gate_steps=STEPS)
    assert res.status == "solved" and res.flags == ("spooky{wolfhowl}",)


def test_saved_pages_never_read_dot_folders(tmp_path):
    site = hemo_site(tmp_path / "saved")
    files = site / "files"
    for hidden in (files / ".ctf" / "notes.txt", files / ".env", files / "deep" / ".cache" / "seen.txt"):
        hidden.parent.mkdir(parents=True, exist_ok=True)
        hidden.write_text("spooky{from_a_dot_folder} wolfhowl")
    (files / "deep" / "visible.txt").write_text("spooky{a_saved_note}")
    sources, notes = cg.saved_sources(site)
    routes = {s.route for s in sources}
    assert routes == {"/index.html", "/script.js", "/deep/visible.txt"}
    assert "3 file(s) under a dot-folder or with a dot-name (.ctf/, .env, ...) not read" in notes
    res = cg.solve(tmp_path, SAVED, saved=str(site), gate_steps=STEPS)
    assert "spooky{from_a_dot_folder}" not in res.flags and "spooky{a_saved_note}" in res.flags
    assert "spooky{wolfhowl}" not in res.flags     # the gate's answer sits only in the dot-files


def test_evaluator_budget_bounds_the_gate_search(tmp_path):
    # a hash only the evaluator can run, the answer last among many candidates: a tiny budget stops early
    files = tmp_path / "files"
    files.mkdir()
    words = " ".join(f"word{i}" for i in range(300))
    (files / "index.html").write_text("<html><!-- " + words + " zebra --><script>"
                                      "function mix(s){let h=7;for(let i=0;i<s.length;i++){h=(h*131+s.charCodeAt(i)*(i+1))%1000000007}return h}"
                                      f"if (mix(f.value) === {_mix('zebra')}) ok()</script></html>")
    res = cg.solve(tmp_path, SAVED, gate_steps=20_000)
    assert res.status != "solved" and "step budget (20000) ran out" in res.notes
    res = cg.solve(tmp_path, SAVED, gate_steps=STEPS)
    assert res.status == "candidate" and "zebra" in res.flags     # not in the flag format: a candidate


def test_route_and_manifest_wiring():
    from ctf.engines import manifest as M
    from ctf.engines import router
    m = M.load(Path(cg.__file__).with_suffix(".manifest.toml"))
    assert m.id == "web.client_gate" and m.entry_raw == "solvers.web.client_gate:solve" and m.intake is not None
    picks = router.route("web", "the page checks the flag in the browser with a javascript check")
    assert picks and picks[0].manifest.id == "web.client_gate"
    assert all(h.manifest.id != "web.client_gate" for h in router.route("web", "a plain login form"))
