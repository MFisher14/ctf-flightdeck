#!/usr/bin/env python3
"""Script Analysis language-identification coverage: crib-based recognition of languages and packaging
idioms the lane has not shipped a module for, for the `language` / `next-language` fields and nothing else.

Why this file exists (Day 23 look-ahead, 2026-10-23). The polyglot specimens store a version-3 plan whose
`language=` and `next_language=` are plain strings in the judge's own vocabulary (`xslt`, `terraform_hcl`,
`csx`, `google_apps_script`, `perl`, ...). When the descriptor decodes, the general path (plan_codec /
generic) reads those two fields plain and this file does nothing. The gap this file closes is the OTHER
case, the one that cost Day 23 time: a specimen in a language the lane has no module for whose descriptor
does NOT decode cleanly (a SPLIT / two-plan polyglot, an obfuscated or stripped body), so the `-language`
and `-next-language` ids come back None and need morning-of adaptation. For such an id this file offers an
evidence-ranked, crib-based language name as an UNSURE answer (labels.pick): spellings of the one language
its live cribs establish, judge-observed spellings first, probed by tools/verify.py on the untimed base and
by the runners only on an attempt with no deadline. It never answers plain and never invents a fact: a
language-name label is the author's vocabulary, so it is always unsure until the judge accepts a spelling.

Covered (cheap, high-value, under-covered as of Day 23):
  - Godot GDScript  (`.gd`): `extends`, `func`, `signal`, `@export`/`@onready`/`onready var`, `res://`,
                    `preload(`, `_ready(`/`_process(`, `$NodePath`. Obfuscated bodies (string/const blobs,
                    `char()`/PackedByteArray joins) still carry the structural keywords, which is what is read.
  - C# script       (`.csx`, and csx embedded in an .aspx/.cshtml/.ashx string): the script directives
                    `#r "..."` / `#load "..."` (unique to csx), top-level `using System;` with
                    `Console.WriteLine(`/`var x =` and no `namespace`/`class` wrapper, `CSharpScript`.
  - Terraform HCL   (`.tf`): `resource "x" "y" {`, `provider "x" {`, `variable/module/data/output/terraform`
                    block headers, `= var.`, interpolation `${...}`.
  - XSLT            (`.xsl`, `.xslt`): `<xsl:stylesheet`/`<xsl:transform`, `xmlns:xsl=".../Transform"`,
                    `<xsl:template`, `<xsl:value-of`, `<xsl:for-each`.

Never wrong (AGENTS.md, "Uncertain answers"):
  - cribs are counted on LIVE code only: comments (`#`, `//`, `/* */`, `<!-- -->`) and string literals are
    blanked first, so a language's signature sitting in another language's comment or dead string is a decoy
    and is not read (the csx-in-string path is the one deliberate look inside a string, and only in a host).
  - a language is identified only when EXACTLY ONE of the covered languages reaches its crib threshold; when
    two do (an ambiguous polyglot) the answer is None.
  - the answer is always labels.pick (unsure); a brand-new `script.language/<ext>.cribs` key never has an
    accepted name, so pick returns the unsure string. Nothing here is ever plain.

Entry points (this file ships under its own name and is INERT in the live solver: analyze.py loads
`lang_<ext>.py`, `shapes_<ext>.py` and `day_patch.py` by name, never this file). The variant-proof language
knowledge is made live, with no edit to any shipped solver, by copying the three lines the docstring of
`overrides` shows into the lane's `day_patch.py` (which analyze.py calls last for every specimen):

    identify(text)                      -> canonical language key (e.g. "godot_gdscript") or None
    options_for(lang_key)               -> ordered spelling candidates, judge-observed first
    language_pick(ext, text, field)     -> labels.pick string (unsure) for a `-language`/`-next-language`
                                           id, or None when no single language is established
    embedded_csx(text)                  -> (snippet, "csx") when a host string literal holds a C# script,
                                           else None  (the csx-in-string / csx-in-aspx case)
    overrides(member, questions, answers, files, find=None) -> {qid: pick} for the language ids a reader
                                           left None/unsure; a day_patch.py calls this and returns its result

CLI (offline, no Game Master):  .venv/bin/python solvers/script-analysis/gdscript_csx_langs.py <file> ...
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


# --------------------------------------------------------------------------- comment / string blanking

def _keep(ch: str) -> str:
    """A character blanked to a space, newlines kept, so line-anchored cribs and line counts stay honest."""
    return ch if ch == "\n" else " "


def live_code(text: str) -> str:
    """`text` with comments (`/* */`, `<!-- -->`, `//`, `#`) and string literals blanked, newlines kept.

    A single left-to-right scanner, so a `//` inside a URL inside a string and a `"` inside a comment do not
    cross-contaminate (the bug a regex pass has). This defeats the decoy shapes the break-it battery
    synthesizes: a language's signature cribs inside a comment or a string of another language no longer
    count toward identification. The C# SCRIPT directives `#r` / `#load` and a `#!` shebang are kept (not
    treated as `#` comments), so the strongest csx cribs survive; their trailing string is still blanked."""
    if not isinstance(text, str):
        return ""
    out = []
    i, n = 0, len(text)
    at_line_start = True                      # True until a non-space character on the current line
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        three = text[i:i + 3]
        # ---- comments ----
        if three == "<!-":  # noqa: SIM114 - keep each comment kind explicit
            if text[i:i + 4] == "<!--":
                j = text.find("-->", i + 4)
                j = n if j < 0 else j + 3
                out.append("".join(_keep(ch) for ch in text[i:j])); i = j; at_line_start = False; continue
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(_keep(ch) for ch in text[i:j])); i = j; at_line_start = False; continue
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j; continue
        if c == "#" and not (text[i:i + 2] == "#!" or re.match(r"#r[ \t\"]|#load[ \t\"]", text[i:i + 6])):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j; continue
        # ---- strings ----
        if c == "@" and text[i + 1:i + 2] == '"':          # C# verbatim @"..."  ("" is an escaped quote)
            j = i + 2
            while j < n:
                if text[j] == '"':
                    if text[j + 1:j + 2] == '"':
                        j += 2; continue
                    j += 1; break
                j += 1
            out.append("".join(_keep(ch) for ch in text[i:j])); i = j; at_line_start = False; continue
        if three in ('"""', "'''"):
            q = three
            j = text.find(q, i + 3)
            j = n if j < 0 else j + 3
            out.append("".join(_keep(ch) for ch in text[i:j])); i = j; at_line_start = False; continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n) if j < n and text[j] == c else j
            out.append("".join(_keep(ch) for ch in text[i:j])); i = j; at_line_start = False; continue
        out.append(c)
        if c == "\n":
            at_line_start = True
        elif not c.isspace():
            at_line_start = False
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------- the covered languages

# Each language: a list of (regex, weight) strong cribs read on LIVE code, a MULTILINE flag, the minimum
# total weight to count it present, and the ordered spelling candidates (judge-observed spelling first).
LANGS = {
    "godot_gdscript": {
        "min": 2,
        "cribs": [
            (r"^[ \t]*extends[ \t]+\w", 2),
            (r"^[ \t]*func[ \t]+\w+[ \t]*\(", 1),
            (r"^[ \t]*signal[ \t]+\w", 2),
            (r"@export\b|@onready\b|^[ \t]*onready[ \t]+var\b", 2),
            (r"\bpreload[ \t]*\(|res://", 2),
            (r"^[ \t]*func[ \t]+_(?:ready|process|physics_process|init)[ \t]*\(", 2),
            (r"\bget_node[ \t]*\(|\$\w", 1),
            (r"\bvar[ \t]+\w+[ \t]*:=|\bPackedByteArray\b|\bNode2?D?\b", 1),
        ],
        "options": ["godot_gdscript", "gdscript", "godot", "gd_script"],
    },
    "csx": {
        "min": 2,
        "cribs": [
            (r"^[ \t]*#r\b", 3),      # the string after it is blanked by live_code; the directive survives
            (r"^[ \t]*#load\b", 3),
            (r"\bCSharpScript\b|\bScript\.RunAsync\b|\bRoslyn\b", 3),
            (r"\busing[ \t]+System\b", 1),
            (r"\bConsole[ \t]*\.[ \t]*(?:WriteLine|Write)[ \t]*\(", 1),
            (r"\bvar[ \t]+\w+[ \t]*=", 1),
            (r"\bawait[ \t]+\w", 1),
        ],
        "options": ["csx", "csharp_script", "dotnet_script", "csharp", "cs_script"],
    },
    "terraform_hcl": {
        "min": 2,
        "cribs": [
            # live_code() blanks string literals, so the quoted names are spaces by the time these are read
            (r'^[ \t]*(?:resource|data)[ \t]+\{', 3),
            (r'^[ \t]*(?:provider|variable|module|output)[ \t]+\{', 2),
            (r"^[ \t]*terraform[ \t]*\{", 2),
            (r"=[ \t]*var\.\w|=[ \t]*local\.\w|=[ \t]*data\.\w", 1),
            (r"\$\{[^}]+\}", 1),
        ],
        "options": ["terraform_hcl", "hcl", "terraform", "tf"],
    },
    "xslt": {
        "min": 2,
        "cribs": [
            (r"<xsl:stylesheet\b|<xsl:transform\b", 3),
            (r'xmlns:xsl[ \t]*=[ \t]*"[^"]*/Transform"', 3),
            (r"<xsl:template\b", 2),
            (r"<xsl:value-of\b|<xsl:for-each\b|<xsl:apply-templates\b|<xsl:call-template\b", 1),
            (r"<xsl:variable\b|<xsl:param\b|<xsl:choose\b|<xsl:if\b", 1),
        ],
        "options": ["xslt", "xsl", "xslt_stylesheet", "xsl_transform"],
    },
    # ---- Day 24 look-ahead (build night 2026-10-23): further languages and packagings a polyglot day may add.
    # Every one is unsure-only (labels.pick under the same key); min weight 4 so one stray word never counts.
    "lua": {
        "min": 4,
        "cribs": [
            (r"^[ \t]*local[ \t]+function[ \t]+\w+", 3),
            (r"^[ \t]*function[ \t]+[\w.:]+[ \t]*\([^)]*\)[ \t]*$", 2),
            (r"\bthen[ \t]*$|^[ \t]*elseif\b", 2),
            (r"\bmath\.random\b|\bstring\.(?:format|char|byte|rep)\b|\bio\.open\b|\bos\.execute\b|\bloadstring\b", 2),
            (r"^[ \t]*local[ \t]+\w+[ \t]*=", 1),
            (r"\bipairs\b|\bpairs[ \t]*\(", 1),
        ],
        "need": [r"^[ \t]*local[ \t]+function\b|\bthen[ \t]*$|^[ \t]*elseif\b|\bipairs\b|\bstring\.(?:format|char|byte|rep)\b|\bio\.open\b|\bos\.execute\b|\bloadstring\b|\bmath\.random\b"],
        "neg": [r"^[ \t]*(?:def|class|import|from)[ \t]+\w+.*:[ \t]*$", r";[ \t]*$", r"\bfunction[ \t]*\([^)]*\)[ \t]*\{"],
        "options": ["lua", "lua_script", "luau"],
    },
    "applescript": {
        "min": 4,
        "cribs": [
            (r"^[ \t]*tell[ \t]+application\b", 3),
            (r"^[ \t]*end[ \t]+tell\b", 2),
            (r"\bdo[ \t]+shell[ \t]+script\b", 3),
            (r"^[ \t]*set[ \t]+\w+[ \t]+to\b", 1),
            (r"\bosascript\b|\bPOSIX[ \t]+file\b", 1),
        ],
        "options": ["applescript", "osascript", "apple_script"],
    },
    "dockerfile": {
        "min": 4,
        "cribs": [
            (r"^FROM[ \t]+\S+", 2),
            (r"^RUN[ \t]+\S+", 2),
            (r"^(?:ENTRYPOINT|CMD)[ \t]+[\[\w]", 2),
            (r"^(?:COPY|ADD|WORKDIR|EXPOSE|ENV|ARG|USER)[ \t]+\S+", 1),
        ],
        "options": ["dockerfile", "docker", "containerfile"],
    },
    "makefile": {
        "min": 4,
        "cribs": [
            (r"^\.PHONY[ \t]*:", 3),
            (r"^[\w.-]+[ \t]*:(?!=)[^\n=]*\n(?:\t[^\n]+\n?)+", 3),
            (r"\$\((?:CC|CFLAGS|MAKE|SHELL|\w+)\)|\$@|\$<|\$\^", 1),
            (r"^[A-Z_]+[ \t]*[:?+]?=[ \t]*\S", 1),
        ],
        "need": [r"^\.PHONY[ \t]*:|^[\w.-]+[ \t]*:(?!=)[^\n=]*\n\t[^\n]+"],
        "neg": [r"^[ \t]*(?:def|class|import|from)[ \t]+\w+", r"^jobs:[ \t]*$"],
        "options": ["makefile", "make", "gnu_make"],
    },
    "ansible_yaml": {
        "min": 4,
        "cribs": [
            (r"^---[ \t]*$", 1),
            (r"^[ \t-]*hosts:[ \t]*\S+", 2),
            (r"^[ \t]*tasks:[ \t]*$", 2),
            (r"^[ \t]*-[ \t]+name:[ \t]*\S", 2),
            (r"^[ \t]+(?:ansible\.builtin\.)?(?:shell|command|copy|get_url|uri|cron|win_shell):", 2),
        ],
        "need": [r"^[ \t-]*hosts:[ \t]*\S+|^[ \t]*tasks:[ \t]*$|ansible\.builtin\."],
        "neg": [r"^jobs:[ \t]*$", r"^on:[ \t]*|^'on':", r"\bruns-on:", r"^services:[ \t]*$", r"^stages:[ \t]*$",
                r"^apiVersion:", r"^trigger:[ \t]*$"],
        "options": ["ansible_yaml", "ansible_playbook", "ansible", "yaml"],
    },
    "groovy_jenkins": {
        "min": 4,
        "cribs": [
            (r"^[ \t]*pipeline[ \t]*\{", 3),
            (r"^[ \t]*stages[ \t]*\{|^[ \t]*stage[ \t]*\([^)]*\)[ \t]*\{", 2),
            (r"^[ \t]*steps[ \t]*\{|^[ \t]*agent[ \t]+(?:any|none|\{)", 2),
            (r"\b(?:sh|bat|powershell)[ \t]+['\"]", 1),
            (r"\bnode[ \t]*\([^)]*\)[ \t]*\{", 2),
        ],
        "options": ["groovy_jenkins", "jenkinsfile", "groovy", "jenkins_pipeline"],
    },
}
# XML comments are the only place XSLT cribs could hide; they are blanked. A `<xsl:` inside a text string of
# another language is blanked too. Nothing is read from inside a string except the csx-in-host path below.

_COMPILED = {
    name: ([(re.compile(p, re.M), w) for p, w in spec["cribs"]], spec["min"])
    for name, spec in LANGS.items()
}


def _score(name: str, code: str) -> int:
    rxs, _min = _COMPILED[name]
    spec = LANGS[name]
    if any(re.search(p, code, re.M) for p in spec.get("neg", ())):
        return 0                       # a marker of another family: not this language
    if spec.get("need") and not any(re.search(p, code, re.M) for p in spec["need"]):
        return 0                       # the min weight alone is not enough: a structural crib is required
    return sum(w for rx, w in rxs if rx.search(code))


def present(text: str) -> dict:
    """{language key: weight} for every covered language that reaches its threshold on `text`'s live code."""
    code = live_code(text or "")
    out = {}
    for name, (_rxs, mn) in _COMPILED.items():
        s = _score(name, code)
        if s >= mn:
            out[name] = s
    return out


def identify(text: str):
    """The one covered language `text` is written in, read from its live cribs, or None.

    None when no covered language reaches its threshold, and None when two or more do (an ambiguous polyglot:
    the lane must not guess which one the question asks)."""
    hits = present(text)
    if len(hits) == 1:
        return next(iter(hits))
    return None


def options_for(lang_key):
    """The ordered spelling candidates of a covered language, judge-observed spelling first; () if unknown."""
    spec = LANGS.get(lang_key)
    return tuple(spec["options"]) if spec else ()


# --------------------------------------------------------------------------- csx embedded in a host string

# A host (.aspx/.cshtml/.ashx/.cs) that compiles a C# script held in a string literal: the one place a crib
# inside a string is read. The host is recognised by a server-code marker, and the string by csx cribs.
_HOST_MARKERS = (
    re.compile(r"<%@[ \t]*(?:Page|Control|WebHandler|Assembly)\b", re.I),
    re.compile(r'<script[ \t]+runat[ \t]*=[ \t]*"server"', re.I),
    re.compile(r"\bCSharpScript\b|\bCSharpCodeProvider\b|\bScriptOptions\b|\bRoslyn\b|\bcsc(?:\.exe)?\b"),
    re.compile(r"\bProcessStartInfo\b.*\bcsi\b"),
)
_CSX_IN_STRING = re.compile(r"#r\s+\\?\"|#load\s+\\?\"|using\s+System\b|Console\s*\.\s*Write")
# literals a host might carry the script in: a C# verbatim string, a triple-quoted blob, a long "..."
_STRING_LITS = (
    re.compile(r'@"(?:[^"]|"")*"', re.S),                      # C# verbatim @"..."
    re.compile(r'"""(?:.*?)"""|\'\'\'(?:.*?)\'\'\'', re.S),    # triple-quoted
    re.compile(r'"(?:\\.|[^"\\])*"', re.S),                    # ordinary "..."
)


def embedded_csx(text: str):
    """(snippet, "csx") when a host file carries a C# script inside a string literal, else None.

    The host must show a server-code / Roslyn marker AND a string literal that holds csx cribs
    (`#r "`, `#load "`, `using System`, `Console.Write`). This is the csx-in-aspx / csx-in-string case: the
    one read that looks inside a string, and only in a host, so an ordinary C# string is not mistaken for an
    embedded script."""
    if not isinstance(text, str) or not text:
        return None
    if not any(rx.search(text) for rx in _HOST_MARKERS):
        return None
    best = None
    for rx in _STRING_LITS:
        for m in rx.finditer(text):
            body = m.group(0)
            if len(body) >= 24 and _CSX_IN_STRING.search(body):
                if best is None or len(body) > len(best):
                    best = body
    return (best, "csx") if best is not None else None


# --------------------------------------------------------------------------- the answers

_LANG_FIELDS = ("language", "next-language", "next_language", "embedded-language", "stage-language",
                "next-stage-language")


def _field_of(q) -> str:
    """The question's field word, from q['field'] else the third part of its id, `-` and `_` unified."""
    field = q.get("field") if isinstance(q, dict) else None
    if not (isinstance(field, str) and field):
        qid = re.sub(r"^set\d+\.", "", str((q or {}).get("qid") or (q or {}).get("id") or ""))
        parts = qid.split("-", 2)
        field = parts[2] if len(parts) == 3 else qid
    return field


def _ext_of(member) -> str:
    return re.sub(r"[^a-z0-9]+", "_", Path(str(member or "")).suffix.lower().lstrip(".")).strip("_") or "unknown"


def _pick(key, options):
    if labels is None or not options:
        return None
    try:
        v = labels.pick(key, list(options))
    except Exception as e:  # noqa: BLE001 - a bad key costs one answer, never the set
        print(f"[gdscript_csx_langs] labels.pick({key!r}) raised {type(e).__name__}: {e}", file=sys.stderr)
        return None
    return v


def language_pick(ext, text, field: str = "language"):
    """An unsure labels.pick for a `-language` field (what this specimen is) or a `-next-language` field
    (the next stage's language), from the specimen's live cribs, or None when no single language is read.

    `-language`: the specimen's own identified language.
    `-next-language` / embedded: when the specimen is a host carrying a C# script in a string (csx-in-aspx),
      the embedded language is csx; otherwise (wave123) the plan's STATED next_language is offered as an unsure
      labels.candidates hypothesis that re-derives its value per variant, so the truth is among the options and
      it resolves in one probe; None only when neither is available. Never a plain guess."""
    ext = _ext_of(ext) if ("." in str(ext) or "/" in str(ext)) else re.sub(r"[^a-z0-9]+", "_", str(ext or "").lower()).strip("_")
    fld = (field or "").replace("_", "-")
    if fld in ("next-language", "next-stage-language", "stage-language", "embedded-language"):
        got = embedded_csx(text)
        if got is not None:
            # unchanged: a host carrying an embedded C# script still offers the csx guess, same key
            return _pick(f"script.next_language/{ext}.embedded_csx", options_for("csx"))
        # wave123 harden (strictly None -> unsure): when the embedded guess does not apply (this id
        # used to come back None), offer the plan's STATED next_language, so the truth is among the
        # options and it resolves in one probe. Unsure (labels.candidates), never plain; the stated
        # hypothesis re-derives its value per variant, so an accepted name answers the next variant
        # with that variant's own stated value.
        try:
            import shape_fallback_lib as _sfl
            return _sfl.next_language_candidates(ext, _sfl.stated_next_language(text), None)
        except Exception as e:  # noqa: BLE001 - the harden must never cost the shipped answer
            print(f"[gdscript_csx_langs] next_language fallback raised {type(e).__name__}: {e}", file=sys.stderr)
            return None
    lang = identify(text)
    if lang is None:
        return None
    # one key PER LANGUAGE: a key's accepted name is returned plain for every id that shares it, so a shared key
    # would answer one language's name for another language's id
    return _pick(f"script.language/{ext}.cribs_{lang}", options_for(lang))


def overrides(member, questions, answers, files, find=None):
    """{qid: pick} for the language ids of ONE specimen that a shipped reader left None or unsure.

    This is the function a lane's day_patch.py calls. Copy these three lines into day_patch.py's patch():

        import gdscript_csx_langs as _langs       # (on sys.path beside analyze.py)
        return _langs.overrides(member, questions, answers, files)

    It never touches a plain answer (a decoded plan's own `language=`/`next_language=` stays), never answers
    plain itself, and names only `-language` / `-next-language` ids whose field word it recognises."""
    data = None
    if files is not None:
        if find is not None:
            try:
                data = find(files, member)
            except Exception:  # noqa: BLE001
                data = None
        if data is None and isinstance(files, dict):
            data = files.get(member)
            if data is None and member:
                base = str(member).rsplit("/", 1)[-1]
                data = next((v for k, v in files.items() if "->" not in str(k)
                             and str(k).rsplit("/", 1)[-1] == base), None)
    text = _text_of(data)
    if not text:
        return {}
    ext = _ext_of(member)
    out = {}
    for q in questions or ():
        if not isinstance(q, dict):
            continue
        fld = _field_of(q)
        if fld not in _LANG_FIELDS:
            continue
        qid = q.get("qid") or q.get("id")
        cur = (answers or {}).get(qid)
        plain = cur is not None and not (isinstance(cur, str) and cur.startswith("??"))
        if plain:
            continue                     # never replace a plain answer (the plan's own stated value)
        value = language_pick(ext, text, fld)
        if value is None:
            continue
        out[qid] = value
        print(f"[gdscript_csx_langs] {qid}: language field offered an unsure crib-based pick ({fld})",
              file=sys.stderr)
    return out


def _text_of(data) -> str:
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


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        sys.exit(__doc__)
    for arg in sys.argv[1:]:
        try:
            raw = Path(arg).read_bytes()
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})")
            continue
        body = _text_of(raw)
        lang = identify(body)
        emb = embedded_csx(body)
        print(f"{arg}: identify={lang!r} present={present(body)} "
              f"embedded_csx={'yes' if emb else 'no'}")
        if lang:
            print(f"    language pick -> {language_pick(arg, body, 'language')}")
        if emb:
            print(f"    next-language pick -> {language_pick(arg, body, 'next-language')}")
