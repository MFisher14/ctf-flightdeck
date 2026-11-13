#!/usr/bin/env python3
"""Script-lane cross-language table, id-keyed question reading and a generalised composite-label reader
(B-217, built 2026-11-12).

Why this exists (analysis/out/reports/synthesis/to_build.json id B-217, a recurring Huntress morning stop):
the Game Master reworded older Script questions and renamed descriptor containers, and the lane keyed on
wording and on a fixed table of composite tags. Three things were missing, and this module supplies them as
pure, testable library functions so a reworded question or a new carrier language does not need a hand fix:

  1. A LANGUAGE TABLE (language name -> comment/string reader), so a descriptor marker can be searched for in
     a carrier whose extension is unknown but whose language is named (a `next_language=<name>` field of one
     v=3 descriptor, a `<script language="...">` attribute, an operator's hint). The table maps 80+ language
     names and aliases onto a handful of comment PROFILES; a marker that sits inside a STRING or inside
     another language's comment is a decoy and is not read. Loud on an unknown language (no silent fallback).

  2. ID-KEYED QUESTION READING. `field_from_id(qid, plan_keys)` reads the asked plan field from the answer id
     and (optionally) the known plan keys, never from the English wording, so a reworded question banks the
     same answer. `changed_wording(prev, cur)` diffs a delivery against the prior day's: the ids whose
     wording changed while the id and answer_format held are exactly the ones the id-keyed path still covers.

  3. A COMPOSITE-LABEL READER generalised beyond descriptor.TAGS. `composite_label(tag)` tokenises a tag on
     any separator the author may use (`GZ+B64`, `HEX_GZ`, `B64-ZLIB-REV`, `rev.gz`), normalises each token
     through a synonym table, strips a version suffix (`B64V2`) and an inline key (`XOR5A`), and reports which
     tokens it could not resolve rather than guessing. `descriptor_chain(tag)` returns a layer list in
     descriptor.py's own vocabulary, or None when any token is unknown, so it is a SAFE fallback for
     descriptor.tag_chain (it fires only where the current table already gave None).

What is NOT automated (the item's stated blocker): a genuinely new descriptor SHAPE -- a token that names an
encoding no reader here knows -- still needs a first-time reader. `composite_label` names that token in
`unknown` so the gap is reported loudly, never silently dropped.

Entry points (all pure, no I/O, no network, specimen text is DATA and is never executed):
    composite_label(tag) -> {"chain": [...], "key": bytes|None, "unknown": [...], "ok": bool}
    descriptor_chain(tag) -> [layer, ...] | None
    profile_for(language) -> profile key           reader_for(language) -> carriers(text) bound to it
    comment_regions(text, language) -> [(start, end), ...]
    carriers(text, language) -> [(marker, tag, payload), ...]
    field_from_id(qid, plan_keys=None) -> field name | None
    changed_wording(prev_questions, cur_questions) -> {qid, ...}
CLI:  .venv/bin/python -I solvers/script-analysis/lang_table.py <file> [...]   (prints each file's carriers)
"""
import re
import sys
from pathlib import Path

__all__ = ["composite_label", "descriptor_chain", "profile_for", "reader_for", "comment_regions",
           "carriers", "field_from_id", "changed_wording", "LANGUAGES", "PROFILES", "ATOMS"]


# ---------------------------------------------------------------- 3. the composite-label reader

# A single tag token -> the descriptor layer atoms it names (outermost first). Only atoms descriptor.py can
# apply appear here (its LAYERS and TAG_LAYERS keys), so descriptor_chain() hands back a directly applicable
# chain. A COMPRESSION word maps to the raw decompressor alone; a lone compression tag is given its base64
# text layer by composite_label (descriptor's convention: a bare `GZ` carries base64), but inside a composite
# the author spells the text layer (`HEX+GZ`), so no implicit layer is inserted and the token order is kept.
ATOMS = {
    # base-n text codecs
    "b64": ["b64"], "base64": ["b64"], "b64u": ["b64"], "b64url": ["b64"], "urlb64": ["b64"], "ub64": ["b64"],
    "frombase64": ["b64"], "frombase64string": ["b64"],
    "b32": ["b32"], "base32": ["b32"],
    "b85": ["b85"], "base85": ["b85"],
    "a85": ["a85"], "ascii85": ["a85"], "adobe85": ["a85"], "adobe": ["a85"],
    "z85": ["z85"],
    "b58": ["b58"], "base58": ["b58"],
    "b91": ["b91"], "base91": ["b91"],
    "b45": ["b45"], "base45": ["b45"],
    "b62": ["b62"], "base62": ["b62"],
    "b36": ["b36"], "base36": ["b36"],
    "hex": ["hex"], "h": ["hex"], "hexstr": ["hex"], "frag": ["hex"], "fraghex": ["hex"], "hexfrag": ["hex"],
    "dec": ["dec"], "decimal": ["dec"], "charcodes": ["dec"], "charcode": ["dec"],
    "oct": ["oct"], "octal": ["oct"],
    "bin": ["bin"], "binary": ["bin"],
    "pct": ["pct"], "url": ["pct"], "urlenc": ["pct"], "percent": ["pct"], "urlencode": ["pct"],
    "qp": ["qp"], "quopri": ["qp"], "quotedprintable": ["qp"],
    "uu": ["uu"], "uue": ["uu"], "uuencode": ["uu"], "uuencoded": ["uu"],
    "yenc": ["yenc"],
    # byte-level transforms
    "rev": ["rev"], "reverse": ["rev"], "reversed": ["rev"],
    "rot13": ["rot13"], "r13": ["rot13"],
    "rot47": ["rot47"], "rot18": ["rot18"],
    "u16": ["u16"], "utf16": ["u16"], "u16le": ["u16"], "utf16le": ["u16"],
    "u16be": ["u16be"], "utf16be": ["u16be"],
    # compressors (raw decompressor; see note above)
    "gz": ["inflate"], "gzip": ["inflate"], "zlib": ["inflate"], "deflate": ["inflate"], "inflate": ["inflate"],
    "gunzip": ["inflate"], "unzlib": ["inflate"],
    "bz2": ["bz2"], "bzip2": ["bz2"], "bz": ["bz2"],
    "xz": ["xz"], "lzma": ["xz"],
    "zstd": ["zstd"], "zst": ["zstd"],
    "lz4": ["lz4"],
    "snappy": ["snappy"],
    "brotli": ["brotli"], "br": ["brotli"],
    # no-op / key-carrying words (the key is a crib, read elsewhere)
    "xor": [], "plain": [], "raw": [], "text": [], "none": [], "identity": [], "id": [],
}

# atoms whose input is binary: a lone tag of one of these carries base64 text (descriptor's `GZ` convention)
_NEEDS_TEXT = {"inflate", "bz2", "xz", "zstd", "lz4", "snappy", "brotli", "u16", "u16be"}
# every atom descriptor.py can apply: descriptor_chain refuses a chain that leaves this set
_APPLICABLE = {a for atoms in ATOMS.values() for a in atoms}

_SEP = re.compile(r"[+>_\-./,|:;&~ \t]+")
# a trailing inline key on a token: XOR5A, XOR_5A (split handles the underscore form)
_KEY_SUFFIX = re.compile(r"^(xor|x)([0-9a-f]{2,})$", re.I)
# an explicit version marker on a token: B64V2, GZV10 (a bare `V` plus digits, so `b64` itself is left alone)
_VER_SUFFIX = re.compile(r"v\d+$", re.I)


def _key_bytes(hexstr):
    h = hexstr if len(hexstr) % 2 == 0 else "0" + hexstr
    try:
        return bytes.fromhex(h)
    except ValueError:
        return None


def composite_label(tag):
    """Read a (possibly composite) descriptor tag into a decode chain.

    Returns {"chain": [atom, ...], "key": bytes|None, "unknown": [token, ...], "ok": bool}. `chain` is the
    descriptor layer atoms, outermost first, in the token order the author wrote (a text decoder first, then a
    byte transform or decompressor). `key` is the first inline XOR key found (`XOR5A` -> b"\\x5a"). `unknown`
    names every token that resolved to no atom -- the loud report of a shape that still needs a reader. `ok` is
    True only when nothing was unknown and at least one token was given.
    """
    chain, key, unknown, tokens = [], None, [], 0
    for tok in _SEP.split((tag or "").strip()):
        if not tok:
            continue
        tokens += 1
        low = tok.lower()
        km = _KEY_SUFFIX.match(low)
        if km:
            if key is None:
                key = _key_bytes(km.group(2))
            chain += ATOMS["xor"]                      # the xor layer itself is a crib: no decode step
            continue
        if low in ATOMS:
            chain += ATOMS[low]
            continue
        stripped = _VER_SUFFIX.sub("", low)            # B64V2 -> b64 (only an explicit `V<digits>` marker)
        if stripped != low and stripped in ATOMS:
            chain += ATOMS[stripped]
            continue
        unknown.append(tok)
    # a lone binary-input tag carries base64 text (descriptor's bare-`GZ` convention)
    if tokens == 1 and not unknown and chain and chain[0] in _NEEDS_TEXT:
        chain = ["b64"] + chain
    return {"chain": chain, "key": key, "unknown": unknown, "ok": not unknown and tokens > 0}


def descriptor_chain(tag):
    """The layer list descriptor.py can apply for `tag`, or None when a token is unknown or names an atom
    descriptor cannot apply. SAFE as a fallback after descriptor.tag_chain: it only ever returns a chain of
    applicable atoms, so a chain it hands back decodes with the same vocabulary the hardcoded table uses."""
    r = composite_label(tag)
    if not r["ok"] or not r["chain"]:
        return None                        # an empty chain is a no-op tag (PLAIN/RAW/XOR); descriptor's own
    if any(a not in _APPLICABLE for a in r["chain"]):   # TAGS already names those, so this never adds one
        return None
    return r["chain"]


# ---------------------------------------------------------------- 1. the language table

# comment / string syntax: (line-comment starters, block-comment pairs, string quote characters).
PROFILES = {
    "c":      (("//",), (("/*", "*/"),), "\"'`"),
    "hash":   (("#",), (), "\"'"),
    "hashc":  (("#",), (("/*", "*/"),), "\"'`"),
    "dash":   (("--",), (("{-", "-}"),), "\"'"),
    "dashsql": (("--",), (("/*", "*/"),), "\"'"),
    "semi":   ((";",), (), "\"'"),
    "pct":    (("%",), (), "\"'"),
    "ml":     ((), (("(*", "*)"),), "\"'"),
    "lua":    (("--",), (("--[[", "]]"),), "\"'"),
    "vb":     (("'", "REM "), (), "\""),
    "bat":    (("REM ", "::"), (), "\""),
    "ps":     (("#",), (("<#", "#>"),), "\"'`"),
    "xml":    ((), (("<!--", "-->"),), ""),
    "tex":    (("%",), (), ""),
    "fortran": (("!",), (), "\"'"),
    "jl":     (("#",), (("#=", "=#"),), "\"'"),
    "erlang": (("%",), (), "\"'"),
    "ini":    ((";", "#"), (), "\"'"),
}

# language name (and common aliases) -> profile key. Over 80 names; every name is lower case, and lookups
# normalise case, spaces, dots and `+`/`#` (`C++`, `C#`, `objective-c`, `visual basic`). The answer is the
# comment syntax, never the extension.
LANGUAGES = {
    # C family and curly-brace descendants
    "c": "c", "c++": "c", "cpp": "c", "c#": "c", "csharp": "c", "objective-c": "c", "objc": "c",
    "java": "c", "javascript": "c", "js": "c", "jscript": "c", "typescript": "c", "ts": "c",
    "go": "c", "golang": "c", "rust": "c", "swift": "c", "kotlin": "c", "scala": "c", "dart": "c",
    "d": "c", "php": "c", "groovy": "c", "jsonc": "c", "hlsl": "c", "glsl": "c", "verilog": "c",
    "systemverilog": "c", "arduino": "c", "processing": "c", "zig": "c", "vala": "c", "haxe": "c",
    "solidity": "c", "cuda": "c", "opencl": "c", "qml": "c", "less": "c", "scss": "c", "sass": "c",
    # hash-comment languages
    "python": "hash", "py": "hash", "ruby": "hash", "rb": "hash", "perl": "hash", "pl": "hash",
    "bash": "hash", "sh": "hash", "shell": "hash", "zsh": "hash", "fish": "hash", "awk": "hash",
    "tcl": "hash", "r": "hash", "yaml": "hash", "yml": "hash", "toml": "hash", "make": "hash",
    "makefile": "hash", "cmake": "hash", "dockerfile": "hash", "docker": "hash", "elixir": "hash",
    "crystal": "hash", "nim": "hash", "coffeescript": "hash", "coffee": "hash", "gitignore": "hash",
    "properties": "hash", "conf": "hash", "graphql": "hash", "puppet": "hash", "nix": "hash",
    "php-hash": "hash",
    # hash + /* */ (languages that take both)
    "php8": "hashc", "autoit": "hash",
    # Haskell / Elm (dash + {- -})
    "haskell": "dash", "hs": "dash", "elm": "dash", "purescript": "dash", "agda": "dash", "idris": "dash",
    # SQL family (dash + /* */)
    "sql": "dashsql", "mysql": "dashsql", "postgresql": "dashsql", "postgres": "dashsql", "plsql": "dashsql",
    "tsql": "dashsql", "sqlite": "dashsql", "mariadb": "dashsql", "ada": "dashsql", "vhdl": "dashsql",
    # Lisp / assembly (semicolon)
    "lisp": "semi", "clojure": "semi", "clj": "semi", "scheme": "semi", "racket": "semi", "elisp": "semi",
    "asm": "semi", "assembly": "semi", "nasm": "semi", "masm": "semi", "autohotkey": "semi", "ahk": "semi",
    "ini-semi": "semi", "gas": "semi",
    # Matlab / Erlang / LaTeX (percent)
    "matlab": "pct", "octave": "pct", "latex": "tex", "tex": "tex", "prolog": "pct", "mercury": "pct",
    # ML family ((* *))
    "ocaml": "ml", "ml": "ml", "sml": "ml", "fsharp": "ml", "f#": "ml", "pascal": "ml", "delphi": "ml",
    "mathematica": "ml", "wolfram": "ml",
    # Lua
    "lua": "lua", "moonscript": "lua",
    # VB / BASIC / scripting hosts
    "vbscript": "vb", "vbs": "vb", "vba": "vb", "vb": "vb", "visual basic": "vb", "vbnet": "vb", "basic": "vb",
    "batch": "bat", "bat": "bat", "cmd": "bat", "dos": "bat",
    "powershell": "ps", "ps1": "ps", "pwsh": "ps",
    # markup / data
    "html": "xml", "xml": "xml", "xhtml": "xml", "svg": "xml", "xsl": "xml", "xslt": "xml", "markdown": "xml",
    "md": "xml", "wsf": "xml", "hta": "xml", "jsp": "xml", "aspx": "xml", "razor": "xml", "vue": "xml",
    "angular": "xml", "plist": "xml", "wsdl": "xml",
    # scientific / misc
    "fortran": "fortran", "f90": "fortran", "f77": "fortran",
    "julia": "jl", "jl": "jl",
    "erlang": "erlang", "erl": "erlang", "applescript": "ml",
    "ini": "ini", "cfg": "ini", "editorconfig": "ini", "desktop": "ini", "registry": "semi", "reg": "semi",
}


class UnknownLanguage(ValueError):
    """A language the table does not map. Raised, never swallowed: the carrier cannot be read without its
    comment syntax, and a silent wrong profile would read a string literal as a comment."""


def _normalise(language):
    return re.sub(r"\s+", " ", (language or "").strip().lower())


def profile_for(language):
    """The comment profile of a language name, or raise UnknownLanguage (no silent fallback)."""
    name = _normalise(language)
    if name in LANGUAGES:
        return LANGUAGES[name]
    # try a looser spelling: drop spaces, keep `+`/`#`/`-` (so `visual basic` -> `visualbasic` is not matched,
    # but `objective c` -> `objective-c`); then the alnum-only squash as a last resort.
    hyphen = re.sub(r"\s+", "-", name)
    if hyphen in LANGUAGES:
        return LANGUAGES[hyphen]
    squashed = re.sub(r"[\s_]+", "", name)
    if squashed in LANGUAGES:
        return LANGUAGES[squashed]
    raise UnknownLanguage(f"no comment profile for language {language!r} (add it to lang_table.LANGUAGES)")


MAX_TEXT = 1 << 20     # characters of a carrier that are scanned


def comment_regions(text, language):
    """[(start, end), ...] of the comment spans of `text` read in `language`'s comment syntax, in order. A
    string literal is NOT a comment: its body is skipped so a marker inside a string is not reported. One
    left-to-right scan; an unterminated block or line comment runs to the end of the text."""
    prof = profile_for(language)
    line_starts, blocks, quotes = PROFILES[prof]
    text = text[:MAX_TEXT]
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        # block comments first (longest opener wins so `<!--` beats a bare `<`)
        hit = None
        for a, b in sorted(blocks, key=lambda p: -len(p[0])):
            if text.startswith(a, i):
                k = text.find(b, i + len(a))
                end = n if k < 0 else k + len(b)
                hit = (i, end, end)
                break
        if hit is None:
            for a in sorted(line_starts, key=len, reverse=True):
                if not text.startswith(a, i):
                    continue
                if a == "REM " and i and (text[i - 1].isalnum() or text[i - 1] == "_"):
                    continue                           # REM only at a word boundary
                k = text.find("\n", i)
                end = n if k < 0 else k
                hit = (i, end, end)
                break
        if hit is not None:
            start, cend, nxt = hit
            out.append((start, cend))
            i = max(nxt, i + 1)
            continue
        if c in quotes:                                # skip a string literal's body (not a comment)
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" and prof not in ("vb", "bat") else 1
            i = j + 1
            continue
        i += 1
    return out


# A descriptor marker the lane plants in a comment: `HUNTRESS_ANALYSIS_V<n>:<TAG>-<payload>` and the softer
# `HUNTRESS_<NAME>:<TAG>-<payload>` (descriptor.MARK / SOFT_MARK). The payload is read as DATA; nothing runs.
_MARKER = re.compile(r"HUNTRESS[_-][A-Za-z][A-Za-z0-9_-]{0,40}?[ \t]*[:=][ \t]*"
                     r"([A-Za-z][A-Za-z0-9+>_.\-]{0,47})[ \t]*[-:|][ \t]*(\S(?:[^\r\n]*\S)?)")
# a bare tag with no payload on the line (the .gs SPLIT family: `// HUNTRESS_ANALYSIS_V1:SPLIT`)
_BARE = re.compile(r"HUNTRESS[_-][A-Za-z][A-Za-z0-9_-]{0,40}?[ \t]*[:=][ \t]*([A-Za-z][A-Za-z0-9+>_.\-]{0,47})[ \t]*$")


def carriers(text, language):
    """[(marker_text, tag, payload), ...] for every descriptor marker inside a comment of `text` read as
    `language`. A marker in code or in a string literal is ignored. `payload` is "" for a bare tag line (the
    SPLIT family); `tag` is the raw tag text, read with composite_label by the caller. Raises UnknownLanguage
    for a language the table does not map."""
    if "HUNTRESS" not in text:
        return []
    out = []
    for start, end in comment_regions(text, language):
        body = text[start:end]
        for m in _MARKER.finditer(body):
            out.append((m.group(0), m.group(1), m.group(2).strip()))
        for m in _BARE.finditer(body):
            if not any(m.start() >= mm.start() and m.start() < mm.end()
                       for mm in _MARKER.finditer(body)):
                out.append((m.group(0), m.group(1), ""))
    return out


def reader_for(language):
    """A `carriers` reader bound to one language: `reader_for('Rust')(text)`. Raises UnknownLanguage now, not
    on first use, so an unknown language fails loudly at the point of choosing it."""
    profile_for(language)              # fail fast on an unknown language
    return lambda text: carriers(text, language)


# ---------------------------------------------------------------- 2. id-keyed question reading

_SET_PREFIX = re.compile(r"^set\d+\.")
# role words that NAME a specimen in an id but are not plan fields (analyze.KNOWN_ROLE_WORDS and friends)
_ROLE_WORDS = frozenset(("benign", "chain", "downloader", "dropper", "impact", "launcher", "relay",
                         "stager", "uploader", "persistence", "advanced", "loader"))
# id tails that name a derived field rather than a plain plan key
_SPECIAL_TAILS = {"campaign": "campaign_id", "stage-count": "stage_count"}


def _qid_text(q):
    if isinstance(q, dict):
        return str(q.get("qid") or q.get("id") or "")
    return str(q or "")


def field_from_id(qid, plan_keys=None):
    """The plan field an answer id asks, read from the ID (and, when given, the known `plan_keys`), never from
    the question wording. This is the id-keyed reading the lane relies on to survive a reworded question.

    With `plan_keys` (a set/collection of the plan's field names) the longest tail of the id that is a plan key
    wins: `-cron-path` picks `cron_path` over `path`, `-upload-url` picks `url` only when `upload_url` is not a
    key. Without `plan_keys` the nominal field is the last id segment (`stage-count` -> `stage_count`,
    `-campaign` -> `campaign_id`); `-steps`, `-role` and `-attack` keep their own names. Returns None when the
    id names no field, or when `plan_keys` is given and no tail of the id is among them.
    """
    qid = _SET_PREFIX.sub("", _qid_text(qid))
    if not qid:
        return None
    for tail, field in _SPECIAL_TAILS.items():
        if qid.endswith("-" + tail) or qid == tail:
            if plan_keys is None or field in plan_keys:
                return field
            return None
    words = [w for w in re.split(r"[-]", qid) if w]
    if not words:
        return None
    last = words[-1]
    if last in ("steps", "role", "attack"):
        return last
    if plan_keys is not None:
        keys = set(plan_keys)
        for n in range(min(3, len(words)), 0, -1):
            cand = "_".join(words[-n:])
            if cand in keys:
                return cand
        return None
    # no plan to check against: the nominal field is the id's last segment (two words when the last is generic)
    if last in ("id", "name", "value", "indicator") and len(words) >= 2 and words[-2] not in _ROLE_WORDS:
        return "_".join(words[-2:])
    return last


def changed_wording(prev_questions, cur_questions):
    """{qid, ...} for the ids present in BOTH deliveries whose question wording changed while the id and the
    answer_format held. These are exactly the ids a wording-keyed solver would have missed and the id-keyed
    path still covers: a caller diffs against the prior day before banking and trusts the id reading for them.
    Ids new to `cur`, ids dropped, and ids whose answer_format changed are not reported (a changed format may
    change the asked form -- answer_forms.py handles that)."""
    prev = {}
    for q in prev_questions or ():
        if isinstance(q, dict):
            qid = q.get("qid") or q.get("id")
            if qid:
                prev[qid] = (str(q.get("question") or ""), _fmt_sig(q))
    out = set()
    for q in cur_questions or ():
        if not isinstance(q, dict):
            continue
        qid = q.get("qid") or q.get("id")
        if qid in prev:
            old_text, old_fmt = prev[qid]
            if _fmt_sig(q) == old_fmt and str(q.get("question") or "") != old_text:
                out.add(qid)
    return out


def _fmt_sig(q):
    """A stable signature of a question's answer_format, so a wording change is told from a format change."""
    fmt = q.get("answer_format")
    if not isinstance(fmt, dict):
        return ()
    kind = fmt.get("kind")
    accepted = fmt.get("accepted_values")
    accepted = tuple(accepted) if isinstance(accepted, list) else accepted
    return (kind, accepted, fmt.get("syntax"))


# ---------------------------------------------------------------- CLI

def main(argv):
    if argv and argv[0] in ("-h", "--help"):
        print("usage: lang_table.py <file> [...]   (prints the descriptor carriers of each file, by language)")
        return 0
    if not argv:
        print("lang_table.py: expected at least one file", file=sys.stderr)
        return 2
    for path in argv:
        p = Path(path)
        text = p.read_text(encoding="utf-8", errors="replace")
        # the language is guessed from the extension only for the CLI's convenience; the library takes a name.
        ext = p.suffix.lstrip(".").lower()
        try:
            name = next((k for k, v in LANGUAGES.items() if k == ext), ext)
            found = carriers(text, name)
        except UnknownLanguage as e:
            print(f"{path}: {e}", file=sys.stderr)
            continue
        for marker, tag, payload in found:
            print(f"{path}\t{tag}\t{descriptor_chain(tag)}\t{payload[:48]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
