#!/usr/bin/env python3
"""The language-blind plan/descriptor reader of the Script Analysis lane (B-227).

Usage:
  python3 solvers/script-analysis/blind_reader.py <specimen> [...]     print what each file's containers give

Why it exists. Through the Huntress run the lane needed a new per-language module on most days: a plan miner
for VBScript (Day 4), cribs and a literal reader for Python (Day 5), tagged descriptors in PHP and host files
(Day 8), split-array containers in Apps Script (Day 18), escaped string-literal hosts in .csx and aspx (Day 19).
plan_codec and descriptor answer most of those now, but each container they read whole is still one entry of
a per-idiom table (descriptor.JOIN_FORMS, descriptor_whole._FORMS). A join written in an idiom the table does
not hold (Zig's `++`, `(..) -join ""`, a host literal with escaped quotes) is read as a PIECE, so the plan's
last field (`file_path`, often `url`) is dropped, or, under a SPLIT marker, the file is refused outright.

This reader proves wholeness from structure alone, the same way in every language:

  literals     every quoted literal of the text, in every quote style (" ' ` and triple quotes, C#'s @"..."
               verbatim with "" for a quote), with backslash escapes undone (\\" \\n \\xNN \\uNNNN \\u{..} octal).
               A literal that may interpolate (`$x`, `${..}`, `#{..}` in double quotes or backquotes) has no
               known value and is never material. In VB text only `"` quotes, `""` inside it is one quote (so
               `"ab""cd"` is one literal holding a quote, never two pieces), a backslash is itself and a literal
               ends on its line. VB text is a VB_EXTS file, or the VBScript/VB blocks of a host file (HOST_EXTS)
               as its markers name them (vb_spans: `<script language="VBScript">`, `<%@ Language=VBScript %>`).
  container    the right-hand side of an assignment (`=`, `:=`, `<-`, `=>`, and `:` for a key), read to the end
               of its statement (a `;`, `,` or line end outside every bracket, a closer of a bracket opened
               before it, a host closer `?>` `%>` `</`). A line that ends with, or a next line that starts
               with, a join operator goes on. It is ONE container when its non-empty literals stand together
               with nothing between them but glue (blanks, brackets, commas, `+ . & | ~ < >`, a VB `_`, the word
               `concat`) and nothing around them but brackets, punctuation, empty literals (a join's separator)
               and words that are neither names the file assigns nor words that reorder or cut a value
               (DENY: reverse, sort, slice, replace, ...). No digit may stand in it (`[::-1]`, `substr(0, 9)`,
               `"ab" * 2`). Pieces written as a list (commas between them) must be joined by a word that
               joins (JOIN_WORDS: join, concat, implode, paste, ...); a bare list has no string value.
               Its value is its literals' values in the order written: joining with an empty separator is
               concatenation, so the separator's spelling never matters.
  whole        a container is the variable's whole value when, besides, its head is live code (not in a comment
               block, a multi-line string or behind a line-comment opener: descriptor.live_code), its name is
               assigned once, and no other mention of the name grows it, glues it to more text (glue before
               or after it, on its line or across a line break the way a container continues), indexes it,
               interpolates it or hands it to a join or a mutator.
  host         a container whose value holds quotes is itself code (an escaped string-literal host: an aspx
               page's C#, a .csx `@"..."`, JSON in a string) and is read again, once more at most (MAX_DEPTH).
               What it gives is whole only when the host container is.
  decode       a value `<TAG>-<payload>` (optionally behind `HUNTRESS_ANALYSIS_V<n>:`) by the tag
               (descriptor.decode, or plan_layers for `LYR-<labels>-<payload>`); any other value by the free
               search of descriptor.decode. The ONLY acceptance is the plan grammar (v=<n> and key=value fields
               in any order, plan_codec.grammar_plan, or a JSON descriptor), one plan per value, and for a
               version whose fields are known, all of them (descriptor.checked).
  agreement    every whole container, every piece and every tagged comment of the file must give the same plan
               (a piece or a wrapped comment may give its head: plan_codec.head_of); two plans are no plan. A
               plan that plan_codec sees going on past it (continued_plans) is a head, never whole.

reading(text, ext) -> Verdict(plan_text, how, transform, copies, tagged, why). plan_text is set only for ONE
plan read whole; why says why a file that carries containers gave none. generic.read() asks it for every
extension (BLIND_READER) where plan_codec, descriptor and descriptor_whole left the plan cut or unread, and
takes its plan only when every field they did read agrees.

Nothing is executed and nothing is fetched. Specimen text is untrusted data: it is decoded, never followed.
Work is bounded (MAX_TEXT, MAX_LITERALS, MAX_RHS, MAX_DECODES).
"""
from __future__ import annotations

import bisect
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import plan_codec  # noqa: E402

MAX_TEXT = 1 << 21          # characters of a file read
MAX_LITERALS = 50_000       # literals scanned in one file
MAX_RHS = 400_000           # characters of one right-hand side
MAX_DECODES = 32            # distinct values decoded per file (each is a bounded free search)
MAX_DEPTH = 1               # host literals read inside host literals (0 = the file only)
MIN_VALUE = 24              # characters: a shorter value is not material (descriptor.MIN_PAYLOAD)
MAX_NEST = 16               # bracket levels a dict's material is counted through (deeper: no keyed value is whole)
# Extensions of the Visual Basic family: only " quotes, "" inside it is one quote, a backslash is a backslash.
VB_EXTS = frozenset(("vbs", "vba", "vb", "bas", "cls", "frm"))
# Host files whose script blocks name their own language (vb_spans): a block in VBScript (or VB.NET) is read with
# the VB quote rules, the rest of the file with the C rules.
HOST_EXTS = frozenset(("wsf", "wsc", "hta", "asp", "aspx", "ascx", "asmx", "ashx", "htm", "html", "xhtml", "sct"))


class MissingModule(RuntimeError):
    """A module this reader cannot work without (descriptor.py) did not load. It is raised, never read as 'no
    plan': generic.by_blind lets it through unless the module was hidden on purpose (plan_codec.hidden)."""

    def __init__(self, module: str, why: str):
        super().__init__(why)
        self.module = module

# Words that change a value's order or content: a container that names one is not its written text.
DENY = frozenset("""
reverse reversed strrev reverse_string sort sorted shuffle slice substr substring splice replace replaceall
translate maketrans tr rotate swapcase upper lower touppercase tolowercase ucase lcase mid left right repeat
padstart padend insert remove pop shift unshift filter map select take skip drop chunk truncate trim_end
""".split())
# Words that join a list of pieces into one string.
JOIN_WORDS = ("join", "concat", "implode", "paste", "glue", "combine", "collapse", "strcat", "stringcat")
# The words a mention of the value's name may be handed to or followed by and still be the whole value: none.
_GROW_AFTER = re.compile(r"[ \t]*(?:\+=|\.=|&=|\.\.=|\|\|=|<<=?|\+\+(?![\"'])|-=|=(?![=>~])|:=|<-)")
_GLUE_AFTER = re.compile(r"[ \t]*(?:\+(?!\+?=)|&(?!&)|\.\.|\|\||<>|~|\+\+|\.(?=[ \t]|[\"'$]))")
_GLUE_BEFORE = re.compile(r"(?:\+|&|\.\.|\|\||<>|~|\+\+|(?<=[ \t\"'])\.)[ \t]*$")
_MUTATE_AFTER = re.compile(r"[ \t]*(?:\[|\.[ \t]*(?:push|append|concat|extend|insert|add|addrange|reverse|sort|"
                           r"splice|unshift|shift|pop|remove|clear|fill|set|put|update|write|appendline)\b)", re.I)
_CALL_BEFORE = re.compile(r"([A-Za-z_][\w.]*)[ \t]*\([ \t]*(?:[^()\"'\n]{0,40}?,[ \t]*)?[$@%]?$")
_LISP_CALL_BEFORE = re.compile(r"\(([A-Za-z_][\w.*/!?-]*)[ \t]+(?:[^()\"'\n]{0,40}?[ \t])?$")

_BLANK = " \t\r\n"


def _glued_before(t: str, s: int) -> bool:
    """Whether the mention at t[s] is the tail of a join: glue (`+ & . .. ++ || ~ <>`) stands before it, on its
    line at any distance or on an earlier line with only blanks, line breaks and line-continuation marks (VB's
    ` _`, a backslash, PowerShell's backquote) between: `"x" +\n    m`, the continuation rhs_end reads.
    Linear: the blank runs walked back over before distinct mentions are disjoint."""
    j = s
    while True:
        end = j
        while j > 0 and t[j - 1] in _BLANK:
            j -= 1
        mark = j > 0 and (t[j - 1] in "\\`" or t[j - 1] == "_" and j > 1 and t[j - 2] in " \t")
        if mark and "\n" in t[j:end]:
            j -= 1                                    # a continuation mark ends the line: look on before it
            continue
        break
    # the longest glue is two characters (`..`, `++`, `||`, `<>`); the lookbehind of a lone `.` sees before pos
    return _GLUE_BEFORE.search(t, max(0, j - 2), j) is not None


def _glued_after(t: str, e: int) -> bool:
    """Whether glue follows the mention ending at t[e], on its line or at the start of the next one with only
    blanks between (`m\n    + "x"`: the next-line continuation rhs_end reads)."""
    if _GLUE_AFTER.match(t, e):
        return True
    k = e
    while k < len(t) and t[k] in " \t":
        k += 1
    if t[k:k + 1] == "\r":
        k += 1
    if t[k:k + 1] != "\n":
        return False
    return _CONT_START.match(t, k + 1) is not None


_QUOTE = re.compile(r"[\"'`]")
_IDENT = re.compile(r"[$@%]?[A-Za-z_]\w*")
_INTERP = re.compile(r"\$\{|\$[A-Za-z_(]|#\{")
# An assignment head: a name (a sigil allowed, a dotted or `script:` scope not), an optional type behind `:`,
# and the operator. A `:` alone is a key's (an object or dict entry).
_HEAD = re.compile(r"(?<![\w$@%.])(?P<name>[$@%]?[A-Za-z_]\w*)(?:[ \t]*:[ \t]*[A-Za-z_][\w.<>\[\], ?]{0,60}?)?"
                   r"[ \t]*(?P<op>:=|<-|=>|=(?![=>~])|:(?![:=/]))[ \t]*")
_KEY_OP = re.compile(r"[ \t]*(?P<op>=>|:(?![:=/]))[ \t]*")
# A Lisp definition, `(def name <value>)`: the value runs to the form's own closer.
_LISP_DEFS = ("def", "define", "defvar", "defparameter", "defconst", "defconstant", "defonce", "setq", "setf", "set!")
_LISP_HEAD = re.compile(r"\((?:%s)[ \t]+(?P<name>[A-Za-z_*][\w*!?<>-]*)[ \t\r\n]+"
                        % "|".join(re.escape(w) for w in _LISP_DEFS))
_LINE_COMMENT = re.compile(r"(?:^|[ \t;])(?://|#|--|')|^[ \t]*(?:;|::|%|\*|rem(?:[ \t]|$))", re.I)
_CONT_END = re.compile(r"(?:\+|&|\.\.|\.|\+\+|\|\||~|<>|\\|[ \t]_|`)[ \t]*\r?$")
_CONT_START = re.compile(r"[ \t]*(?:\+(?!\+?=)|&|\.\.|\+\+|\|\||~|<>|\.(?=[ \t\"']))")
_TAGGED = re.compile(r"(?:HUNTRESS[_-]?ANALYSIS[_-]?V\d+[ \t]*[:=_-][ \t]*)?(?P<tag>[A-Z][A-Z0-9_+]{0,31})-"
                     r"(?P<payload>\S+)$")
_COMMENT_TAG = re.compile(r"HUNTRESS[_-]?ANALYSIS[_-]?V\d+[ \t]*[:=][ \t]*(?P<tag>[A-Z][A-Z0-9_+]{0,31})-"
                          r"(?P<payload>[A-Za-z0-9+/=._:%-]{16,})")
_MATERIAL = re.compile(r"[\x21-\x7e]+")
_SIBLING = re.compile(r"[A-Za-z0-9+/=._:%-]{16,}")
_GLUE_P = frozenset(",+.&|~<>()[]{}\\")
_FRAME_P = _GLUE_P | frozenset("@!:-")


@dataclass
class Lit:
    start: int          # the opening quote (or `@`)
    end: int            # one past the closing quote
    value: str          # the text the literal stands for
    interp: bool        # it may interpolate: its value is not known


@dataclass
class Copy:
    plan_text: str
    how: str
    whole: bool
    kind: str           # container | tagged | host | comment
    at: int             # where in the text (of its own level) it stands
    name: str = ""


@dataclass
class Verdict:
    plan_text: str | None = None
    how: str | None = None
    transform: str | None = None
    copies: int = 0
    tagged: bool = False
    why: str | None = None
    notes: list = field(default_factory=list)


class _Reader:
    """The containers and tagged comments of one text (one level: the file, or a host literal's value)."""

    def __init__(self, text: str, ext=None, depth: int = 0, budget=None):
        self.text = text[:MAX_TEXT]
        self.ext = (ext or "").lower().lstrip(".")
        self.depth = depth
        self.budget = budget if budget is not None else {"decodes": 0, "values": {}}
        self.lits = scan_dialects(self.text, vb_spans(self.text, self.ext))
        self.starts = [lit.start for lit in self.lits]
        self.by_start = {lit.start: lit for lit in self.lits}
        self.code = _live(self.text, self.ext)
        self.interp_lits = [lit for lit in self.lits if lit.interp]
        self._names = None

    # ------------------------------------------------------------------ positions

    def in_literal(self, i: int) -> Lit | None:
        k = bisect.bisect_right(self.starts, i) - 1
        if k >= 0 and self.lits[k].start <= i < self.lits[k].end:
            return self.lits[k]
        return None

    def live(self, a: int, b: int) -> bool:
        """text[a:b] is live code: no comment block or multi-line string, and no line-comment opener before
        `a` on its line (outside a literal)."""
        if self.code[a:b] != self.text[a:b]:
            return False
        ls = self.text.rfind("\n", 0, a) + 1
        prefix = "".join(" " if self.in_literal(i) else self.text[i] for i in range(ls, a))
        return _LINE_COMMENT.search(prefix) is None

    def names(self) -> set:
        """Every name the file assigns (bare, without a sigil). A named argument (`f(sep="")`, `collapse=""`:
        a name right behind `(` or `,`) assigns nothing."""
        if self._names is None:
            names = set()
            for m in _HEAD.finditer(self.text):
                if self.in_literal(m.start()):
                    continue
                before = self.text[max(0, m.start() - 64):m.start()].rstrip()
                if m.group("op") == "=" and before[-1:] in ("(", ","):
                    continue
                names.add(m.group("name").lstrip("$@%"))
            names.update(m.group("name") for m in _LISP_HEAD.finditer(self.text) if not self.in_literal(m.start()))
            self._names = names
        return self._names

    # ------------------------------------------------------------------ heads and right-hand sides

    def heads(self):
        """[(name, is_key, head start, rhs start)] of every assignment and keyed entry in live code."""
        out = []
        for m in _HEAD.finditer(self.text):
            if self.in_literal(m.start()) or self.in_literal(m.start("op")):
                continue
            out.append((m.group("name"), m.group("op") in (":", "=>"), m.start(), m.end()))
        for lit in self.lits:
            m = _KEY_OP.match(self.text, lit.end)
            if m and lit.value and not lit.interp:
                out.append((lit.value, True, lit.start, m.end()))
        for m in _LISP_HEAD.finditer(self.text):
            if not self.in_literal(m.start()):
                out.append((m.group("name"), False, m.start(), m.end()))
        return out

    def rhs_end(self, i: int):
        """Where the statement that starts at `i` ends, or None (unbalanced, or longer than MAX_RHS)."""
        t, n, depth, j = self.text, len(self.text), 0, i
        limit = min(n, i + MAX_RHS)
        while j < limit:
            lit = self.by_start.get(j)
            if lit is not None:
                j = lit.end
                continue
            c = t[j]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    return j
                depth -= 1
            elif c == "\n":
                if depth == 0 and not (_CONT_END.search(t, max(i, t.rfind("\n", 0, j) + 1), j)
                                       or _CONT_START.match(t, j + 1)):
                    return j
            elif depth == 0 and c in ";,":
                return j
            elif depth == 0 and (t.startswith("?>", j) or t.startswith("%>", j) or t.startswith("</", j)):
                return j
            j += 1
        return j if j == n and depth == 0 else None

    def container(self, a: int, b: int):
        """(value, why-not-whole or None, listy) of the right-hand side text[a:b], or None when it holds no
        material literal at all."""
        toks, j, t = [], a, self.text
        while j < b:
            lit = self.by_start.get(j)
            if lit is not None:
                toks.append(("I" if lit.interp else "Q" if lit.value else "E", lit))
                j = lit.end
                continue
            c = t[j]
            if c.isspace():
                j += 1
                continue
            m = _IDENT.match(t, j)
            if m:
                toks.append(("W", m.group(0)))
                j = m.end()
                continue
            if c.isdigit():
                toks.append(("N", c))
            elif c in "+&|~<>" or c == "." and t[j + 1:j + 2] in ("", " ", "\t", "\r", "\n", '"', "'", "$") \
                    or c == "-" and t[j + 1:j + 2] in ("", " ", "\t", "\r", "\n"):
                toks.append(("O", c))                 # a binary operator: what stands beside it is an operand
            else:
                toks.append(("P", c))
            j += 1
        qs = [k for k, (kind, _) in enumerate(toks) if kind == "Q"]
        if not qs:
            return None
        value = "".join(toks[k][1].value for k in qs)
        first, last = qs[0], qs[-1]
        names = self.names()
        listy = False
        for kind, v in toks[first:last + 1]:
            if kind in ("Q", "E"):
                continue
            if kind == "O" and v != "-" or kind == "P" and v in _GLUE_P:
                listy = listy or v == ","
                continue
            if kind == "W" and v.lower() in ("_", "concat"):
                continue
            return value, f"{_shown(v)} stands between its pieces", listy
        joins = False
        for k, (kind, v) in enumerate(toks):
            if first <= k <= last or kind in ("E", "O"):
                continue
            if kind == "I":
                return value, "an interpolated literal stands beside it", listy
            if kind == "Q":
                return value, "another literal stands beside it", listy
            if kind == "N":
                return value, "a number stands in it (an index, a slice, a count)", listy
            prv = toks[k - 1] if k > 0 else (None, None)
            nxt = toks[k + 1] if k + 1 < len(toks) else (None, None)
            if kind == "P":
                if v in _FRAME_P:
                    continue
                if v == "=" and prv[0] == "W" and nxt[0] == "E":
                    continue                          # a named separator: collapse=""
                return value, f"{_shown(v)} stands in it", listy
            word = v.lstrip("$@%")
            low = word.lower()
            if low in DENY:
                return value, f"{_shown(word)} changes the value", listy
            if word in names:
                return value, f"the name {_shown(word)} the file assigns stands in it", listy
            if low == "_":
                continue                              # a VB line continuation, an inferred size `[_]`
            if prv[0] == "O" or nxt[0] == "O":
                return value, f"the operand {_shown(word)} is joined to it", listy
            called = nxt[0] == "P" and nxt[1] in "([{.:!=" or nxt[0] == "W"      # a call, a type, a namespace
            method = prv[0] == "P" and prv[1] in ".-:"                         # `.join`, `-join`, `::Join`
            head = prv[0] == "P" and prv[1] == "(" and nxt[0] in ("Q", "E")        # a Lisp head: (str "a" "b")
            if not (called or method or head):
                return value, f"the word {_shown(word)} stands beside it as a value", listy
            joins = joins or any(w in low for w in JOIN_WORDS)
        if listy and not joins:
            return value, "a list of pieces that nothing joins", listy
        return value, None, listy

    def _bracket_map(self, positions):
        """One pass over the text: the innermost open bracket around each of `positions` (-1 at the top level),
        and for each bracket the number of material values (not keys) anywhere inside it."""
        t, n = self.text, len(self.text)
        want = sorted(set(positions))
        at, k, stack, count, material, deep = {}, 0, [], {}, [], False
        j = 0
        while j < n:
            while k < len(want) and want[k] <= j:
                at[want[k]] = stack[-1] if stack else -1
                k += 1
            lit = self.by_start.get(j)
            if lit is not None:
                if _SIBLING.fullmatch(lit.value) and not _KEY_OP.match(t, lit.end):
                    material.append(lit.start)
                    deep = deep or len(stack) > MAX_NEST
                    for o in stack[-MAX_NEST:]:
                        count[o] = count.get(o, 0) + 1
                j = lit.end
                continue
            c = t[j]
            if c in "([{":
                stack.append(j)
            elif c in ")]}" and stack:
                stack.pop()
            j += 1
        while k < len(want):
            at[want[k]] = stack[-1] if stack else -1
            k += 1
        self._brackets = (at, count, material, deep)

    def siblings(self, h: int, b: int) -> bool:
        """Whether the bracket that holds a keyed entry (head at `h`, value to `b`) holds another value of
        material (16 characters or more of an encoding's alphabet): the entries of one dict or list may be read
        joined, so no one of them is whole. A bracket nested deeper than MAX_NEST is not counted: then yes."""
        at, count, material, deep = self._brackets
        o = at.get(h, -1)
        if o < 0:
            return False                              # a key at the top level (YAML, an INI line): no bracket
        if deep:
            return True
        own = bisect.bisect_left(material, b) - bisect.bisect_left(material, h)
        return count.get(o, 0) - own > 0

    def name_whole(self, name: str, is_key: bool, a: int, b: int):
        """None when the value of `name` (assigned at text[a:b]) is all of it as far as the file shows, else
        why not."""
        if is_key and self.siblings(a, b):
            return "another value of its dict or list is material too"
        bare = re.escape(name.lstrip("$@%"))
        t = self.text
        interpolated = re.compile(r"[$@]\{?[ \t]*" + bare + r"(?!\w)|#\{[^}\n]*(?<!\w)" + bare + r"(?!\w)")
        for lit in self.interp_lits:
            if not (a <= lit.start < b) and interpolated.search(t, lit.start, lit.end):
                return "it is interpolated into another literal"
        mention = re.compile(r"(?<![\w$@%])[$@%]?" + bare + r"(?!\w)")
        for m in mention.finditer(t):
            s, e = m.start(), m.end()
            if a <= s < b:
                continue
            if self.in_literal(s) is not None:
                continue                              # text of another literal (its interpolation: above)
            if t[max(0, s - 1):s] == "." and not is_key:
                continue                              # a member of another object
            if _GROW_AFTER.match(t, e):
                return "it is assigned again or grown"
            if _glued_after(t, e) or _glued_before(t, s):
                return "it is joined to more text"
            if _MUTATE_AFTER.match(t, e):
                return "it is indexed or changed in place"
            call = _CALL_BEFORE.search(t, max(0, s - 64), s) or _LISP_CALL_BEFORE.search(t, max(0, s - 64), s)
            if call:
                low = call.group(1).lower().rsplit(".", 1)[-1]
                if low in _LISP_DEFS:
                    return "it is assigned again"
                if low in DENY or any(w in low for w in JOIN_WORDS) or low in ("push", "append", "extend", "insert",
                                                                               "str", "format", "sprintf"):
                    return f"it is handed to {_shown(call.group(1))}"
        return None

    # ------------------------------------------------------------------ copies

    def copies(self) -> list:
        out = []
        heads = self.heads()
        self._bracket_map([h for _, is_key, h, _ in heads if is_key])
        for name, is_key, h, a in heads:
            b = self.rhs_end(a)
            if b is None or b <= a:
                continue
            got = self.container(a, b)
            if got is None:
                continue
            value, why, _listy = got
            if len(value) < MIN_VALUE:
                continue                              # no material and no host: nothing to read or weigh
            memo = []

            def whole(why=why, name=name, is_key=is_key, h=h, b=b, memo=memo):
                # asked only of a value that gives a plan: the mention scan is linear in the file
                if not memo:
                    memo.append(why is None and self.live(h, b) and self.name_whole(name, is_key, h, b) is None)
                return memo[0]
            out.extend(self._read_value(value, whole, h, name))
        for m in _COMMENT_TAG.finditer(self.text):
            if self.in_literal(m.start()):
                continue
            for t, how in self._decode(m.group("tag"), m.group("payload")):
                out.append(Copy(t, how, False, "comment", m.start()))
        return out

    def _read_value(self, value: str, whole, at: int, name: str) -> list:
        """The copies one container's value gives; `whole()` says whether the container is the whole value."""
        out = []
        if self.depth < MAX_DEPTH and ('"' in value or "'" in value) and len(value) >= MIN_VALUE:
            inner = _Reader(value, None, self.depth + 1, self.budget)
            for c in inner.copies():
                out.append(Copy(c.plan_text, "host:" + c.how, c.whole and whole(), "host", at, name))
        if len(value) < MIN_VALUE or not _MATERIAL.fullmatch(value):
            return out
        m = _TAGGED.match(value)
        got = self._decode(m.group("tag"), m.group("payload")) if m else []
        kind = "tagged" if got else "container"
        if not got:
            got = self._decode(None, value)
        if len(got) > 1:
            out.extend(Copy(t, how, whole(), kind, at, name) for t, how in got)   # two plans: refused below
            return out
        for t, how in got:
            out.append(Copy(t, how, _complete(t) and whole(), kind, at, name))
        return out

    def _decode(self, tag, payload: str) -> list:
        """[(plan text, how)] distinct plans the value decodes to, under its tag when it names one."""
        key = (tag, payload)
        memo = self.budget["values"]
        if key in memo:
            return memo[key]
        if self.budget["decodes"] >= MAX_DECODES:
            self.budget["skipped"] = True             # a value left unread could be a second plan: see reading()
            return []
        self.budget["decodes"] += 1
        found = {}
        try:
            if tag == "LYR":
                lyr = plan_codec.optional("plan_layers")
                labels, _, rest = payload.partition("-")
                if lyr is not None and rest:
                    for t, chain in lyr.decode_plans(labels, rest):
                        found.setdefault(t, "lyr:" + "+".join(chain) + "|identity")
            else:
                desc = plan_codec.optional("descriptor")
                if desc is None:
                    raise MissingModule("descriptor", "descriptor.py did not load: no value can be decoded")
                if tag is not None and desc.tag_chain(tag) is None:
                    memo[key] = []
                    return []
                for row in desc.decode(tag, payload):
                    found.setdefault(row[0], row[1])
        except RuntimeError:
            raise
        except Exception:  # noqa: BLE001 - a value that breaks a decoder is no reading
            found = {}
        memo[key] = list(found.items())
        return memo[key]


def _complete(plan_text: str) -> bool:
    """A plan of a version whose fields are known holds all of them, and its counts agree (descriptor.checked)."""
    desc = plan_codec.optional("descriptor")
    try:
        return desc is not None and not desc.checked(plan_codec.flatten(plan_text), short_ok=False)
    except Exception:  # noqa: BLE001
        return False


# Block comments of any language, blanked whatever the extension (descriptor.live_code blanks those of the
# extension's own family). A pair that is not a comment in the file's language only costs a reading: what it
# blanks is never whole, though it is still read as a witness that can refuse the file.
_BLOCKS = (("/*", "*/"), ("<!--", "-->"), ("<#", "#>"), ("{-", "-}"), ("(*", "*)"), ("#|", "|#"), ("#[", "]#"),
           ("#=", "=#"), ("--[[", "]]"), ("%{", "%}"), ("\n=begin", "\n=end"), ("\n=pod", "\n=cut"),
           ("\n=head", "\n=cut"), ("#cs", "#ce"), ("#comments-start", "#comments-end"))


def _blank_blocks(code: str) -> str:
    spans = []
    for opener, closer in _BLOCKS:
        i = 0
        while True:
            a = code.find(opener, i)
            if a < 0:
                break
            b = code.find(closer, a + len(opener))
            if b < 0:
                break
            spans.append((a, b + len(closer)))
            i = b + len(closer)
    if not spans:
        return code
    out = list(code)
    for a, b in spans:
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def _live(text: str, ext: str) -> str:
    desc = plan_codec.optional("descriptor")
    if desc is None or not hasattr(desc, "live_code"):
        raise MissingModule("descriptor", "descriptor.py did not load: live code cannot be told from dead text")
    return _blank_blocks(desc.live_code(text, ext))


def _shown(s: str) -> str:
    s = str(s).encode("ascii", "backslashreplace").decode("ascii")
    return s if len(s) <= 40 else s[:40] + "..."


# ---------------------------------------------------------------------- literals

_SIMPLE = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b",
           "\\": "\\", '"': '"', "'": "'", "`": "`", "/": "/", "$": "$", "\n": ""}
_ESC = re.compile(r"\\(x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]{1,6}\}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|.)", re.S)


def unescape(raw: str) -> str:
    """A backslash-escaped body as the text it stands for; an escape this table does not know is kept."""
    if "\\" not in raw:
        return raw

    def one(m):
        e = m.group(1)
        if e[0] == "x":
            return chr(int(e[1:], 16))
        if e[0] == "u" and e[1:2] == "{":
            return chr(min(int(e[2:-1], 16), 0x10FFFF))
        if e[0] in "uU" and len(e) > 1:
            return chr(min(int(e[1:], 16), 0x10FFFF))
        if e[0] in "01234567":
            return chr(int(e, 8) & 0xFF) if e != "0" else "\0"
        return _SIMPLE.get(e, "\\" + e)
    return _ESC.sub(one, raw)


def _vb_literal(text: str, s: int):
    """The VB literal opened at text[s] (a `"`): `""` inside it is one quote, nothing else is an escape, and it
    ends on its line. (end, value), or None when it has no closer on its line."""
    k, n, buf = s + 1, len(text), []
    while k < n:
        c = text[k]
        if c == '"':
            if text.startswith('""', k):
                buf.append('"')
                k += 2
                continue
            return k + 1, "".join(buf)
        if c == "\n":
            return None
        buf.append(c)
        k += 1
    return None


def scan_literals(text: str, vb: bool = False) -> list:
    """[Lit] of the text, left to right, never overlapping. A quote with no closer on its line (a verbatim or
    triple-quoted literal: in the text) is no literal. With `vb` (a VB_EXTS file) only `"` opens a literal, and
    `"a""b"` is ONE literal whose value holds a quote, never two literals side by side."""
    out, i, n = [], 0, len(text)
    while i < n and len(out) < MAX_LITERALS:
        if vb:
            s = text.find('"', i)
            if s < 0:
                break
            got = _vb_literal(text, s)
            if got is None:
                i = s + 1
                continue
            out.append(Lit(s, got[0], got[1], False))
            i = got[0]
            continue
        m = _QUOTE.search(text, i)
        if not m:
            break
        s, q = m.start(), m.group(0)
        raw_prefix = s > 0 and text[s - 1] in "rR" and (s < 2 or not (text[s - 2].isalnum() or text[s - 2] == "_"))
        if q == '"' and s > 0 and text[s - 1] == "@":        # C# verbatim: "" is a quote, no escapes
            k, buf = s + 1, []
            while k < n:
                c = text[k]
                if c == '"':
                    if text.startswith('""', k):
                        buf.append('"')
                        k += 2
                        continue
                    break
                buf.append(c)
                k += 1
            if k >= n:
                i = s + 1
                continue
            out.append(Lit(s - 1, k + 1, "".join(buf), False))
            i = k + 1
            continue
        if text.startswith(q * 3, s):
            k = text.find(q * 3, s + 3)
            if k < 0:
                i = s + 3
                continue
            raw = text[s + 3:k]
            val = raw if raw_prefix else unescape(raw)
            out.append(Lit(s, k + 3, val, q != "'" and _INTERP.search(raw) is not None))
            i = k + 3
            continue
        k = s + 1
        while k < n:
            c = text[k]
            if c == "\\" and not raw_prefix:
                k += 2
                continue
            if c == q or c == "\n":
                break
            k += 1
        if k >= n or text[k] != q:
            i = s + 1
            continue
        raw = text[s + 1:k]
        val = raw if raw_prefix else unescape(raw)
        out.append(Lit(s, k + 1, val, q != "'" and _INTERP.search(raw) is not None))
        i = k + 1
    return out


_SCRIPT_OPEN = re.compile(r"<script\b(?P<attrs>[^>]*)>", re.I)
_LANG_ATTR = re.compile(r"\b(?:language|type)[ \t]*=[ \t]*[\"']?[ \t]*(?:text/|application/)?(?P<lang>[A-Za-z#.+-]+)",
                        re.I)
_RUNAT = re.compile(r"\brunat[ \t]*=[ \t]*[\"']?[ \t]*server\b", re.I)
_PAGE_LANG = re.compile(r"<%@[^%]*?\blanguage[ \t]*=[ \t]*[\"']?[ \t]*(?P<lang>[A-Za-z#.+-]+)", re.I)
_VB_LANGS = frozenset(("vbscript", "vbs", "vb", "visualbasic", "vbnet", "vb.net"))


def vb_spans(text: str, ext=None) -> list:
    """[(a, b)] the parts of the text written in a VB dialect, read with the VB quote rules. A VB_EXTS file is
    all VB. In a host file (HOST_EXTS) the dialect is named by its markers, never guessed: a `<script>` block
    whose language or type is VBScript (or VB), and, when the page language is VB (a `<%@ ... Language=VBScript
    %>` directive; an .asp page without one is VBScript), its `<% .. %>` blocks and its `runat=server` script
    blocks that name no language. Anything else is read with the C quote rules."""
    ext = (ext or "").lower().lstrip(".")
    if ext in VB_EXTS:
        return [(0, len(text))]
    if ext not in HOST_EXTS:
        return []
    low = text.lower()
    page = _PAGE_LANG.search(text)
    page_lang = page.group("lang").lower() if page else ("vbscript" if ext == "asp" else "")
    page_vb = page_lang in _VB_LANGS
    spans = []
    for m in _SCRIPT_OPEN.finditer(text):
        attrs = m.group("attrs")
        lang = _LANG_ATTR.search(attrs)
        if lang is not None:
            vb = lang.group("lang").lower() in _VB_LANGS
        else:
            vb = page_vb and _RUNAT.search(attrs) is not None
        end = low.find("</script", m.end())
        end = len(text) if end < 0 else end
        if vb:
            spans.append((m.end(), end))
    if page_vb:
        i = 0
        while True:
            a = text.find("<%", i)
            if a < 0:
                break
            b = text.find("%>", a + 2)
            b = len(text) if b < 0 else b
            if not text.startswith("<%@", a) and not text.startswith("<%--", a):
                spans.append((a + 2, b))
            i = b + 2
    spans.sort()
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def scan_dialects(text: str, spans) -> list:
    """[Lit] of the text with the VB quote rules inside `spans` (vb_spans) and the C rules outside. A literal never
    runs across the edge of a span."""
    if not spans:
        return scan_literals(text)
    if spans == [(0, len(text))]:
        return scan_literals(text, vb=True)
    out, at = [], 0
    parts = []
    for a, b in spans:
        if at < a:
            parts.append((at, a, False))
        parts.append((a, b, True))
        at = b
    if at < len(text):
        parts.append((at, len(text), False))
    for a, b, vb in parts:
        for lit in scan_literals(text[a:b], vb=vb):
            out.append(Lit(lit.start + a, lit.end + a, lit.value, lit.interp))
            if len(out) >= MAX_LITERALS:
                return out
    return out


# ---------------------------------------------------------------------- the file

def copies(text: str, ext=None) -> list:
    """[Copy] of every container (and host-literal container) that decodes to a plan, and of every tagged
    comment, in the text."""
    if not isinstance(text, str):
        text = plan_codec.text_of(text)
    return _Reader(text, ext).copies()


def reading(text: str, ext=None) -> Verdict:
    """The ONE plan the file's containers give whole (see the module doc), or a Verdict with plan_text None.
    A file with more values than MAX_DECODES is not read at all: a value left unread could be a second plan."""
    if not isinstance(text, str):
        text = plan_codec.text_of(text)
    reader = _Reader(text, ext)
    found = reader.copies()
    if reader.budget.get("skipped"):
        return Verdict(why=f"more than {MAX_DECODES} values to decode: not all could be weighed, none is taken")
    whole = [c for c in found if c.whole]
    if not whole:
        return Verdict(why="no container gives a whole plan" if found else None,
                       notes=[f"{c.kind} {c.name or '-'}: not whole" for c in found][:8])
    plans = {c.plan_text for c in whole}
    if len(plans) > 1:
        return Verdict(why=f"{len(plans)} whole containers give different plans")
    plan = next(iter(plans))
    for c in found:
        if c.plan_text != plan and not plan_codec.head_of(c.plan_text, plan):
            return Verdict(why=f"a {c.kind} copy gives another plan")
    try:
        continued = plan_codec.continued_plans(text, ext)
    except Exception:  # noqa: BLE001 - a check that fails proves nothing: not whole
        return Verdict(why="plan_codec's continuation check failed")
    if plan in continued or any(plan_codec.head_of(plan, t) for t in continued):
        return Verdict(why="plan_codec reads the plan going on past this container")
    first = whole[0]
    rep, _, tr = first.how.partition("|")
    agree = [c for c in found if c.plan_text == plan]
    return Verdict(plan_text=plan, how=rep, transform=tr or "identity", copies=len(agree),
                   tagged=any(c.kind in ("tagged", "comment") for c in agree),
                   notes=[f"{c.kind} {c.name or '-'}{' (whole)' if c.whole else ''}" for c in agree][:8])


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: blind_reader.py <specimen> [...]   (prints the plan each file's containers give whole)",
              file=sys.stderr)
        return 2
    status = 0
    for arg in argv:
        try:
            raw = Path(arg).read_bytes()
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})", file=sys.stderr)
            status = 1
            continue
        v = reading(plan_codec.text_of(raw), Path(arg).suffix)
        if v.plan_text:
            shown = v.plan_text.encode("ascii", "backslashreplace").decode("ascii")
            print(f"{arg}: plan ({v.copies} cop{'y' if v.copies == 1 else 'ies'}, {v.how}) {shown}")
        else:
            print(f"{arg}: no whole plan" + (f" ({v.why})" if v.why else ""))
    return status


if __name__ == "__main__":
    sys.exit(main())
