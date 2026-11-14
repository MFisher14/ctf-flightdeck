#!/usr/bin/env python3
"""Language-blind census of the control-flow form around a specimen's recovery call.

Usage:
  .venv/bin/python solvers/script-analysis/census.py <specimen> [...]

Every Script Analysis language so far asks one question about the control flow that wraps
the recovery of the plan ("Identify the exact Batch control-flow form."). The language
modules answer it with a parser of their own. This module answers it for a language nobody
has written a parser for, from tables of keyword pairs that belong to no single language:

    census(text, ext) -> None or {"klass": ..., "keyword": ..., "inner": ...}
    answer(q, text, ext) -> None, a plain name, or an unsure answer (labels.pick)

generic.py loads this file by name if it exists; nothing else depends on it.

How a specimen is read (nothing is executed, and `ext` never selects a rule):

  1. Lines become statements: comments are dropped, string literals are emptied, and a
     line is cut at ';', '{' and '}'.
  2. One pass keeps a stack of open blocks, whichever way the language closes them: a
     closing keyword (End If, fi, Wend, done, Loop, Next, esac, end), a brace, a batch
     parenthesis, or indentation after a header that ends in ':'.
  3. The recovery site is the statement that names the routine consuming the material,
     outside that routine's own body: a routine or label whose name contains `decode`;
     failing that `recover` or a HUNTRESS_ dispatch label; failing that `load`. When two
     such routines are chained (a decodeBase64 helper feeding the decoder), the site is
     the one at the end of the chain.
  4. The reading is the one block that encloses the site inside its routine, or the
     transfer keyword of the site itself (goto, call, gosub), or `direct`.
  5. A script that is a flat run of labels (an entry label containing `inspect`, no
     routines) is also read along that entry's path up to its first exit, for the two
     guards that enclose nothing: a one-line guard on a HUNTRESS_ marker and a one-line
     guard that aborts.

klass is one of direct, loop, guard, multiway, dispatch, subroutine. keyword is the
language's own word for the block (`for`, `do`, `select`, `try`, `goto`, `call`), joined to
what qualifies it (`for_l` for a loop switch, `if_defined` for a unary test, `on_error`), or
the error word a guard tests (`errorlevel`); `none` for direct. inner is the transfer
({"klass", "keyword"}) when a loop or guard wraps a goto, call or gosub, else None.

None means "no reading", never "direct": no site, two sites that read differently, a block
that was never closed or closed by the wrong word, an enclosing block of an unknown kind,
or more than one real block around the site. A constant-true guard (`If True Then`) is
layout: it is skipped when another block encloses the site, and reported as a guard when it
is the only wrapper. A wrong reading can cost probes on a new language, so every doubtful
case ends here as None and the question stays open for an agent.

`direct` is the costly mistake: every direct specimen of a language shares one key whose
only option is `direct`, so one wrapped call misread as direct, if it is the id that gets
probed, has the name rejected for all of them. So `direct` is claimed only for a plain
call. These are None as well:

  - a site inside the header of a block (`while ((d = decode(s)).length == 0) {`);
  - a site whose own statement carries control flow the block stack cannot see: a
    trailing modifier (`d = decode(s) if s`), `&&`, `||`, `and`, `or`, a ternary, a
    comprehension, an anonymous function, or the routine passed as a value
    (`pcall(decode, s)`);
  - a block the tables do not know: `eval {`, `1.times {`, `x.forEach(function () {`,
    a line that ends in ':' above deeper lines (`async for ...:`), a bare `do ... end`,
    a brace-less `else` in a brace language, a `trap`;
  - in an indented language, a site deeper than the block it was placed in;
  - a plain call in a routine that holds a goto (`goto run; run: d = decode(s);`);
  - a recovery routine that is defined but that nothing visibly calls (its call sits in
    a string: Execute, GetRef, eval), or one that is called but whose header this table
    did not read as a definition (`Decode_x(s) {`). The next tier of names is then not
    consulted: it would read the call of the recover routine, which is always plain;
  - on a flat path, a one-line guard that is neither on a HUNTRESS_ marker nor an abort,
    or a one-line loop with a switch (`for /l ... do set ...`) that is not the site.

Specimens are untrusted, and the solver runs inside a window of a few seconds, so the
work is bounded: whitespace runs are collapsed before any pattern is tried, and a
specimen with blocks nested deeper than _MAX_DEPTH, more than _MAX_NAMES recovery names
or more than _MAX_SITES call sites gives None instead of a slow answer.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import labels  # noqa: E402

KLASSES = ("direct", "loop", "guard", "multiway", "dispatch", "subroutine")

# Extension -> the language part of a ledger key (docs/ops/contracts.md, "Key spelling,
# pinned"). A new language uses its extension.
LANG_OF_EXT = {"cmd": "batch", "bat": "batch", "vbs": "vbs", "vbe": "vbs", "js": "jscript", "jse": "jscript",
               "ps1": "powershell"}

# ---------------------------------------------------------------------------- keyword tables
# Loop openers -> the family a closing word must name. Guards (if, unless, try) and
# multiway blocks (select, switch, match, case ... in) are told apart in _header.
_LOOPS = {"for": "for", "foreach": "for", "while": "while", "until": "until", "do": "do", "repeat": "repeat"}
# Blocks that are not control flow, but whose extent is unknown to a keyword table.
_UNKNOWN = ("with", "using", "begin", "class", "module", "namespace", "interface", "struct")
_ROUTINE_WORDS = "function|sub|def|func|fn|proc|procedure"
_MIDDLE = {"else", "elseif", "elsif", "elif", "catch", "except", "finally", "rescue", "ensure", "default",
           "otherwise", "when", "then"}

_IF, _FOR, _SWITCH, _ROUTINE, _OTHER = {"if"}, {"for"}, {"multi"}, {"routine"}, {"unknown"}
_ANY = frozenset()  # a bare `end` closes whatever is open
_CLOSE_ONE = {"endif": _IF, "fi": _IF, "wend": {"while"}, "endwhile": {"while"}, "done": {"for", "while", "until"},
              "esac": _SWITCH, "endswitch": _SWITCH, "endselect": _SWITCH, "endfor": _FOR, "endforeach": _FOR,
              "endtry": {"try"}, "endfunc": _ROUTINE, "endfunction": _ROUTINE, "endsub": _ROUTINE,
              "enddef": _ROUTINE, "endwith": _OTHER, "endclass": _OTHER}
_CLOSE_TWO = {"if": _IF, "unless": _IF, "select": _SWITCH, "switch": _SWITCH, "case": _SWITCH, "while": {"while"},
              "for": _FOR, "foreach": _FOR, "try": {"try"}, "function": _ROUTINE, "sub": _ROUTINE, "def": _ROUTINE,
              "property": _ROUTINE, "with": _OTHER, "using": _OTHER, "class": _OTHER, "module": _OTHER}

# Words that qualify a guard: a unary test joins the keyword (if_defined), an error-status
# word replaces it (errorlevel), because that is how the judge has named the two so far.
_UNARY_TESTS = {"defined", "exist", "exists", "isset", "empty"}
_ERROR_STATUS = {"errorlevel": "errorlevel", "%errorlevel%": "errorlevel", "err": "err", "error": "error",
                 "errno": "errno", "$?": "error", "$error": "error", "$lastexitcode": "lastexitcode"}
_CONSTANT_TRUE = {"true", "1", "$true", "1==1", "1 == 1", "1=1", "1 = 1", "1 -eq 1", "1 eq 1", ":"}

# Which names mark the recovery, best first: the first tier that has a call site is used.
_TIERS = (lambda n: "decode" in n,
          lambda n: "recover" in n or (n.startswith("huntress_") and "dispatch" in n),
          lambda n: re.search(r"(?:^|[_.-])load", n) is not None)
# Labels a flat script jumps to for layout, not for control: they never count as a site.
_LAYOUT_LABEL = re.compile(r"separator|emit|done|skip|unused|plan|inspect|exit|end|eof|next|continue")
_ABORT = re.compile(r"\b(?:exit|return|quit|die|raise|throw|abort|stop)\b|\bgoto\s+:?eof\b")
_OUTPUT = ("echo", "print", "write", "puts", "say", "return", "wscript.echo", "console.log")
_STOP = ("exit", "return", "quit", "stop")

# Limits that keep a hostile specimen from costing a timed window (see the module docstring).
_MAX_DEPTH = 64      # open blocks; the saved specimens nest 3 deep
_MAX_NAMES = 16      # recovery names in one tier; the saved specimens have 1 or 2
_MAX_SITES = 64      # call sites of one tier; the saved specimens have 1 or 2
_MAX_ESCAPED = 8192  # longest line on which the escaped-quote pattern is tried

# Control flow inside the site's own statement, which no block on the stack shows.
_WORD_EDGE = r"(?<![\w$.@%-])(?:{})(?![\w$-])"
# After the keyword of a one-line header (`if defined X for /l ... do call :label`): a second header.
_SECOND_HEADER = re.compile(_WORD_EDGE.format("if|unless|while|until|for|foreach|switch|select|try"))
# In a statement that is no header: a trailing modifier, a short circuit, a ternary, a
# comprehension, an anonymous function or a block that opens and closes inside parentheses.
_MODIFIER = re.compile(
    _WORD_EDGE.format("if|unless|while|until|for|foreach|switch|select|try|catch|except|rescue|else|then|do|when"
                      "|and|or|function|lambda|sub")
    + r"|&&|\|\||[{}]|=>")
_TERNARY = re.compile(r"(?<![$?])\?(?![?.>:])")  # `c ? a : b` when a ':' follows; not `$?`, `??`, `?.`, `?:`
# A brace after one of these is a value (`x = {`, `f({`, `return {`), not a block of its statement.
_VALUE_BRACE = re.compile(r"(?:[=(,:\[]|(?<![\w$.-])return)$")
# An anonymous function that is a routine of its own, not a callback handed to a call:
# `(function () {` at the start of a statement, or one that is assigned (`a.b = function () {`).
_ANONYMOUS = re.compile(r"(?:^[(!+~-]*|[=:]\s*)(?:async\s+)?function\s*\([^()]*\)$")
# A name with an argument list: `decode_x(`, `Decode-x (`.
_CALLED = re.compile(r"(?<![\w$-])([a-z_][\w$-]*)\s?\(")
_SPACES = re.compile(r"[ \t\f\v]{2,}")
_GOTO = re.compile(r"(?<![\w$.@%-])goto(?![\w$-])")

# ---------------------------------------------------------------------------- lexing
_COMMENT = re.compile(r"'|rem(?:\s|$)|::|#|//|--|;|/\*|<")
_TRAILING = re.compile(r"\s+(?://|#(?=\s|$)).*$|\s*&+\s*rem\b.*$")
_DQ = re.compile(r'"[^"\n]*"')
_DQ_ESCAPED = re.compile(r'"(?:[^"\\\n]|\\.)*"')
_SQ = re.compile(r"'[^'\n]*'")
_INTERPOLATION = re.compile(r"\$\{[^{}]*\}")
_WORDS = re.compile(r"(?:([a-z]+)(?![\w$-])(?:\s+([a-z]+)(?![\w$]))?)?")
_LABEL = re.compile(r":([\w$.-]+)|([a-z_]\w*):$")
_NOT_A_LABEL = _MIDDLE | {"try", "do", "begin", "end", "public", "private", "protected", "repeat", "loop"}
_DEF = re.compile(r"(?:(?:public|private|protected|static|export|async|local|default|friend|global)\s+)*"
                  rf"(?:{_ROUTINE_WORDS})\s+([\w$.:-]*[\w$])")
_FUNCTION_VALUE = re.compile(r"(?:(?:var|let|const|my|local|our)\s+)?\$?([\w$]+)\s*=\s*(?:async\s+)?"
                             r"(?:function\b|sub\b|lambda\b|\([^()]*\)\s*=>|[\w$]+\s*=>)")
_SHELL_DEF = re.compile(r"([\w$-]+)\s*\(\s*\)$")
_TRANSFER = re.compile(r"\b(goto|call|gosub)\s+:?([\w$.-]+)")
_ASSIGNED = re.compile(r"(?:case\b[^:]*:\s*)?(?:(?:var|let|const|my|local|set)\s+)?\$?([a-z_][\w$]*)\s*=(?!=)")
_GUARD_WORD = re.compile(r"(?:/[a-z]\s+)*(not\s+)?[\[(\s]*([a-z_$?%][\w$?%.]*)")


def _mask(s: str) -> str:
    """The line with every string literal emptied and a trailing comment removed, so a
    keyword inside a string or a comment is never read as code."""
    if "${" in s:
        s = _INTERPOLATION.sub("$v", s)
    if '"' in s:
        # The escaped form rescans the line from every quote that finds no partner, so it
        # is tried only on a line short enough for that to cost nothing.
        if '\\"' in s and len(s) <= _MAX_ESCAPED:
            escaped = _DQ_ESCAPED.sub('""', s)
            s = escaped if escaped.count('"') % 2 == 0 else _DQ.sub('""', s)
        else:
            s = _DQ.sub('""', s)
    if "'" in s:
        s = _SQ.sub("\0", s)
        lone = s.find("'")  # an apostrophe with no partner starts a comment (VBScript)
        if lone >= 0:
            s = s[:lone]
        s = s.replace("\0", "''")
    return _TRAILING.sub("", s).strip()


def _lex(text: str) -> list:
    """[(kind, text, line, indent, first on its line)], kind one of 's' (statement), '{', '}'."""
    out, in_comment = [], False
    for no, raw in enumerate(text.splitlines()):
        body = raw.strip()
        if not body:
            continue
        indent = len(raw) - len(raw.lstrip())
        low = body.lower()
        if in_comment:
            in_comment = "*/" not in low
            continue
        if low[0] == "@":
            low = low[1:].lstrip()
        if not low or _COMMENT.match(low):
            in_comment = low.startswith("/*") and "*/" not in low
            continue
        # Runs of blanks carry nothing, and the patterns below retry from every blank of a run.
        low = _mask(_SPACES.sub(" ", low))
        if not low:
            continue
        # An output statement carries free text (`echo for targets then ...`): one piece.
        if not (";" in low or "{" in low or "}" in low) or low.startswith("echo"):
            out.append(("s", low, no, indent, True))
            continue
        # Where to cut: ';' outside parentheses, and every brace except those of a group
        # that closes on its own line (`for (k in {a: 1}) {` has one block, not two).
        groups, cuts = [], []
        for i, ch in enumerate(low):
            if ch == "(":
                groups.append(len(cuts))
            elif ch == ")":
                if groups:
                    del cuts[groups.pop():]
            elif ch in "{}" or (ch == ";" and not groups):
                cuts.append(i)
        first, start = True, 0
        for i in cuts:
            piece = low[start:i].strip()
            if piece:
                out.append(("s", piece, no, indent, first))
                first = False
            if low[i] != ";":
                out.append((low[i], low[i], no, indent, first))
                first = False
            start = i + 1
        piece = low[start:].strip()
        if piece:
            out.append(("s", piece, no, indent, first))
    return out


# ---------------------------------------------------------------------------- blocks
class _Block:
    """One open block. klass: guard, loop, multiway, routine, neutral or unknown. base: the
    family its closing word must name. style: word, brace, paren, indent, or once (a header
    with no braces that governs the next statement only)."""
    __slots__ = ("klass", "kw", "base", "style", "indent", "layout", "fresh", "body")

    def __init__(self, klass, kw, base, layout=False):
        self.klass, self.kw, self.base, self.layout = klass, kw, base, layout
        self.style, self.indent, self.fresh = "word", 0, False
        self.body = None  # an indented block: the indentation of its first statement

    def arm(self):
        """The same block reopened by `} else {`, `} catch (e) {` or `) else (`."""
        twin = _Block(self.klass, self.kw, self.base, self.layout)
        twin.style, twin.indent = self.style, self.indent
        return twin


class _Rec:
    """One statement: where it is, what encloses it, and what was in force when it ran.

    err: False, True (an On Error guard is in force) or "unknown" (a trap, whose reach
    this table does not know). opens: the statement is the header of a block, so a call
    in it sits in the condition. deep: in an indented block, it is indented further than
    the block's first statement, so something this table did not see encloses it. scope:
    the routine it belongs to (0 outside any); a routine that holds a goto does not run
    in the order it is written (_Parse.jumps)."""
    __slots__ = ("text", "line", "indent", "chain", "inline", "err", "defines", "opens", "deep", "scope")

    def __init__(self, text, line, indent, chain, err, scope=0):
        self.text, self.line, self.indent, self.chain, self.err = text, line, indent, chain, err
        self.inline, self.defines, self.opens, self.deep, self.scope = None, None, False, False, scope


def _wrapped(rest: str) -> bool:
    """Is `rest` one parenthesised group and nothing else: `(p < 1)`, not `(a)==(b) echo`?"""
    if not rest.startswith("(") or not rest.endswith(")"):
        return False
    depth = 0
    for i, ch in enumerate(rest):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0:
            return i == len(rest) - 1
    return False


def _guard_keyword(rest: str) -> str:
    """`if`, joined to a unary test (`if_defined`) or replaced by the error word it tests."""
    m = _GUARD_WORD.match(rest)
    if not m:
        return "if"
    word = m.group(2)
    root = word.split(".", 1)[0]
    if word in _ERROR_STATUS or root in _ERROR_STATUS:
        return _ERROR_STATUS.get(word) or _ERROR_STATUS[root]
    if word in _UNARY_TESTS and re.match(r"\s+\S", rest[m.end():]):
        return "if_" + ("not_" if m.group(1) else "") + word
    return "if"


def _constant(rest: str) -> bool:
    """Is the condition of this guard a literal truth (`If True Then`, `if (1) {`, `if true:`)?"""
    cond = re.sub(r"(?:\bthen|[:({])$", "", rest).strip()
    while (cond.startswith("(") and cond.endswith(")") and _wrapped(cond)) or (cond[:1] == "[" and cond[-1:] == "]"):
        cond = cond[1:-1].strip()
    return cond in _CONSTANT_TRUE


def _header(s, w1, w2, rest):
    """The block a statement opens, or None. Only the keyword table decides."""
    if w1 in ("if", "unless"):
        return _Block("guard", _guard_keyword(rest) if w1 == "if" else "unless", "if", layout=_constant(rest))
    if w1 == "for":
        switch = re.match(r"/([a-z])\b", rest)  # a loop switch names the kind of loop (for /l)
        return _Block("loop", "for_" + switch.group(1) if switch else "for", "for")
    if w1 in _LOOPS:
        return _Block("loop", w1, _LOOPS[w1])
    if w1 in ("select", "switch") or (w1 == "match" and s.endswith(":")) or \
            (w1 == "case" and re.search(r"\s(?:in|of)$", s)):
        return _Block("multiway", w1, "multi")
    if w1 == "try":
        return _Block("guard", "try", "try")
    if w1 in _UNKNOWN:
        return _Block("unknown", w1, "unknown")
    return None


def _closes(s, w1, w2, top):
    """The families this statement closes: a set, _ANY for a bare `end`, or None."""
    if w1 == "end":
        # `end)` and `end,` close an anonymous function handed to a call (`pcall(function() ... end)`).
        return _ANY if re.fullmatch(r"end[\s)\]},;.]*", s) else _CLOSE_TWO.get(w2)
    if w1 in _CLOSE_ONE:
        return _CLOSE_ONE[w1]
    if w1 == "loop" and (s == "loop" or w2 in ("while", "until")):
        return {"do"}
    if w1 == "next" and re.fullmatch(r"next(?:\s+[\w$]+)?", s):
        return _FOR
    if w1 == "until" and top is not None and top.style == "word" and \
            (top.base == "repeat" or (top.base == "do" and top.kw == "do")):
        return {top.base}  # repeat ... until, and Do ... Until
    return None


class _Parse:
    """The statements of a specimen with their enclosing blocks, the names it defines, and
    whether every block was closed by a word that fits it."""

    def __init__(self, text):
        self.recs, self.defs, self.broken = [], {}, False
        self.jumps = set()  # routines (by scope) that hold a goto
        toks = _lex(text)
        braces = any(t[0] == "{" for t in toks)
        stack, err = [], {}
        pending, closed, after_close = None, None, False

        def scope():
            for b in reversed(stack):
                if b.klass == "routine":
                    return id(b)
            return 0

        def pop():
            b = stack.pop()
            if b.klass == "routine":
                err.pop(id(b), None)
            return b

        for i, (kind, s, no, indent, first) in enumerate(toks):
            if len(stack) > _MAX_DEPTH:  # every statement copies the stack: no reading, and no quadratic work
                self.broken = True
                break
            nxt = toks[i + 1] if i + 1 < len(toks) else ("", "", 0, 0, True)
            if kind != "s" and first:  # a brace that starts a line ends indented blocks like any line
                while stack and stack[-1].style == "indent" and indent <= stack[-1].indent:
                    pop()
            if kind == "{":
                if isinstance(pending, _Block):
                    blk = pending
                elif pending == "arm" and closed is not None:
                    blk = closed.arm()
                else:
                    blk = _Block("neutral", "", "brace")
                blk.style, pending, after_close = "brace", None, False
                stack.append(blk)
                continue
            if kind == "}":
                pending = None
                while stack and stack[-1].style == "once":
                    pop()
                if stack and stack[-1].style == "brace":
                    closed, after_close = pop(), True
                else:
                    self.broken = True
                continue

            pending = None
            m = _WORDS.match(s)
            w1, w2 = m.group(1) or "", m.group(2) or ""
            rest = s[len(w1):].lstrip()
            # `for = 3`, `match.group(1)`, `next, last`: an identifier that is spelled like a keyword.
            keyword = bool(w1) and not (rest[:1] in (".", ",") or (rest[:1] == "=" and rest[:2] != "=="))
            top = stack[-1] if stack else None
            closes = _closes(s, w1, w2, top) if keyword else None
            consumed = False
            if first:  # an indented block ends at the first line that is not indented deeper
                while stack and stack[-1].style == "indent" and indent <= stack[-1].indent:
                    top = stack[-1]
                    if indent == top.indent:
                        if closes is not None and (closes is _ANY or top.base in closes):
                            closed, consumed = pop(), True  # `endif;` after `if (x):`
                            break
                        if keyword and w1 in _MIDDLE:
                            break
                    pop()
            was_fresh = stack[-1] if stack and stack[-1].fresh else None
            once = stack[-1] if stack and stack[-1].style == "once" else None
            rec = _Rec(s, no, indent, tuple(stack), err.get(scope(), False), scope())
            self.recs.append(rec)
            if rec.scope and "goto" in s and _GOTO.search(s) and not s.startswith("on error"):
                self.jumps.add(rec.scope)
            if first and not consumed and stack and stack[-1].style == "indent" and indent > stack[-1].indent:
                # Indentation is the syntax here: a statement deeper than the first one of
                # its block hangs on a header this table did not read (or continues a line).
                if stack[-1].body is None:
                    stack[-1].body = indent
                rec.deep = indent > stack[-1].body
            do_tail = after_close and closed is not None and closed.base in ("do", "repeat")
            # `} else {` reopens the block its brace just closed. A middle word anywhere else
            # (`case 1: {`, `default {` as the first arm) belongs to the block still open.
            self._adjacent = after_close
            after_close = False
            self._statement(rec, s, w1, w2, rest, keyword, closes, consumed, nxt, braces, stack, err, scope, pop,
                            do_tail)
            if self._pending is not None:
                pending = self._pending
            if self._closed is not None:
                closed = self._closed
            if was_fresh is not None:
                was_fresh.fresh = False
            if once is not None and stack and stack[-1] is once:
                pop()
        if any(b.style != "indent" for b in stack):
            self.broken = True

    def _statement(self, rec, s, w1, w2, rest, keyword, closes, consumed, nxt, braces, stack, err, scope, pop, do_tail):
        self._pending = self._closed = None
        brace_next = nxt[0] == "{"
        if consumed:
            return
        if closes is not None:
            while stack and stack[-1].style == "once":
                pop()
            top = stack[-1] if stack else None
            if top is not None and top.style == "word" and (closes is _ANY or top.base in closes):
                self._closed = pop()
                if closes is _ANY and self._closed.kw == "do":
                    # A bare `do` closed by a bare `end` is a scope, not a loop (a loop's
                    # `do` ends in Loop, While or Until): a block of a kind unknown here.
                    self._closed.klass = "unknown"
            else:
                self.broken = True
            return
        if s[0] == ")":  # a batch block closes; `) else (` reopens it
            if stack and stack[-1].style == "paren":
                blk = pop()
                if s.endswith("(") and "else" in s:
                    stack.append(blk)
            return
        m = _LABEL.fullmatch(s) if s[0] != ":" else _LABEL.match(s)
        if m and (m.group(1) or m.group(2) not in _NOT_A_LABEL):
            name = m.group(1) or m.group(2)
            rec.defines = name
            self.defs.setdefault(name, ("label", len(self.recs) - 1, None))
            return

        # A routine: `Function X(...)`, `def x():`, `x = function(...) {`, `x() {`.
        m = _DEF.match(s)
        value = None if m else _FUNCTION_VALUE.match(s)
        shell = None if (m or value) else (_SHELL_DEF.fullmatch(s) if brace_next else None)
        if m or value or shell:
            name = (m or value or shell).group(1)
            blk = _Block("routine", name, "routine")
            rec.defines = name
            self.defs.setdefault(name, ("routine", len(self.recs) - 1, blk))
            if brace_next:
                self._pending = blk
            elif m and s.endswith(":"):
                blk.style, blk.indent = "indent", rec.indent
                stack.append(blk)
            elif m:
                stack.append(blk)
            return
        if not keyword:
            self._plain(rec, s, nxt, stack)
            return
        if w1 == "on" and w2 == "error":  # On Error Resume Next ... On Error GoTo 0
            err[scope()] = not re.search(r"goto\s+0\b", s)
            return
        if w1 == "trap":  # an error handler whose reach is not written as a block: `trap - ERR` lifts it
            err[scope()] = False if re.match(r"trap\s+-", s) else "unknown"
            self._plain(rec, s, nxt, stack)
            return
        if w1 in _MIDDLE or (w1 == "case" and not re.search(r"\s(?:in|of)$", s)):
            if brace_next:
                self._pending = "arm" if self._adjacent else None
            elif braces and s == "else" and not (stack and stack[-1].base == "if" and stack[-1].style != "brace"):
                # `else` alone on its line in a brace language governs the next statement
                # (`if (x) a; else\n b;`), and which guard it belongs to is already closed.
                blk = _Block("unknown", "else", "unknown")
                blk.style = "once"
                stack.append(blk)
            elif s.endswith(":") and stack and stack[-1].style == "indent" and rec.indent > stack[-1].indent \
                    and nxt[0] == "s" and nxt[4] and nxt[3] > rec.indent:
                # `case 1:` inside an indented `match`: the arm is a level of its own.
                blk = _Block("neutral", "", "arm")
                blk.style, blk.indent = "indent", rec.indent
                stack.append(blk)
            return
        if do_tail and w1 in ("while", "until"):  # `} while (cond);` belongs to the block just closed
            rec.opens = True
            return
        if s == "do" and stack and stack[-1].fresh:  # `while [ ... ]; do`
            return
        blk = _header(s, w1, w2, rest)
        if blk is None:
            self._plain(rec, s, nxt, stack)
            return
        rec.opens = True  # cleared below for a one-line form, whose statement follows its condition
        if brace_next:
            self._pending = blk
        elif s.endswith(":"):
            blk.style, blk.indent = "indent", rec.indent
            stack.append(blk)
        elif blk.base == "if":
            if s.endswith("then") or (nxt[0] == "s" and nxt[1] == "then"):
                stack.append(blk)
            elif s.endswith("("):
                blk.style = "paren"
                stack.append(blk)
            elif braces and _wrapped(rest):
                blk.style = "once"
                stack.append(blk)
            else:  # `If c Then stmt`, `if cond stmt`
                rec.inline, rec.opens = blk, False
        elif blk.klass == "loop" and blk.base != "do" and blk.base != "repeat":
            if re.search(r"\bdo\s*\($", s):
                blk.style = "paren"
                stack.append(blk)
            elif re.search(r"\bdo\s+\S", s):  # `for ... do stmt`
                rec.inline, rec.opens = blk, False
            elif braces and _wrapped(rest):
                blk.style = "once"
                stack.append(blk)
            else:
                blk.fresh = not s.endswith("do")
                stack.append(blk)
        else:
            stack.append(blk)

    def _plain(self, rec, s, nxt, stack):
        """A statement no table knows. If a block hangs on it, that block is of an unknown
        kind, and a site inside it gets no reading instead of `direct`:

          eval {            1.times {            x.forEach(function (p) {
          async for b in g():   (a line that ends in ':' above deeper lines)

        A brace is not a block of its statement when the statement is an arm of the
        multiway block around it (`1 { ... }` inside `switch`) or when the brace is on a
        later line. An anonymous function that is not a callback is a routine of its own."""
        if nxt[0] == "{":
            top = stack[-1] if stack else None
            if nxt[2] != rec.line or (top is not None and top.klass == "multiway"):
                return
            if _VALUE_BRACE.search(s):
                # A literal or a script block: a routine named inside it is handed over as
                # a value (`{1: decode}[1](s)`, `$b = { Decode-x $s }`), not called here.
                self._pending = _Block("unknown", "value", "unknown")
            elif _ANONYMOUS.search(s):
                self._pending = _Block("routine", "", "routine")
            else:
                self._pending = _Block("unknown", s.split(None, 1)[0], "unknown")
        elif s.endswith(":") and nxt[0] == "s" and nxt[4] and nxt[2] > rec.line and nxt[3] > rec.indent:
            blk = _Block("unknown", s.split(None, 1)[0], "unknown")
            blk.style, blk.indent = "indent", rec.indent
            stack.append(blk)


# ---------------------------------------------------------------------------- reading
def _transfer(text: str, name: str):
    """(klass, keyword) when the statement hands control to `name` by goto, call or gosub."""
    for m in _TRANSFER.finditer(text):
        if m.group(2) == name:
            return ("dispatch", "goto") if m.group(1) == "goto" else ("subroutine", m.group(1))
    return None


def _read(rec, name, jumps=()):
    """The reading of one site: (klass, keyword, inner), or None when it is doubtful.
    `jumps` are the routines that hold a goto (see _Parse.jumps)."""
    blocks = [rec.inline] if rec.inline is not None else []
    for b in reversed(rec.chain):
        if b.klass == "routine":
            break
        blocks.append(b)
    if any(b.klass == "unknown" for b in blocks) or rec.opens or rec.deep or rec.err == "unknown":
        return None
    real = [b for b in blocks if b.klass in ("guard", "loop", "multiway") and not b.layout]
    moved = _transfer(rec.text, name)
    if len(real) > 1 or (rec.err and (real or moved)):
        return None  # two wrappers: which one the form is named after is not ours to guess
    if rec.scope in jumps and not moved:
        return None  # `goto run ... run: d = decode(s)` inside a routine: a dispatch this walk does not follow
    # Control flow written inside the statement itself: see the module docstring.
    text = rec.text
    lead = _WORDS.match(text).group(1) or ""
    if rec.inline is not None:
        if _SECOND_HEADER.search(text, len(lead)):
            return None  # `if defined X for /l %%i in (1,1,1) do call :label`: two wrappers
    elif _MODIFIER.search(text) or (lead in _MIDDLE and not real):
        return None  # `d = decode(s) if s`, `s && (d = decode(s))`, an `else stmt` whose guard is closed
    mark = _TERNARY.search(text)
    if mark and ":" in text[mark.end():]:
        return None  # `d = s ? decode(s) : []`
    if re.search(r"(?<![\w$-])" + re.escape(name) + r"\s*[,\]}]", text):
        return None  # the routine handed over as a value: `pcall(decode, s)`, `{1: decode}[1](s)`
    if real:
        return (real[0].klass, real[0].kw, moved)
    if moved:
        return moved + (None,)
    if rec.err:
        return ("guard", "on_error", None)
    if any(b.layout for b in blocks):
        return ("guard", "if", None)
    return ("direct", "none", None)


def _sites(p):
    """[(statement, name)] for the best tier of recovery names that is used anywhere
    outside its own definition. None when there is no telling: a routine of a tier that
    nothing visibly calls (its call is in a string, so the next tier would read the wrong
    statement), or more names or sites than a specimen has any reason to hold."""
    for tier in _TIERS:
        names = [(name, d) for name, d in p.defs.items() if tier(name)]
        if len(names) > _MAX_NAMES:
            return None
        found = []
        for name, (kind, at, blk) in names:
            ref = re.compile(r"(?<![\w$-])" + re.escape(name) + r"(?![\w-])")
            for i, rec in enumerate(p.recs):
                if i == at or (blk is not None and any(b is blk for b in rec.chain)):
                    continue
                if ref.search(rec.text):
                    found.append((rec, name))
            if len(found) > _MAX_SITES:
                return None
        if found:
            return found
        if any(kind == "routine" for _, (kind, _at, _blk) in names):
            return None
        # A call of a name of this tier that was never seen defined (`Decode_x(s) {` in a
        # language whose routine header this table does not read): the specimen has such
        # a routine, so a lower tier would read the wrong statement, and read it `direct`.
        for rec in p.recs:
            if any(tier(m.group(1)) for m in _CALLED.finditer(rec.text)):
                return None
    return []


def _consumers(sites):
    """Drop a site whose result a site of another routine takes as its input.

    A specimen can hold two routines with `decode` in their names: a helper that reads the
    stored representation (decodeBase64) and the routine that undoes the transform. The
    form in question wraps the second, the one at the end of the chain, so a site that
    only feeds another one is the loader. Two sites of the SAME routine stay two sites."""
    keep = []
    for rec, name in sites:
        m = _ASSIGNED.match(rec.text)
        var = re.compile(r"(?<![\w$])" + re.escape(m.group(1)) + r"(?![\w$])") if m else None
        fed = var is not None and any(
            other is not rec and other_name != name and other.line >= rec.line
            and var.search(other.text.split("=", 1)[-1]) for other, other_name in sites)
        if not fed:
            keep.append((rec, name))
    return keep or sites


def _flat(p, readings):
    """Read a flat script along its entry label: add the guards that enclose nothing to
    `readings`. Returns False when the path holds something this table cannot place, True
    when the path was read, None when the script has no such entry."""
    entries = [at for name, (kind, at, blk) in p.defs.items() if kind == "label" and "inspect" in name]
    if len(entries) != 1:
        return None
    emits = False
    for rec in p.recs[entries[0] + 1:]:
        if rec.chain:
            return False  # a block on the path: its reach is not something a flat walk knows
        text = rec.text
        if rec.defines:
            continue
        if rec.inline is None and text.startswith(_STOP):
            break
        emits = emits or text.startswith(_OUTPUT)
        for m in _TRANSFER.finditer(text):
            target = p.defs.get(m.group(2))
            if target and target[0] == "label" and not any(t(m.group(2)) for t in _TIERS) \
                    and not _LAYOUT_LABEL.search(m.group(2)):
                return False  # a jump to a label of unknown purpose
        guard = rec.inline
        if guard is not None and not guard.layout \
                and not any(t(m.group(2)) for m in _TRANSFER.finditer(text) for t in _TIERS):
            if guard.klass != "guard":
                # A plain `for ... do` joins the fragments in every form. A loop with a
                # switch (`for /l ... do set ...`) may be the form itself: no reading.
                if guard.kw != "for":
                    return False
            elif re.search(r"\bhuntress_\w+", text) or _ABORT.search(text):
                readings.append((guard.klass, guard.kw, None))
            else:
                return False  # a guard on the path that is neither of the two known kinds
    if not readings and not emits:
        return None  # nothing on the path recovers or emits anything
    return True


def census(text, ext=None):
    """The control-flow form around the recovery of the plan, or None.

    Returns {"klass", "keyword", "inner"}; see the module docstring. `ext` is accepted for
    the caller's convenience and never changes the reading: the tables are the same for
    every language. Never raises: a specimen this cannot read gives None."""
    try:
        if isinstance(text, (bytes, bytearray)):
            data = bytes(text)
            text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("utf-8", "replace")
        p = _Parse(text.lstrip("﻿"))
        if p.broken:
            return None
        sites = _sites(p)
        if sites is None:
            return None
        readings = [_read(rec, name, p.jumps) for rec, name in _consumers(sites)]
        flat = _flat(p, readings)
        if flat is False or None in readings:
            return None
        if not readings:
            if not flat:
                return None
            readings = [("direct", "none", None)]
        if len(set(readings)) != 1:
            return None
        klass, keyword, inner = readings[0]
        return {"klass": klass, "keyword": keyword,
                "inner": {"klass": inner[0], "keyword": inner[1]} if inner else None}
    except Exception as e:  # noqa: BLE001 - a hook must never take the lane solver down
        print(f"[census] no reading ({type(e).__name__}: {e})", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------- answering
def language(ext) -> str:
    """The language part of a ledger key for a file extension ('.CMD' -> 'batch')."""
    ext = re.sub(r"[^a-z0-9_+-]", "", str(ext or "").lower().rsplit(".", 1)[-1])
    return LANG_OF_EXT.get(ext, ext or "unknown")


def is_control_question(q) -> bool:
    """Does the question ask for the control-flow form? Read from its id; from its wording only when the
    id names no field (fewer than three words and no `field` from generic.with_fields). Day 12: a text
    that says "control-flow" in a question about something else must not make it a control question."""
    qid = str(q.get("qid") or q.get("id") or "")
    if re.search(r"(?:^|-)control(?:-flow|-form)?$", qid):
        return True
    field = q.get("field")
    if (isinstance(field, str) and field) or len(re.sub(r"^set\d+\.", "", qid).split("-", 2)) == 3:
        return False
    return bool(re.search(r"control[- ]flow", str(q.get("question") or ""), re.I))


def options(reading, vocabulary=None) -> list:
    """Candidate names for a reading, best first: the names built from its keyword, with
    the names of the wrapped transfer right after the first one (the judge named
    `for /l ... do call :label` after the call), and `direct` last."""
    if vocabulary is None:
        vocabulary = labels.family("script.control/")
    keyword, klass = reading["keyword"], reading["klass"]
    names = labels.patterns(keyword, klass, vocabulary)
    if keyword == "foreach":  # the same loop under the keyword the judge already knows
        names += [n for n in labels.patterns("for", klass, vocabulary) if n not in names]
    inner = reading.get("inner")
    if inner:
        nested = [n for n in labels.patterns(inner["keyword"], inner["klass"], vocabulary)
                  if n != "direct" and n not in names[:1]]
        names = names[:1] + nested + [n for n in names[1:] if n not in nested]
    if "direct" in names:
        names = [n for n in names if n != "direct"] + ["direct"]
    return names


def answer(q, text, ext):
    """The answer to a control-flow question: labels.pick over the census of `text`.

    None when the question is about something else or the census has no reading. The key
    is script.control/<language>.<keyword>, so a name the judge accepts for one specimen
    answers every specimen with the same keyword, on this variant and the next."""
    if not is_control_question(q):
        return None
    reading = census(text, ext)
    if reading is None:
        return None
    return labels.pick(f"script.control/{language(ext)}.{reading['keyword']}", options(reading))


def main(argv) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print("usage: census.py <specimen> [...]", file=sys.stderr)
        return 2
    for path in argv:
        try:
            data = Path(path).read_bytes()
        except OSError as e:
            print(f"census.py: {path}: {e.strerror or e}", file=sys.stderr)
            return 2
        reading = census(data, Path(path).suffix)
        if reading is None:
            print(f"{path}: no reading")
            continue
        inner = reading["inner"]
        print(f"{path}: klass={reading['klass']} keyword={reading['keyword']}"
              f" inner={inner['keyword'] if inner else None}"
              f" key=script.control/{language(Path(path).suffix)}.{reading['keyword']}"
              f" options={','.join(options(reading))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
