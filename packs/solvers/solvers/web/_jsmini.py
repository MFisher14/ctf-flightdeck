"""A pure, bounded evaluator for a small subset of JavaScript (B-127): enough to run a page's client-side
check function (a 53-bit string hash, a djb2 / FNV / hashCode loop, a char-code transform, an atob of a
constant) on candidate inputs, in process, with no JavaScript engine.

It is NOT a JavaScript engine and it never executes a fetched page: there is no DOM, no timer, no network,
no file, no `eval`/`Function`, no `import`, no prototype, no `this`, no host object of any kind. The only
names a program can reach are the ones this module defines (Math, String.fromCharCode, parseInt, atob,
btoa, the digest helpers md5/sha1/sha256/sha512 and CryptoJS.<digest>, ...) and the program's own
functions and constants. Every expression and statement costs one step against `max_steps`; a string or
array past MAX_LEN, a call deeper than MAX_DEPTH, or an unsupported construct raises JsLimit /
JsUnsupported, never a hang. A name the program does not define raises Unresolved(name): the caller uses
that to find the input slot of a gate (`document.getElementById('f').value` is unresolved here).

    toks = tokenize(src)                      # [Tok]; JsSyntax on an unterminated string or comment
    p = Parser(toks, i)                       # parse from token i
    p.function_declaration(); p.var_statement(); p.paren_expression(); p.expression(); p.statement()
    interp = Interp(max_steps=200_000)
    interp.define(name, value_or_ast)         # a global (functions: Closure from a 'fn' node)
    interp.eval(expr_ast, {"name": value})    # value; Unresolved / JsLimit / JsUnsupported / JsThrow
    interp.call(closure, [args])
    strict_equal(a, b); loose_equal(a, b); to_str(v); to_number(v)

AST nodes are tuples whose first item names the kind; see Parser for the shapes.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import urllib.parse

MAX_SRC = 2 << 20           # characters of one source the tokenizer reads
MAX_TOKENS = 400_000        # tokens of one source
MAX_LEN = 1 << 20           # characters of one string / elements of one array a program may build
MAX_DEPTH = 64              # nested calls
MAX_PARSE_DEPTH = 200       # nested expressions in the parser


class JsError(Exception):
    """Base of everything this module raises on purpose."""


class JsSyntax(JsError):
    pass


class JsUnsupported(JsError):
    pass


class JsLimit(JsError):
    pass


class JsThrow(JsError):
    """A `throw` statement in the evaluated program, or a TypeError the subset models."""


class Unresolved(JsError):
    def __init__(self, name):
        super().__init__(f"unresolved name {name!r}")
        self.name = name


class _Undefined:
    __slots__ = ()

    def __repr__(self):
        return "undefined"


UNDEF = _Undefined()


# ---------------------------------------------------------------------------------------------- tokens

class Tok:
    __slots__ = ("kind", "value", "pos", "nl", "end")

    def __init__(self, kind, value, pos, nl, end):
        self.kind, self.value, self.pos, self.nl, self.end = kind, value, pos, nl, end

    def __repr__(self):
        return f"Tok({self.kind},{self.value!r})"


_PUNCT = sorted(""">>>= ... === !== **= <<= >>= >>> &&= ||= ??= => == != <= >= && || ?? ?. ++ -- += -= *= /=
%= &= |= ^= ** << >> { } ( ) [ ] ; , < > + - * / % & | ^ ! ~ ? : = . @ #""".split(), key=len, reverse=True)
_REGEX_AFTER_WORDS = frozenset({"return", "typeof", "case", "in", "of", "new", "delete", "void", "throw",
                                "instanceof", "do", "else", "yield", "await"})
_ID_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$")
_ID_PART = _ID_START | frozenset("0123456789")


def _is_id_start(ch):
    return ch in _ID_START or (ch > "\x7f" and ch.isalpha())


def _is_id_part(ch):
    return ch in _ID_PART or (ch > "\x7f" and ch.isalnum())


def _read_escape(src, i):
    """(char(s), next index) for the escape whose backslash is at src[i-1]."""
    ch = src[i]
    simple = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
    if ch in simple and not (ch == "0" and i + 1 < len(src) and src[i + 1].isdigit()):
        return simple[ch], i + 1
    if ch == "x":
        h = src[i + 1:i + 3]
        if len(h) == 2 and all(c in "0123456789abcdefABCDEF" for c in h):
            return chr(int(h, 16)), i + 3
        raise JsSyntax("bad \\x escape")
    if ch == "u":
        if src[i + 1:i + 2] == "{":
            end = src.find("}", i + 2)
            if end < 0:
                raise JsSyntax("bad \\u{} escape")
            try:
                return chr(int(src[i + 2:end], 16)), end + 1
            except (ValueError, OverflowError):
                raise JsSyntax("bad \\u{} escape") from None
        h = src[i + 1:i + 5]
        if len(h) == 4 and all(c in "0123456789abcdefABCDEF" for c in h):
            return chr(int(h, 16)), i + 5
        raise JsSyntax("bad \\u escape")
    if ch == "\r" and src[i + 1:i + 2] == "\n":
        return "", i + 2
    if ch in "\n\r  ":
        return "", i + 1
    return ch, i + 1


def _scan_string(src, i, quote):
    out, n = [], len(src)
    while i < n:
        ch = src[i]
        if ch == quote:
            return "".join(out), i + 1
        if ch == "\\":
            if i + 1 >= n:
                break
            s, i = _read_escape(src, i + 1)
            out.append(s)
            continue
        if ch == "\n":
            raise JsSyntax("newline in string literal")
        out.append(ch)
        i += 1
    raise JsSyntax("unterminated string literal")


def _scan_template(src, i):
    """(([cooked strings], [expression sources]), next index) for a template literal after its backquote."""
    strs, exprs, cur, n = [], [], [], len(src)
    while i < n:
        ch = src[i]
        if ch == "`":
            strs.append("".join(cur))
            return (strs, exprs), i + 1
        if ch == "\\":
            if i + 1 >= n:
                break
            s, i = _read_escape(src, i + 1)
            cur.append(s)
            continue
        if ch == "$" and src[i + 1:i + 2] == "{":
            strs.append("".join(cur))
            cur = []
            depth, j = 1, i + 2
            while j < n and depth:
                c = src[j]
                if c in "'\"":
                    _, j = _scan_string(src, j + 1, c)
                    continue
                if c == "`":
                    _, j = _scan_template(src, j + 1)
                    continue
                depth += (c == "{") - (c == "}")
                j += 1
            if depth:
                break
            exprs.append(src[i + 2:j - 1])
            i = j
            continue
        cur.append(ch)
        i += 1
    raise JsSyntax("unterminated template literal")


def _scan_number(src, i):
    n = len(src)
    j = i
    if src[j] == "0" and j + 1 < n and src[j + 1] in "xXoObB":
        base = {"x": 16, "o": 8, "b": 2}[src[j + 1].lower()]
        j += 2
        k = j
        while k < n and (src[k].isalnum() or src[k] == "_"):
            k += 1
        digits = src[j:k].replace("_", "")
        if digits.endswith("n"):
            return ("bigint", digits), k
        try:
            return ("num", float(int(digits, base))), k
        except ValueError:
            raise JsSyntax(f"bad number literal {src[i:k]!r}") from None
    while j < n and (src[j].isdigit() or src[j] == "_"):
        j += 1
    if j < n and src[j] == "n":
        return ("bigint", src[i:j]), j + 1
    if j < n and src[j] == ".":
        j += 1
        while j < n and (src[j].isdigit() or src[j] == "_"):
            j += 1
    if j < n and src[j] in "eE":
        k = j + 1
        if k < n and src[k] in "+-":
            k += 1
        if k < n and src[k].isdigit():
            j = k
            while j < n and src[j].isdigit():
                j += 1
    text = src[i:j].replace("_", "")
    try:
        return ("num", float(text)), j
    except ValueError:
        raise JsSyntax(f"bad number literal {text!r}") from None


def _regex_allowed(prev):
    if prev is None:
        return True
    if prev.kind in ("num", "str", "tmpl", "regex", "bigint"):
        return False
    if prev.kind == "name":
        return prev.value in _REGEX_AFTER_WORDS
    return prev.value not in (")", "]", "}")


def _scan_regex(src, i):
    n, j, in_class = len(src), i, False
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            raise JsSyntax("newline in regex literal")
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "/":
            k = j + 1
            while k < n and _is_id_part(src[k]):
                k += 1
            return (src[i:j], src[j + 1:k]), k
        j += 1
    raise JsSyntax("unterminated regex literal")


def tokenize(src: str) -> list:
    """The tokens of a JavaScript source. Comments (and HTML-like <!-- / --> line openers) are dropped;
    `nl` on a token says a line break came before it (automatic semicolons)."""
    if len(src) > MAX_SRC:
        src = src[:MAX_SRC]
    out, i, n, nl = [], 0, len(src), False
    prev = None
    while i < n:
        if len(out) > MAX_TOKENS:
            raise JsLimit("too many tokens")
        ch = src[i]
        if ch in "\n\r  ":
            nl = True
            i += 1
            continue
        if ch.isspace():
            i += 1
            continue
        if src.startswith("//", i) or src.startswith("<!--", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                raise JsSyntax("unterminated block comment")
            if "\n" in src[i:j]:
                nl = True
            i = j + 2
            continue
        start = i
        if ch in "'\"":
            val, i = _scan_string(src, i + 1, ch)
            tok = Tok("str", val, start, nl, i)
        elif ch == "`":
            val, i = _scan_template(src, i + 1)
            tok = Tok("tmpl", val, start, nl, i)
        elif ch.isdigit() or (ch == "." and i + 1 < n and src[i + 1].isdigit()):
            (kind, val), i = _scan_number(src, i)
            tok = Tok(kind, val, start, nl, i)
        elif _is_id_start(ch) or ch == "\\":
            j = i + 1
            while j < n and _is_id_part(src[j]):
                j += 1
            tok = Tok("name", src[i:j], start, nl, j)
            i = j
        elif ch == "/" and _regex_allowed(prev):
            val, i = _scan_regex(src, i + 1)
            tok = Tok("regex", val, start, nl, i)
        else:
            p = next((p for p in _PUNCT if src.startswith(p, i)), ch)
            i += len(p)
            tok = Tok("punct", p, start, nl, i)
        out.append(tok)
        prev, nl = tok, False
    out.append(Tok("eof", None, n, nl, n))
    return out


# ---------------------------------------------------------------------------------------------- parser

_BINARY = {
    "??": 1, "||": 2, "&&": 3, "|": 4, "^": 5, "&": 6,
    "==": 7, "!=": 7, "===": 7, "!==": 7,
    "<": 8, ">": 8, "<=": 8, ">=": 8, "instanceof": 8, "in": 8,
    "<<": 9, ">>": 9, ">>>": 9, "+": 10, "-": 10, "*": 11, "/": 11, "%": 11, "**": 12,
}
_ASSIGN = frozenset({"=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "**=",
                     "&&=", "||=", "??="})
_RESERVED_STMT = frozenset({"class", "import", "export", "with", "switch", "try", "yield", "debugger"})


class Parser:
    """A recursive-descent / precedence-climbing parser over a token list, from any start index.

    Expressions: ('num', v) ('str', s) ('bigint', s) ('regex', (body, flags)) ('tmpl', strs, exprs)
    ('name', id) ('arr', [e|('spread', e)|('hole',)]) ('obj', [(key_expr, value_expr)]) ('fn', name,
    params, body, arrow) with params [(target, default_or_None, rest)] and body a block or an expression
    ('member', obj, prop_expr, optional) ('call', callee, args, optional) ('new', callee, args)
    ('unary', op, e) ('update', op, prefix, target) ('bin', op, l, r) ('logic', op, l, r)
    ('cond', t, a, b) ('assign', op, target, value) ('seq', [e]) ('this',) ('input',) -- the last is
    never parsed: callers splice it in for the input slot of a gate.
    Statements: ('var', kind, [(target, init)]) ('fndecl', name, fn) ('if', c, a, b)
    ('for', init, test, update, body) ('forof', kind, target, iter, body) ('forin', kind, target, obj,
    body) ('while', c, body) ('dowhile', body, c) ('return', e) ('break',) ('continue',) ('block', [s])
    ('expr', e) ('empty',) ('throw', e).
    Patterns: ('name', id), ('arrpat', [pattern|None]), ('objpat', [(key, pattern, default)])."""

    def __init__(self, toks, i=0):
        self.t, self.i, self.depth = toks, i, 0

    # -- helpers
    @property
    def tok(self):
        return self.t[self.i]

    def peek(self, k=1):
        j = min(self.i + k, len(self.t) - 1)
        return self.t[j]

    def at(self, value, kind=None):
        tk = self.t[self.i]
        return tk.value == value and (tk.kind == (kind or tk.kind)) and tk.kind in ("punct", "name")

    def eat(self, value):
        if self.at(value):
            self.i += 1
            return True
        return False

    def expect(self, value):
        if not self.eat(value):
            raise JsSyntax(f"expected {value!r}, got {self.tok.value!r}")

    def name(self):
        tk = self.tok
        if tk.kind != "name":
            raise JsSyntax(f"expected a name, got {tk.value!r}")
        self.i += 1
        return tk.value

    def semi(self):
        if self.eat(";"):
            return
        tk = self.tok
        if tk.kind == "eof" or tk.value == "}" or tk.nl:
            return
        raise JsSyntax(f"expected ';', got {tk.value!r}")

    def _enter(self):
        self.depth += 1
        if self.depth > MAX_PARSE_DEPTH:
            raise JsLimit("expression nested too deeply")

    # -- statements
    def statement(self):
        tk = self.tok
        if tk.kind == "punct":
            if tk.value == "{":
                return self.block()
            if tk.value == ";":
                self.i += 1
                return ("empty",)
        if tk.kind == "name":
            v = tk.value
            if v in ("var", "let", "const") and (v != "let" or self.peek().kind in ("name", "punct")
                                                 and self.peek().value not in ("=", "(", ".")):
                return self.var_statement()
            if v == "function" or (v == "async" and self.peek().value == "function" and not self.peek().nl):
                return self.function_declaration()
            if v == "if":
                self.i += 1
                c = self.paren_expression()
                a = self.statement()
                b = self.statement() if self.eat("else") else None
                return ("if", c, a, b)
            if v == "for":
                return self.for_statement()
            if v == "while":
                self.i += 1
                c = self.paren_expression()
                return ("while", c, self.statement())
            if v == "do":
                self.i += 1
                body = self.statement()
                self.expect("while")
                c = self.paren_expression()
                self.eat(";")
                return ("dowhile", body, c)
            if v == "return":
                self.i += 1
                if self.at(";") or self.at("}") or self.tok.kind == "eof" or self.tok.nl:
                    self.eat(";")
                    return ("return", None)
                e = self.expression()
                self.semi()
                return ("return", e)
            if v in ("break", "continue"):
                self.i += 1
                if self.tok.kind == "name" and not self.tok.nl:
                    raise JsUnsupported("labelled break/continue")
                self.semi()
                return (v,)
            if v == "throw":
                self.i += 1
                e = self.expression()
                self.semi()
                return ("throw", e)
            if v in _RESERVED_STMT:
                raise JsUnsupported(f"'{v}' statement")
        e = self.expression()
        self.semi()
        return ("expr", e)

    def block(self):
        self.expect("{")
        body = []
        while not self.at("}"):
            if self.tok.kind == "eof":
                raise JsSyntax("unterminated block")
            body.append(self.statement())
        self.i += 1
        return ("block", body)

    def var_statement(self, in_for=False):
        kind = self.name()
        decls = []
        while True:
            target = self.pattern()
            init = None
            if self.eat("="):
                init = self.assignment(no_in=in_for)
            decls.append((target, init))
            if not self.eat(","):
                break
        if not in_for:
            self.semi()
        return ("var", kind, decls)

    def pattern(self):
        if self.eat("["):
            items = []
            while not self.at("]"):
                if self.at(","):
                    self.i += 1
                    items.append(None)
                    continue
                items.append(self.pattern())
                if not self.at("]"):
                    self.expect(",")
            self.i += 1
            return ("arrpat", items)
        if self.eat("{"):
            items = []
            while not self.at("}"):
                key = self.name() if self.tok.kind == "name" else self._prop_key_raw()
                target = self.pattern() if self.eat(":") else ("name", key)
                default = self.assignment() if self.eat("=") else None
                items.append((key, target, default))
                if not self.at("}"):
                    self.expect(",")
            self.i += 1
            return ("objpat", items)
        return ("name", self.name())

    def _prop_key_raw(self):
        tk = self.tok
        if tk.kind in ("str", "num"):
            self.i += 1
            return to_str(tk.value)
        raise JsSyntax(f"bad property key {tk.value!r}")

    def function_declaration(self):
        if self.eat("async"):
            raise JsUnsupported("async function")
        self.expect("function")
        if self.eat("*"):
            raise JsUnsupported("generator function")
        name = self.name()
        params = self.params()
        body = self.block()
        return ("fndecl", name, ("fn", name, params, body, False))

    def params(self):
        self.expect("(")
        out = []
        while not self.at(")"):
            rest = self.eat("...")
            target = self.pattern()
            default = self.assignment() if self.eat("=") else None
            out.append((target, default, rest))
            if not self.at(")"):
                self.expect(",")
        self.i += 1
        return out

    def for_statement(self):
        self.expect("for")
        self.expect("(")
        init = None
        if self.at("var") or self.at("let") or self.at("const"):
            save = self.i
            kind = self.tok.value
            self.i += 1
            target = self.pattern()
            if self.at("of") or self.at("in"):
                op = self.name()
                it = self.expression() if op == "in" else self.assignment()
                self.expect(")")
                return ("forof" if op == "of" else "forin", kind, target, it, self.statement())
            self.i = save
            init = self.var_statement(in_for=True)
        elif not self.at(";"):
            save = self.i
            try:
                target = self.pattern()
                if self.at("of") or self.at("in"):
                    op = self.name()
                    it = self.expression() if op == "in" else self.assignment()
                    self.expect(")")
                    return ("forof" if op == "of" else "forin", None, target, it, self.statement())
            except JsSyntax:
                pass
            self.i = save
            init = ("expr", self.expression(no_in=True))
        self.expect(";")
        test = None if self.at(";") else self.expression()
        self.expect(";")
        update = None if self.at(")") else self.expression()
        self.expect(")")
        return ("for", init, test, update, self.statement())

    def paren_expression(self):
        self.expect("(")
        e = self.expression()
        self.expect(")")
        return e

    # -- expressions
    def expression(self, no_in=False):
        e = self.assignment(no_in)
        if self.at(","):
            items = [e]
            while self.eat(","):
                items.append(self.assignment(no_in))
            return ("seq", items)
        return e

    def _arrow_ahead(self):
        """True when the tokens at self.i start an arrow function's parameter list."""
        tk = self.tok
        if tk.kind == "name" and self.peek().value == "=>" and self.peek().kind == "punct":
            return True
        if not self.at("("):
            return False
        depth, j = 0, self.i
        while j < len(self.t):
            v, k = self.t[j].value, self.t[j].kind
            if k == "eof":
                return False
            if k == "punct" and v in ("(", "[", "{"):
                depth += 1
            elif k == "punct" and v in (")", "]", "}"):
                depth -= 1
                if depth == 0:
                    nxt = self.t[j + 1] if j + 1 < len(self.t) else None
                    return bool(nxt and nxt.kind == "punct" and nxt.value == "=>")
            j += 1
        return False

    def arrow(self):
        if self.tok.kind == "name" and self.peek().value == "=>":
            params = [(("name", self.name()), None, False)]
        else:
            params = self.params()
        self.expect("=>")
        if self.at("{"):
            body = self.block()
        else:
            body = self.assignment()
        return ("fn", None, params, body, True)

    def assignment(self, no_in=False):
        self._enter()
        try:
            if self.at("async") and not self.peek().nl and (self.peek().value in ("(",) or self.peek().kind == "name"):
                save = self.i
                self.i += 1
                if self._arrow_ahead():
                    raise JsUnsupported("async arrow function")
                self.i = save
            if self._arrow_ahead():
                return self.arrow()
            left = self.conditional(no_in)
            tk = self.tok
            if tk.kind == "punct" and tk.value in _ASSIGN:
                if left[0] not in ("name", "member", "arr", "obj"):
                    raise JsSyntax("invalid assignment target")
                self.i += 1
                right = self.assignment(no_in)
                if left[0] in ("arr", "obj"):
                    raise JsUnsupported("destructuring assignment")
                return ("assign", tk.value, left, right)
            return left
        finally:
            self.depth -= 1

    def conditional(self, no_in=False):
        c = self.binary(0, no_in)
        if self.eat("?"):
            a = self.assignment()
            self.expect(":")
            b = self.assignment(no_in)
            return ("cond", c, a, b)
        return c

    def binary(self, min_prec, no_in=False):
        left = self.unary()
        while True:
            tk = self.tok
            op = tk.value
            if tk.kind not in ("punct", "name") or op not in _BINARY:
                return left
            if tk.kind == "name" and op not in ("instanceof", "in"):
                return left
            if no_in and op == "in":
                return left
            prec = _BINARY[op]
            if prec <= min_prec and not (op == "**" and prec == min_prec):
                return left
            self.i += 1
            right = self.binary(prec - 1 if op == "**" else prec, no_in)
            kind = "logic" if op in ("&&", "||", "??") else "bin"
            left = (kind, op, left, right)

    def unary(self):
        self._enter()
        try:
            tk = self.tok
            if tk.kind == "punct" and tk.value in ("!", "-", "+", "~"):
                self.i += 1
                return ("unary", tk.value, self.unary())
            if tk.kind == "punct" and tk.value in ("++", "--"):
                self.i += 1
                return ("update", tk.value, True, self.unary())
            if tk.kind == "name" and tk.value in ("typeof", "void", "delete"):
                self.i += 1
                return ("unary", tk.value, self.unary())
            if tk.kind == "name" and tk.value == "await":
                raise JsUnsupported("await")
            e = self.postfix()
            return e
        finally:
            self.depth -= 1

    def postfix(self):
        e = self.call_member()
        tk = self.tok
        if tk.kind == "punct" and tk.value in ("++", "--") and not tk.nl:
            self.i += 1
            return ("update", tk.value, False, e)
        return e

    def call_member(self):
        if self.at("new"):
            self.i += 1
            callee = self.primary()
            while True:
                if self.eat("."):
                    callee = ("member", callee, ("str", self._prop_name()), False)
                elif self.at("["):
                    self.i += 1
                    p = self.expression()
                    self.expect("]")
                    callee = ("member", callee, p, False)
                else:
                    break
            args = self.arguments() if self.at("(") else []
            e = ("new", callee, args)
        else:
            e = self.primary()
        while True:
            tk = self.tok
            if tk.kind == "punct" and tk.value == ".":
                self.i += 1
                e = ("member", e, ("str", self._prop_name()), False)
            elif tk.kind == "punct" and tk.value == "?.":
                self.i += 1
                if self.at("("):
                    e = ("call", e, self.arguments(), True)
                elif self.eat("["):
                    p = self.expression()
                    self.expect("]")
                    e = ("member", e, p, True)
                else:
                    e = ("member", e, ("str", self._prop_name()), True)
            elif tk.kind == "punct" and tk.value == "[":
                self.i += 1
                p = self.expression()
                self.expect("]")
                e = ("member", e, p, False)
            elif tk.kind == "punct" and tk.value == "(":
                e = ("call", e, self.arguments(), False)
            elif tk.kind == "tmpl":
                raise JsUnsupported("tagged template")
            else:
                return e

    def _prop_name(self):
        tk = self.tok
        if tk.kind == "name":
            self.i += 1
            return tk.value
        if tk.kind == "punct" and tk.value == "#":
            raise JsUnsupported("private field")
        raise JsSyntax(f"expected a property name, got {tk.value!r}")

    def arguments(self):
        self.expect("(")
        args = []
        while not self.at(")"):
            if self.eat("..."):
                args.append(("spread", self.assignment()))
            else:
                args.append(self.assignment())
            if not self.at(")"):
                self.expect(",")
        self.i += 1
        return args

    def primary(self):
        tk = self.tok
        k, v = tk.kind, tk.value
        if k == "num":
            self.i += 1
            return ("num", v)
        if k == "str":
            self.i += 1
            return ("str", v)
        if k == "bigint":
            self.i += 1
            return ("bigint", v)
        if k == "regex":
            self.i += 1
            return ("regex", v)
        if k == "tmpl":
            self.i += 1
            strs, srcs = v
            exprs = []
            for s in srcs:
                p = Parser(tokenize(s))
                exprs.append(p.expression())
                if p.tok.kind != "eof":
                    raise JsSyntax("bad template expression")
            return ("tmpl", strs, exprs)
        if k == "name":
            if v == "function":
                self.i += 1
                if self.eat("*"):
                    raise JsUnsupported("generator function")
                name = self.name() if self.tok.kind == "name" else None
                params = self.params()
                return ("fn", name, params, self.block(), False)
            if v == "this":
                self.i += 1
                return ("this",)
            if v == "class":
                raise JsUnsupported("class expression")
            if v in ("true", "false"):
                self.i += 1
                return ("bool", v == "true")
            if v == "null":
                self.i += 1
                return ("null",)
            self.i += 1
            return ("name", v)
        if k == "punct":
            if v == "(":
                self.i += 1
                e = self.expression()
                self.expect(")")
                return e
            if v == "[":
                self.i += 1
                items = []
                while not self.at("]"):
                    if self.at(","):
                        self.i += 1
                        items.append(("hole",))
                        continue
                    if self.eat("..."):
                        items.append(("spread", self.assignment()))
                    else:
                        items.append(self.assignment())
                    if not self.at("]"):
                        self.expect(",")
                self.i += 1
                return ("arr", items)
            if v == "{":
                self.i += 1
                props = []
                while not self.at("}"):
                    if self.eat("..."):
                        raise JsUnsupported("object spread")
                    tk2 = self.tok
                    if tk2.kind == "punct" and tk2.value == "[":
                        self.i += 1
                        key = self.assignment()
                        self.expect("]")
                    elif tk2.kind == "name":
                        self.i += 1
                        key = ("str", tk2.value)
                        if self.at(",") or self.at("}"):
                            props.append((key, ("name", tk2.value)))
                            if not self.at("}"):
                                self.expect(",")
                            continue
                        if self.at("("):
                            params = self.params()
                            props.append((key, ("fn", tk2.value, params, self.block(), False)))
                            if not self.at("}"):
                                self.expect(",")
                            continue
                    elif tk2.kind in ("str", "num"):
                        self.i += 1
                        key = ("str", to_str(tk2.value))
                    else:
                        raise JsSyntax(f"bad object key {tk2.value!r}")
                    self.expect(":")
                    props.append((key, self.assignment()))
                    if not self.at("}"):
                        self.expect(",")
                self.i += 1
                return ("obj", props)
        raise JsSyntax(f"unexpected token {v!r}")


def parse_expression(src: str):
    """One whole expression from source text (JsSyntax when anything is left over)."""
    p = Parser(tokenize(src))
    e = p.expression()
    if p.tok.kind != "eof":
        raise JsSyntax(f"trailing tokens after the expression: {p.tok.value!r}")
    return e


def parse_program(src: str):
    """[statement] of a whole source (JsSyntax / JsUnsupported on what the subset does not cover)."""
    p = Parser(tokenize(src))
    out = []
    while p.tok.kind != "eof":
        out.append(p.statement())
    return out


# ---------------------------------------------------------------------------------------------- values

class JSArray(list):
    pass


class JSObject(dict):
    pass


class Closure:
    __slots__ = ("node", "scope", "name")

    def __init__(self, node, scope, name=None):
        self.node, self.scope, self.name = node, scope, name or node[1]


class Builtin:
    __slots__ = ("fn", "name", "props")

    def __init__(self, fn, name, props=None):
        self.fn, self.name, self.props = fn, name, props or {}


def _fmt_num(x: float) -> str:
    if x != x:
        return "NaN"
    if x in (math.inf, -math.inf):
        return "Infinity" if x > 0 else "-Infinity"
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    if "e" in r:
        mant, exp = r.split("e")
        sign = "-" if exp.startswith("-") else "+"
        r = f"{mant}e{sign}{exp.lstrip('+-').lstrip('0') or '0'}"
    return r


def to_str(v) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return _fmt_num(float(v))
    if v is None:
        return "null"
    if v is UNDEF:
        return "undefined"
    if isinstance(v, JSArray):
        return ",".join("" if (x is None or x is UNDEF) else to_str(x) for x in v)
    if isinstance(v, JSObject):
        ts = v.get("toString")
        if isinstance(ts, Builtin):
            return to_str(ts.fn([]))
        return "[object Object]"
    if isinstance(v, (Closure, Builtin)):
        return "function () { [native code] }"
    raise JsUnsupported(f"string of {type(v).__name__}")


def to_number(v) -> float:
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    if v is None:
        return 0.0
    if v is UNDEF:
        return math.nan
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return 0.0
        try:
            if s[:2].lower() in ("0x", "0o", "0b"):
                return float(int(s[2:], {"x": 16, "o": 8, "b": 2}[s[1].lower()]))
            if s in ("Infinity", "+Infinity"):
                return math.inf
            if s == "-Infinity":
                return -math.inf
            if any(c.isalpha() and c not in "eE" for c in s):
                return math.nan
            return float(s)
        except ValueError:
            return math.nan
    if isinstance(v, JSArray):
        return to_number(to_str(v))
    return math.nan


def to_int32(v) -> int:
    x = to_number(v)
    if x != x or x in (math.inf, -math.inf):
        return 0
    n = int(x) & 0xFFFFFFFF
    return n - (1 << 32) if n & 0x80000000 else n


def to_uint32(v) -> int:
    x = to_number(v)
    if x != x or x in (math.inf, -math.inf):
        return 0
    return int(x) & 0xFFFFFFFF


def truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return not (v == 0 or v != v)
    if isinstance(v, str):
        return v != ""
    return not (v is None or v is UNDEF)


def typeof(v) -> str:
    if v is UNDEF:
        return "undefined"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, (Closure, Builtin)):
        return "function"
    return "object"


def strict_equal(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a) == float(b)
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if a is None or a is UNDEF or b is None or b is UNDEF:
        return a is b
    return a is b


def loose_equal(a, b) -> bool:
    if (a is None or a is UNDEF) and (b is None or b is UNDEF):
        return True
    if a is None or a is UNDEF or b is None or b is UNDEF:
        return False
    if typeof(a) == typeof(b) and not isinstance(a, (JSArray, JSObject)):
        return strict_equal(a, b)
    if isinstance(a, (JSArray, JSObject)) and isinstance(b, (JSArray, JSObject)):
        return a is b
    if isinstance(a, (JSArray, JSObject)):
        a = to_str(a)
    if isinstance(b, (JSArray, JSObject)):
        b = to_str(b)
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return to_number(a) == to_number(b)


# ---------------------------------------------------------------------------------------------- control flow

class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    def __init__(self, value):
        self.value = value


class Scope:
    __slots__ = ("vars", "parent")

    def __init__(self, parent=None):
        self.vars, self.parent = {}, parent

    def lookup(self, name):
        s = self
        while s is not None:
            if name in s.vars:
                return s
            s = s.parent
        return None


# ---------------------------------------------------------------------------------------------- builtins

def _digest(name):
    def fn(args):
        data = to_str(args[0] if args else UNDEF).encode("utf-8")
        return hashlib.new(name, data).hexdigest()
    return fn


def _cryptojs_digest(name):
    def fn(args):
        hexd = hashlib.new(name, to_str(args[0] if args else UNDEF).encode("utf-8")).hexdigest()
        word = JSObject()
        word["toString"] = Builtin(lambda a, h=hexd: h if not a or a[0] is UNDEF or a[0] == "hex"
                                   else base64.b64encode(bytes.fromhex(h)).decode() if a[0] == "base64"
                                   else h, "toString")
        return word
    return fn


def _atob(args):
    s = "".join(to_str(args[0] if args else UNDEF).split()).rstrip("=")
    if len(s) % 4 == 1:
        raise JsThrow("atob: invalid base64")
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise JsThrow("atob: invalid base64") from None
    return raw.decode("latin-1")


def _btoa(args):
    s = to_str(args[0] if args else UNDEF)
    if any(ord(c) > 255 for c in s):
        raise JsThrow("btoa: character out of range")
    return base64.b64encode(s.encode("latin-1")).decode("ascii")


def _parse_int(args):
    s = to_str(args[0] if args else UNDEF).strip()
    radix = to_int32(args[1]) if len(args) > 1 and args[1] is not UNDEF else 0
    sign = 1
    if s[:1] in "+-" and s:
        sign = -1 if s[0] == "-" else 1
        s = s[1:]
    if radix in (0, 16) and s[:2].lower() == "0x":
        s, radix = s[2:], 16
    radix = radix or 10
    if not 2 <= radix <= 36:
        return math.nan
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"[:radix]
    j = 0
    while j < len(s) and s[j].lower() in digits:
        j += 1
    if j == 0:
        return math.nan
    return float(sign * int(s[:j], radix))


def _parse_float(args):
    s = to_str(args[0] if args else UNDEF).strip()
    best = math.nan
    for j in range(len(s), 0, -1):
        try:
            best = float(s[:j])
            break
        except ValueError:
            continue
    return best


def _num_to_string(x, args):
    radix = to_int32(args[0]) if args and args[0] is not UNDEF else 10
    if radix == 10:
        return _fmt_num(x)
    if not 2 <= radix <= 36:
        raise JsThrow("toString() radix must be between 2 and 36")
    if x != int(x):
        raise JsUnsupported("fractional toString(radix)")
    n = int(x)
    if n == 0:
        return "0"
    digits, neg, out = "0123456789abcdefghijklmnopqrstuvwxyz", n < 0, []
    n = abs(n)
    while n:
        n, r = divmod(n, radix)
        out.append(digits[r])
    return ("-" if neg else "") + "".join(reversed(out))


def _math():
    def f1(fn):
        return lambda a: fn(to_number(a[0] if a else UNDEF))

    def safe(fn):
        def run(x):
            try:
                return float(fn(x))
            except (ValueError, OverflowError):
                return math.nan
        return run

    def jround(x):
        return x if x != x or x in (math.inf, -math.inf) else float(math.floor(x + 0.5))

    def trunc(x):
        return x if x != x or x in (math.inf, -math.inf) else float(math.trunc(x))

    def floor(x):
        return x if x != x or x in (math.inf, -math.inf) else float(math.floor(x))

    def ceil(x):
        return x if x != x or x in (math.inf, -math.inf) else float(math.ceil(x))

    def imul(a):
        x = (to_int32(a[0] if a else 0) * to_int32(a[1] if len(a) > 1 else 0)) & 0xFFFFFFFF
        return float(x - (1 << 32) if x & 0x80000000 else x)

    def clz32(a):
        return float(32 - to_uint32(a[0] if a else 0).bit_length())

    def mx(a):
        return max((to_number(x) for x in a), default=-math.inf)

    def mn(a):
        return min((to_number(x) for x in a), default=math.inf)

    def pw(a):
        return _pow(to_number(a[0] if a else UNDEF), to_number(a[1] if len(a) > 1 else UNDEF))

    def sign(x):
        return x if x != x or x == 0 else (1.0 if x > 0 else -1.0)

    fns = {"imul": imul, "clz32": clz32, "max": mx, "min": mn, "pow": pw,
           "abs": f1(abs), "floor": f1(floor), "ceil": f1(ceil), "round": f1(jround), "trunc": f1(trunc),
           "sign": f1(sign), "sqrt": f1(safe(math.sqrt)), "log": f1(safe(math.log)),
           "log2": f1(safe(math.log2)), "exp": f1(safe(math.exp)), "sin": f1(math.sin), "cos": f1(math.cos)}
    obj = JSObject({k: Builtin(v, k) for k, v in fns.items()})
    obj.update(PI=math.pi, E=math.e)
    return obj


def _pow(a, b):
    try:
        return float(a ** b)
    except (OverflowError, ZeroDivisionError):
        return math.inf
    except (ValueError, TypeError):
        return math.nan


def _from_char_code(args):
    return "".join(chr(to_uint32(a) & 0xFFFF) for a in args)


def _from_code_point(args):
    out = []
    for a in args:
        n = to_number(a)
        if n != int(n) or not 0 <= n <= 0x10FFFF:
            raise JsThrow("Invalid code point")
        out.append(chr(int(n)))
    return "".join(out)


def _uri(fn):
    def run(args):
        try:
            return fn(to_str(args[0] if args else UNDEF))
        except (UnicodeError, ValueError):
            raise JsThrow("URIError") from None
    return run


def _array_ctor(args):
    if len(args) == 1 and isinstance(args[0], (int, float)) and not isinstance(args[0], bool):
        n = int(to_number(args[0]))
        if n > MAX_LEN or n < 0:
            raise JsLimit("array too long")
        return JSArray([UNDEF] * n)
    return JSArray(args)


def _array_from(interp):
    def run(args):
        src = args[0] if args else UNDEF
        if isinstance(src, str):
            items = list(src)
        elif isinstance(src, JSArray):
            items = list(src)
        elif isinstance(src, JSObject) and "length" in src:
            items = [UNDEF] * int(to_number(src["length"]))
        else:
            raise JsUnsupported("Array.from of this value")
        if len(args) > 1:
            fn = args[1]
            items = [interp.call(fn, [x, float(i)]) for i, x in enumerate(items)]
        return JSArray(items)
    return run


def default_globals(interp) -> dict:
    """The names a program may reach. No host object: nothing here touches I/O."""
    def obj(**kw):
        return JSObject({k: (Builtin(v, k) if callable(v) else v) for k, v in kw.items()})

    crypto_js = obj(MD5=_cryptojs_digest("md5"), SHA1=_cryptojs_digest("sha1"),
                    SHA256=_cryptojs_digest("sha256"), SHA512=_cryptojs_digest("sha512"))
    crypto_js["enc"] = JSObject(Hex="hex", Base64="base64")
    g = {
        "Math": _math(),
        "String": Builtin(lambda a: to_str(a[0]) if a else "", "String",
                          {"fromCharCode": Builtin(_from_char_code, "fromCharCode"),
                           "fromCodePoint": Builtin(_from_code_point, "fromCodePoint")}),
        "Number": Builtin(lambda a: to_number(a[0]) if a else 0.0, "Number",
                          {"isInteger": Builtin(lambda a: bool(a) and isinstance(a[0], float)
                                                and a[0] == a[0] and a[0] == int(a[0]), "isInteger"),
                           "MAX_SAFE_INTEGER": float(2 ** 53 - 1)}),
        "Boolean": Builtin(lambda a: truthy(a[0]) if a else False, "Boolean"),
        "Array": Builtin(_array_ctor, "Array", {"isArray": Builtin(lambda a: bool(a) and isinstance(a[0], JSArray),
                                                                   "isArray"),
                                                "from": Builtin(_array_from(interp), "from")}),
        "Object": Builtin(lambda a: JSObject(), "Object",
                          {"keys": Builtin(lambda a: JSArray(list(a[0].keys())) if a and isinstance(a[0], JSObject)
                                           else JSArray(), "keys"),
                           "values": Builtin(lambda a: JSArray(list(a[0].values())) if a and isinstance(a[0], JSObject)
                                             else JSArray(), "values")}),
        "parseInt": Builtin(_parse_int, "parseInt"),
        "parseFloat": Builtin(_parse_float, "parseFloat"),
        "isNaN": Builtin(lambda a: to_number(a[0] if a else UNDEF) != to_number(a[0] if a else UNDEF), "isNaN"),
        "atob": Builtin(_atob, "atob"),
        "btoa": Builtin(_btoa, "btoa"),
        "encodeURIComponent": Builtin(_uri(lambda s: urllib.parse.quote(s, safe="-_.!~*'()")), "encodeURIComponent"),
        "decodeURIComponent": Builtin(_uri(lambda s: urllib.parse.unquote(s, errors="strict")), "decodeURIComponent"),
        "md5": Builtin(_digest("md5"), "md5"), "sha1": Builtin(_digest("sha1"), "sha1"),
        "sha256": Builtin(_digest("sha256"), "sha256"), "sha512": Builtin(_digest("sha512"), "sha512"),
        "hex_md5": Builtin(_digest("md5"), "hex_md5"), "hex_sha1": Builtin(_digest("sha1"), "hex_sha1"),
        "hex_sha256": Builtin(_digest("sha256"), "hex_sha256"),
        "CryptoJS": crypto_js,
        "console": obj(log=lambda a: UNDEF, info=lambda a: UNDEF, warn=lambda a: UNDEF, error=lambda a: UNDEF,
                       debug=lambda a: UNDEF),
        "undefined": UNDEF, "NaN": math.nan, "Infinity": math.inf,
    }
    return g


DIGEST_NAMES = frozenset({"md5", "sha1", "sha256", "sha512", "hex_md5", "hex_sha1", "hex_sha256", "CryptoJS"})
STRING_METHODS_INPUT = frozenset({"trim", "toLowerCase", "toUpperCase", "trimStart", "trimEnd",
                                  "toLocaleLowerCase", "toLocaleUpperCase", "normalize"})


# ---------------------------------------------------------------------------------------------- interpreter

class Interp:
    def __init__(self, max_steps: int = 200_000):
        self.max_steps = int(max_steps)
        self.steps = 0
        self.depth = 0
        self.globals = Scope()
        self.globals.vars.update(default_globals(self))
        self.lazy = {}            # name -> AST evaluated on first use (a program constant)

    # -- setup
    def define(self, name, value):
        if isinstance(value, tuple) and value and value[0] == "fn":
            value = Closure(value, self.globals, name)
        self.globals.vars[name] = value

    def define_lazy(self, name, expr):
        """A program constant evaluated on first read (Unresolved propagates to the reader)."""
        self.lazy[name] = expr

    def reset(self, max_steps=None):
        self.steps = 0
        if max_steps is not None:
            self.max_steps = int(max_steps)

    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise JsLimit(f"step budget of {self.max_steps} exhausted")

    # -- entry points
    def eval(self, expr, bindings=None):
        scope = Scope(self.globals)
        if bindings:
            scope.vars.update(bindings)
        return self.ev(expr, scope)

    def call(self, fn, args):
        if isinstance(fn, Builtin):
            self.tick()
            return fn.fn(list(args))
        if not isinstance(fn, Closure):
            raise JsThrow(f"{to_str_safe(fn)} is not a function")
        node = fn.node
        _, _, params, body, arrow = node
        self.depth += 1
        if self.depth > MAX_DEPTH:
            self.depth -= 1
            raise JsLimit("call stack too deep")
        try:
            scope = Scope(fn.scope)
            if not arrow:
                scope.vars["arguments"] = JSArray(args)
            for k, (target, default, rest) in enumerate(params):
                if rest:
                    val = JSArray(args[k:])
                else:
                    val = args[k] if k < len(args) else UNDEF
                    if val is UNDEF and default is not None:
                        val = self.ev(default, scope)
                self.bind(target, val, scope, "let")
            if body[0] != "block":
                return self.ev(body, scope)
            try:
                self.run_block(body[1], scope, new_scope=False)
            except _Return as r:
                return r.value
            return UNDEF
        finally:
            self.depth -= 1

    # -- statements
    def hoist(self, stmts, scope):
        for s in stmts:
            if s[0] == "fndecl":
                scope.vars[s[1]] = Closure(s[2], scope, s[1])

    def run_block(self, stmts, scope, new_scope=True):
        if new_scope:
            scope = Scope(scope)
        self.hoist(stmts, scope)
        for s in stmts:
            self.exec(s, scope)

    def exec(self, s, scope):
        self.tick()
        k = s[0]
        if k == "expr":
            self.ev(s[1], scope)
        elif k == "var":
            for target, init in s[2]:
                val = self.ev(init, scope) if init is not None else UNDEF
                self.bind(target, val, scope if s[1] != "var" else self._fn_scope(scope), s[1])
        elif k == "return":
            raise _Return(self.ev(s[1], scope) if s[1] is not None else UNDEF)
        elif k == "if":
            if truthy(self.ev(s[1], scope)):
                self.exec(s[2], scope)
            elif s[3] is not None:
                self.exec(s[3], scope)
        elif k == "block":
            self.run_block(s[1], scope)
        elif k == "for":
            loop = Scope(scope)
            if s[1] is not None:
                self.exec(s[1], loop)
            while True:
                self.tick()
                if s[2] is not None and not truthy(self.ev(s[2], loop)):
                    break
                try:
                    self.exec(s[4], Scope(loop))
                except _Break:
                    break
                except _Continue:
                    pass
                if s[3] is not None:
                    self.ev(s[3], loop)
        elif k in ("forof", "forin"):
            it = self.ev(s[3], scope)
            if k == "forof":
                if isinstance(it, str):
                    items = list(it)
                elif isinstance(it, JSArray):
                    items = list(it)
                else:
                    raise JsUnsupported("for-of over this value")
            else:
                if isinstance(it, (str, JSArray)):
                    items = [str(i) for i in range(len(it))]
                elif isinstance(it, JSObject):
                    items = list(it.keys())
                else:
                    items = []
            for item in items:
                self.tick()
                inner = Scope(scope)
                if s[1] is None:
                    self.assign_target(s[2], item, inner)
                else:
                    self.bind(s[2], item, inner, s[1])
                try:
                    self.exec(s[4], inner)
                except _Break:
                    break
                except _Continue:
                    continue
        elif k == "while":
            while True:
                self.tick()
                if not truthy(self.ev(s[1], scope)):
                    break
                try:
                    self.exec(s[2], scope)
                except _Break:
                    break
                except _Continue:
                    continue
        elif k == "dowhile":
            while True:
                self.tick()
                try:
                    self.exec(s[1], scope)
                except _Break:
                    break
                except _Continue:
                    pass
                if not truthy(self.ev(s[2], scope)):
                    break
        elif k == "break":
            raise _Break()
        elif k == "continue":
            raise _Continue()
        elif k == "fndecl":
            scope.vars.setdefault(s[1], Closure(s[2], scope, s[1]))
        elif k == "empty":
            pass
        elif k == "throw":
            raise JsThrow(f"thrown: {to_str_safe(self.ev(s[1], scope))}")
        else:
            raise JsUnsupported(f"statement {k}")

    def _fn_scope(self, scope):
        return scope

    def bind(self, target, val, scope, kind):
        t = target[0]
        if t == "name":
            scope.vars[target[1]] = val
        elif t == "arrpat":
            seq = list(val) if isinstance(val, (JSArray, str)) else None
            if seq is None:
                raise JsThrow("destructuring a non-iterable")
            for i, sub in enumerate(target[1]):
                if sub is not None:
                    self.bind(sub, seq[i] if i < len(seq) else UNDEF, scope, kind)
        elif t == "objpat":
            for key, sub, default in target[1]:
                v = self.get_member(val, key)
                if v is UNDEF and default is not None:
                    v = self.ev(default, scope)
                self.bind(sub, v, scope, kind)
        else:
            raise JsUnsupported(f"binding pattern {t}")

    # -- names
    def lookup(self, name, scope):
        s = scope.lookup(name)
        if s is not None:
            return s.vars[name]
        if name in self.lazy:
            expr = self.lazy.pop(name)
            try:
                val = self.ev(expr, Scope(self.globals))
            except Unresolved:
                self.lazy[name] = expr
                raise
            self.globals.vars[name] = val
            return val
        raise Unresolved(name)

    def assign_target(self, target, val, scope):
        k = target[0]
        if k == "name":
            s = scope.lookup(target[1])
            if s is None:
                if target[1] in self.lazy:
                    raise JsUnsupported("assignment to a program constant")
                raise Unresolved(target[1])
            s.vars[target[1]] = val
        elif k == "member":
            obj = self.ev(target[1], scope)
            prop = self.ev(target[2], scope)
            self.set_member(obj, prop, val)
        else:
            raise JsUnsupported(f"assignment to {k}")

    # -- expressions
    def ev(self, e, scope):
        self.tick()
        k = e[0]
        if k == "num":
            return e[1]
        if k == "str":
            return e[1]
        if k == "name":
            return self.lookup(e[1], scope)
        if k == "input":
            return self.lookup("\0input", scope)
        if k == "bin":
            return self.binop(e[1], self.ev(e[2], scope), self.ev(e[3], scope))
        if k == "logic":
            left = self.ev(e[2], scope)
            if e[1] == "&&":
                return self.ev(e[3], scope) if truthy(left) else left
            if e[1] == "||":
                return left if truthy(left) else self.ev(e[3], scope)
            return self.ev(e[3], scope) if left is None or left is UNDEF else left
        if k == "call":
            return self.call_expr(e, scope)
        if k == "member":
            obj = self.ev(e[1], scope)
            if e[3] and (obj is None or obj is UNDEF):
                return UNDEF
            return self.get_member(obj, self.ev(e[2], scope))
        if k == "assign":
            return self.assign(e, scope)
        if k == "update":
            return self.update(e, scope)
        if k == "unary":
            return self.unary(e, scope)
        if k == "cond":
            return self.ev(e[2], scope) if truthy(self.ev(e[1], scope)) else self.ev(e[3], scope)
        if k == "seq":
            v = UNDEF
            for x in e[1]:
                v = self.ev(x, scope)
            return v
        if k == "tmpl":
            parts = []
            for i, s in enumerate(e[1]):
                parts.append(s)
                if i < len(e[2]):
                    parts.append(to_str(self.ev(e[2][i], scope)))
            return self._cap("".join(parts))
        if k == "arr":
            out = JSArray()
            for x in e[1]:
                if x[0] == "spread":
                    v = self.ev(x[1], scope)
                    out.extend(list(v) if isinstance(v, (JSArray, str)) else [])
                elif x[0] == "hole":
                    out.append(UNDEF)
                else:
                    out.append(self.ev(x, scope))
            return self._cap(out)
        if k == "obj":
            o = JSObject()
            for key, val in e[1]:
                o[to_str(self.ev(key, scope))] = self.ev(val, scope)
            return o
        if k == "fn":
            return Closure(e, scope)
        if k == "bool":
            return e[1]
        if k == "null":
            return None
        if k == "new":
            callee = self.ev(e[1], scope)
            if isinstance(callee, Builtin) and callee.name in ("Array", "Object", "String", "Number"):
                return self.call(callee, self.args(e[2], scope))
            raise JsUnsupported("new of this constructor")
        if k == "this":
            raise JsUnsupported("this")
        if k == "regex":
            raise JsUnsupported("regular expression")
        if k == "bigint":
            raise JsUnsupported("BigInt")
        raise JsUnsupported(f"expression {k}")

    def _cap(self, v):
        if len(v) > MAX_LEN:
            raise JsLimit("value too long")
        return v

    def args(self, nodes, scope):
        out = []
        for a in nodes:
            if a[0] == "spread":
                v = self.ev(a[1], scope)
                out.extend(list(v) if isinstance(v, (JSArray, str)) else [])
            else:
                out.append(self.ev(a, scope))
        return out

    def call_expr(self, e, scope):
        callee = e[1]
        if callee[0] == "member":
            obj = self.ev(callee[1], scope)
            if callee[3] and (obj is None or obj is UNDEF):
                return UNDEF
            prop = to_str(self.ev(callee[2], scope))
            args = self.args(e[2], scope)
            return self.method(obj, prop, args)
        fn = self.ev(callee, scope)
        if e[3] and (fn is None or fn is UNDEF):
            return UNDEF
        return self.call(fn, self.args(e[2], scope))

    def binop(self, op, a, b):
        if op == "+":
            if isinstance(a, (JSArray, JSObject)):
                a = to_str(a)
            if isinstance(b, (JSArray, JSObject)):
                b = to_str(b)
            if isinstance(a, str) or isinstance(b, str):
                return self._cap(to_str(a) + to_str(b))
            return to_number(a) + to_number(b)
        if op == "-":
            return to_number(a) - to_number(b)
        if op == "*":
            return to_number(a) * to_number(b)
        if op == "/":
            x, y = to_number(a), to_number(b)
            if y == 0:
                if x == 0 or x != x:
                    return math.nan
                return math.copysign(math.inf, x) * math.copysign(1, y)
            return x / y
        if op == "%":
            x, y = to_number(a), to_number(b)
            if y == 0 or x != x or y != y or x in (math.inf, -math.inf):
                return math.nan
            return math.fmod(x, y)
        if op == "**":
            return _pow(to_number(a), to_number(b))
        if op == "&":
            return float(to_int32(a) & to_int32(b))
        if op == "|":
            return float(to_int32(a) | to_int32(b))
        if op == "^":
            return float(to_int32(a) ^ to_int32(b))
        if op == "<<":
            n = (to_int32(a) << (to_uint32(b) & 31)) & 0xFFFFFFFF
            return float(n - (1 << 32) if n & 0x80000000 else n)
        if op == ">>":
            return float(to_int32(a) >> (to_uint32(b) & 31))
        if op == ">>>":
            return float(to_uint32(a) >> (to_uint32(b) & 31))
        if op == "===":
            return strict_equal(a, b)
        if op == "!==":
            return not strict_equal(a, b)
        if op == "==":
            return loose_equal(a, b)
        if op == "!=":
            return not loose_equal(a, b)
        if op in ("<", ">", "<=", ">="):
            if isinstance(a, str) and isinstance(b, str):
                x, y = a, b
            else:
                x, y = to_number(a), to_number(b)
                if x != x or y != y:
                    return False
            return {"<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op]
        if op == "in":
            if isinstance(b, JSObject):
                return to_str(a) in b
            if isinstance(b, JSArray):
                n = to_number(a)
                return n == int(n) and 0 <= n < len(b)
            raise JsThrow("'in' on a non-object")
        raise JsUnsupported(f"operator {op}")

    def assign(self, e, scope):
        op, target, value = e[1], e[2], e[3]
        if op == "=":
            val = self.ev(value, scope)
        elif op in ("&&=", "||=", "??="):
            cur = self.ev(target, scope)
            if (op == "&&=" and not truthy(cur)) or (op == "||=" and truthy(cur)) or \
                    (op == "??=" and cur is not None and cur is not UNDEF):
                return cur
            val = self.ev(value, scope)
        else:
            val = self.binop(op[:-1], self.ev(target, scope), self.ev(value, scope))
        self.assign_target(target, val, scope)
        return val

    def update(self, e, scope):
        op, prefix, target = e[1], e[2], e[3]
        old = to_number(self.ev(target, scope))
        new = old + 1 if op == "++" else old - 1
        self.assign_target(target, new, scope)
        return new if prefix else old

    def unary(self, e, scope):
        op = e[1]
        if op == "typeof":
            try:
                return typeof(self.ev(e[2], scope))
            except Unresolved:
                return "undefined"
        v = self.ev(e[2], scope)
        if op == "!":
            return not truthy(v)
        if op == "-":
            return -to_number(v)
        if op == "+":
            return to_number(v)
        if op == "~":
            return float(~to_int32(v))
        if op == "void":
            return UNDEF
        raise JsUnsupported(f"unary {op}")

    # -- members
    def get_member(self, obj, prop):
        if obj is None or obj is UNDEF:
            raise JsThrow(f"cannot read properties of {to_str(obj)} (reading {to_str_safe(prop)!r})")
        if isinstance(obj, str):
            if prop == "length":
                return float(len(obj))
            n = _index(prop)
            if n is not None:
                return obj[n] if n < len(obj) else UNDEF
            return UNDEF
        if isinstance(obj, JSArray):
            if prop == "length":
                return float(len(obj))
            n = _index(prop)
            if n is not None:
                return obj[n] if n < len(obj) else UNDEF
            return UNDEF
        if isinstance(obj, JSObject):
            return obj.get(to_str(prop), UNDEF)
        if isinstance(obj, Builtin):
            return obj.props.get(to_str(prop), UNDEF)
        return UNDEF

    def set_member(self, obj, prop, val):
        if isinstance(obj, JSArray):
            if prop == "length":
                n = int(to_number(val))
                if n > MAX_LEN:
                    raise JsLimit("array too long")
                del obj[n:]
                obj.extend([UNDEF] * (n - len(obj)))
                return
            n = _index(prop)
            if n is None:
                raise JsUnsupported("non-index array property")
            if n > MAX_LEN:
                raise JsLimit("array too long")
            if n >= len(obj):
                obj.extend([UNDEF] * (n + 1 - len(obj)))
            obj[n] = val
            return
        if isinstance(obj, JSObject):
            key = to_str(prop)
            if key in ("__proto__", "constructor", "prototype"):
                raise JsUnsupported("prototype access")
            obj[key] = val
            return
        if isinstance(obj, str):
            return                      # silently ignored in sloppy mode, as in JavaScript
        raise JsThrow("cannot set a property here")

    def method(self, obj, name, args):
        self.tick()
        if isinstance(obj, str):
            return self._cap_value(_string_method(self, obj, name, args))
        if isinstance(obj, JSArray):
            return self._cap_value(_array_method(self, obj, name, args))
        if isinstance(obj, (int, float)) and not isinstance(obj, bool):
            if name == "toString":
                return _num_to_string(float(obj), args)
            if name == "toFixed":
                d = to_int32(args[0]) if args else 0
                return f"{float(obj):.{max(0, min(d, 100))}f}"
            raise JsUnsupported(f"number method {name}")
        if isinstance(obj, bool) and name == "toString":
            return to_str(obj)
        fn = self.get_member(obj, name)
        if fn is UNDEF:
            raise JsThrow(f"{name} is not a function")
        return self.call(fn, args)

    def _cap_value(self, v):
        if isinstance(v, (str, JSArray)) and len(v) > MAX_LEN:
            raise JsLimit("value too long")
        return v


def to_str_safe(v):
    try:
        return to_str(v)
    except JsError:
        return type(v).__name__


def _index(prop):
    if isinstance(prop, bool):
        return None
    if isinstance(prop, (int, float)):
        if prop == int(prop) and prop >= 0:
            return int(prop)
        return None
    if isinstance(prop, str) and prop.isdigit():
        return int(prop)
    return None


def _clamp_index(v, n, default):
    if v is UNDEF:
        return default
    x = to_number(v)
    if x != x:
        x = 0
    x = int(x) if x not in (math.inf, -math.inf) else (n if x > 0 else -n - 1)
    if x < 0:
        x = max(0, n + x)
    return min(x, n)


def _string_method(interp, s, name, a):
    a0 = a[0] if a else UNDEF
    if name == "charCodeAt":
        i = 0 if a0 is UNDEF else int(to_number(a0)) if to_number(a0) == to_number(a0) else 0
        return float(ord(s[i])) if 0 <= i < len(s) else math.nan
    if name == "codePointAt":
        i = 0 if a0 is UNDEF else int(to_number(a0))
        return float(ord(s[i])) if 0 <= i < len(s) else UNDEF
    if name == "charAt":
        i = 0 if a0 is UNDEF else int(to_number(a0))
        return s[i] if 0 <= i < len(s) else ""
    if name == "at":
        i = int(to_number(a0)) if a0 is not UNDEF else 0
        i = i + len(s) if i < 0 else i
        return s[i] if 0 <= i < len(s) else UNDEF
    if name in ("toLowerCase", "toLocaleLowerCase"):
        return s.lower()
    if name in ("toUpperCase", "toLocaleUpperCase"):
        return s.upper()
    if name == "trim":
        return s.strip(" \t\n\r\v\f ﻿")
    if name in ("trimStart", "trimLeft"):
        return s.lstrip(" \t\n\r\v\f ﻿")
    if name in ("trimEnd", "trimRight"):
        return s.rstrip(" \t\n\r\v\f ﻿")
    if name == "normalize":
        import unicodedata
        return unicodedata.normalize(to_str(a0) if a0 is not UNDEF else "NFC", s)
    if name == "split":
        if a0 is UNDEF:
            return JSArray([s])
        if not isinstance(a0, str):
            raise JsUnsupported("split by a non-string")
        parts = list(s) if a0 == "" else s.split(a0)
        if len(a) > 1 and a[1] is not UNDEF:
            parts = parts[:to_uint32(a[1])]
        return JSArray(parts)
    if name in ("slice", "substring"):
        n = len(s)
        if name == "slice":
            i, j = _clamp_index(a0, n, 0), _clamp_index(a[1] if len(a) > 1 else UNDEF, n, n)
            return s[i:j] if i < j else ""
        def clamp(v, d):
            if v is UNDEF:
                return d
            x = to_number(v)
            return 0 if x != x else max(0, min(int(x) if abs(x) != math.inf else (n if x > 0 else 0), n))
        i, j = clamp(a0, 0), clamp(a[1] if len(a) > 1 else UNDEF, n)
        return s[min(i, j):max(i, j)]
    if name == "substr":
        n = len(s)
        i = _clamp_index(a0, n, 0)
        ln = n - i if len(a) < 2 or a[1] is UNDEF else max(0, int(to_number(a[1])))
        return s[i:i + ln]
    if name == "indexOf":
        return float(s.find(to_str(a0), _clamp_index(a[1], len(s), 0) if len(a) > 1 else 0))
    if name == "lastIndexOf":
        return float(s.rfind(to_str(a0)))
    if name == "includes":
        return to_str(a0) in s
    if name == "startsWith":
        return s.startswith(to_str(a0))
    if name == "endsWith":
        return s.endswith(to_str(a0))
    if name == "repeat":
        n = int(to_number(a0))
        if n < 0 or n * len(s) > MAX_LEN:
            raise JsLimit("repeat too long")
        return s * n
    if name in ("padStart", "padEnd"):
        width = int(to_number(a0))
        fill = to_str(a[1]) if len(a) > 1 and a[1] is not UNDEF else " "
        if width > MAX_LEN:
            raise JsLimit("pad too long")
        if width <= len(s) or not fill:
            return s
        pad = (fill * (width - len(s)))[:width - len(s)]
        return pad + s if name == "padStart" else s + pad
    if name == "replace" or name == "replaceAll":
        if not isinstance(a0, str):
            raise JsUnsupported("replace with a regular expression")
        rep = a[1] if len(a) > 1 else UNDEF
        if isinstance(rep, (Closure, Builtin)):
            raise JsUnsupported("replace with a function")
        rep = to_str(rep)
        return s.replace(a0, rep) if name == "replaceAll" else s.replace(a0, rep, 1)
    if name == "concat":
        return s + "".join(to_str(x) for x in a)
    if name == "toString" or name == "valueOf":
        return s
    raise JsUnsupported(f"string method {name}")


def _array_method(interp, arr, name, a):
    a0 = a[0] if a else UNDEF
    if name == "push":
        if len(arr) + len(a) > MAX_LEN:
            raise JsLimit("array too long")
        arr.extend(a)
        return float(len(arr))
    if name == "pop":
        return arr.pop() if arr else UNDEF
    if name == "shift":
        return arr.pop(0) if arr else UNDEF
    if name == "unshift":
        arr[0:0] = a
        return float(len(arr))
    if name == "join":
        sep = "," if a0 is UNDEF else to_str(a0)
        return sep.join("" if (x is None or x is UNDEF) else to_str(x) for x in arr)
    if name == "reverse":
        arr.reverse()
        return arr
    if name == "slice":
        n = len(arr)
        i, j = _clamp_index(a0, n, 0), _clamp_index(a[1] if len(a) > 1 else UNDEF, n, n)
        return JSArray(arr[i:j])
    if name == "concat":
        out = JSArray(arr)
        for x in a:
            out.extend(x if isinstance(x, JSArray) else [x])
        return out
    if name == "indexOf":
        return float(next((i for i, x in enumerate(arr) if strict_equal(x, a0)), -1))
    if name == "includes":
        return any(strict_equal(x, a0) or (x != x and a0 != a0 if isinstance(x, float) and isinstance(a0, float)
                                           else False) for x in arr)
    if name == "fill":
        for i in range(len(arr)):
            arr[i] = a0
        return arr
    if name in ("map", "forEach", "filter", "every", "some", "find", "findIndex"):
        fn = a0
        out = JSArray()
        for i, x in enumerate(list(arr)):
            r = interp.call(fn, [x, float(i), arr])
            if name == "map":
                out.append(r)
            elif name == "filter" and truthy(r):
                out.append(x)
            elif name == "every" and not truthy(r):
                return False
            elif name == "some" and truthy(r):
                return True
            elif name == "find" and truthy(r):
                return x
            elif name == "findIndex" and truthy(r):
                return float(i)
        return {"map": out, "filter": out, "forEach": UNDEF, "every": True, "some": False, "find": UNDEF,
                "findIndex": -1.0}[name]
    if name in ("reduce", "reduceRight"):
        items = list(enumerate(arr))
        if name == "reduceRight":
            items.reverse()
        if len(a) > 1:
            acc = a[1]
        else:
            if not items:
                raise JsThrow("reduce of empty array with no initial value")
            acc = items.pop(0)[1]
        for i, x in items:
            acc = interp.call(a0, [acc, x, float(i), arr])
        return acc
    if name == "toString":
        return to_str(arr)
    raise JsUnsupported(f"array method {name}")
