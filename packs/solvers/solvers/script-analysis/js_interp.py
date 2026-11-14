#!/usr/bin/env python3
"""A small parser and interpreter for the JScript subset the triage fixtures use.

Pure computation only: no ActiveXObject, no WScript, no eval, no I/O. It exists
so a specimen's own decoding routine can be followed statically, whatever
transform a variant uses, without running the specimen in a real script host.

AST shape: every node is a tuple whose first item is its kind; plain lists are
containers (statement lists, argument lists, [key, value] pairs). `walk()`
yields nodes only.
"""
import math
import re


class JSError(Exception):
    """The script uses something outside the supported, side-effect-free subset."""


class JSThrow(Exception):
    def __init__(self, value):
        super().__init__(repr(value))
        self.value = value


class _Undef:
    __slots__ = ()

    def __repr__(self):
        return "undefined"

    def __bool__(self):
        return False


UNDEF = _Undef()


class JSArray(list):
    pass


class JSObject(dict):
    pass


class JSRegex:
    def __init__(self, source, flags):
        self.source, self.flags, self.g = source, flags, "g" in flags
        self.re = re.compile(source, (re.I if "i" in flags else 0) | (re.M if "m" in flags else 0))


# ----------------------------------------------------------------- tokenizer

_PUNCT = [">>>=", "===", "!==", ">>>", "<<=", ">>=", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=",
          "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>", "{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+",
          "-", "*", "/", "%", "&", "|", "^", "!", "~", "?", ":", "=", "."]
_TOKEN = re.compile(r"""
    (?P<ws>[ \t\r\n ﻿]+)
  | (?P<lc>//[^\n]*)
  | (?P<bc>/\*.*?\*/)
  | (?P<num>0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)
  | (?P<id>[A-Za-z_$][A-Za-z0-9_$]*)
  | (?P<str>"(?:[^"\\\n]|\\[\s\S])*"|'(?:[^'\\\n]|\\[\s\S])*')
  | (?P<punc>""" + "|".join(re.escape(p) for p in _PUNCT) + r""")
""", re.X | re.S)
_REGEX_AFTER_WORD = {"return", "typeof", "case", "in", "instanceof", "new", "delete", "void", "throw", "else", "do"}
_SIMPLE_ESC = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def _unescape(body: str) -> str:
    if "\\" not in body:
        return body
    out, i, n = [], 0, len(body)
    while i < n:
        c = body[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        e = body[i + 1]
        if e == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", body[i + 2:i + 4]):
            out.append(chr(int(body[i + 2:i + 4], 16)))
            i += 4
        elif e == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", body[i + 2:i + 6]):
            out.append(chr(int(body[i + 2:i + 6], 16)))
            i += 6
        elif e in "\r\n":  # line continuation
            i += 3 if body[i + 1:i + 3] == "\r\n" else 2
        else:
            out.append(_SIMPLE_ESC.get(e, e))
            i += 2
    return "".join(out)


def tokenize(src: str) -> list:
    toks, i, n = [], 0, len(src)
    while i < n:
        if src[i] == "/" and src[i:i + 2] not in ("//", "/*"):
            prev = toks[-1] if toks else None
            regex_ok = (prev is None or (prev[0] == "id" and prev[1] in _REGEX_AFTER_WORD)
                        or (prev[0] == "punc" and prev[1] not in (")", "]", "}")))
            if regex_ok:
                j, in_class = i + 1, False
                while j < n:
                    ch = src[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == "\n":
                        raise JSError("unterminated regular expression")
                    if ch == "[":
                        in_class = True
                    elif ch == "]":
                        in_class = False
                    elif ch == "/" and not in_class:
                        break
                    j += 1
                k = j + 1
                while k < n and src[k].isalpha():
                    k += 1
                toks.append(("regex", (src[i + 1:j], src[j + 1:k]), i))
                i = k
                continue
        m = _TOKEN.match(src, i)
        if not m:
            raise JSError(f"unexpected character {src[i]!r} at offset {i}")
        i, kind, text = m.end(), m.lastgroup, m.group()
        if kind in ("ws", "lc", "bc"):
            continue
        if kind == "num":
            if text[:2].lower() == "0x":
                val = int(text, 16)
            elif text.isdigit():
                val = int(text)
            else:
                val = float(text)
            toks.append(("num", val, m.start()))
        elif kind == "str":
            toks.append(("str", _unescape(text[1:-1]), m.start()))
        else:
            toks.append((kind, text, m.start()))
    toks.append(("eof", None, n))
    return toks


# -------------------------------------------------------------------- parser

_BINARY = {"||": 1, "&&": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "===": 6, "!==": 6, "<": 7, ">": 7,
           "<=": 7, ">=": 7, "instanceof": 7, "in": 7, "<<": 8, ">>": 8, ">>>": 8, "+": 9, "-": 9, "*": 10,
           "/": 10, "%": 10}
_ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>="}
_LITERALS = {"true": ("bool", True), "false": ("bool", False), "null": ("null",), "undefined": ("undef",)}


class Parser:
    def __init__(self, src: str):
        self.t = tokenize(src)
        self.i = 0
        self.no_in = False

    def peek(self, k=0):
        return self.t[min(self.i + k, len(self.t) - 1)]

    def at(self, kind, val=None):
        tok = self.t[self.i]
        return tok[0] == kind and (val is None or tok[1] == val)

    def eat(self, kind, val):
        if self.at(kind, val):
            self.i += 1
            return True
        return False

    def expect(self, kind, val=None):
        tok = self.t[self.i]
        if tok[0] != kind or (val is not None and tok[1] != val):
            raise JSError(f"expected {val or kind!r} but found {tok[1]!r} at offset {tok[2]}")
        self.i += 1
        return tok[1]

    def program(self) -> list:
        body = []
        while not self.at("eof"):
            body.append(self.statement())
        return body

    def block(self) -> list:
        self.expect("punc", "{")
        body = []
        while not self.at("punc", "}"):
            if self.at("eof"):
                raise JSError("unterminated block")
            body.append(self.statement())
        self.i += 1
        return body

    def function(self, declaration: bool):
        self.expect("id", "function")
        name = None
        if self.at("id"):
            name = self.expect("id")
        elif declaration:
            raise JSError("function declaration without a name")
        self.expect("punc", "(")
        params = []
        while not self.at("punc", ")"):
            params.append(self.expect("id"))
            self.eat("punc", ",")
        self.i += 1
        return name, params, self.block()

    def var_declarations(self) -> list:
        decls = []
        while True:
            name = self.expect("id")
            init = self.assignment() if self.eat("punc", "=") else None
            decls.append([name, init])
            if not self.eat("punc", ","):
                return decls

    def statement(self):
        tok = self.t[self.i]
        if tok[0] == "punc":
            if tok[1] == "{":
                return ("block", self.block())
            if tok[1] == ";":
                self.i += 1
                return ("empty",)
        if tok[0] == "id":
            kw = tok[1]
            if kw == "var":
                self.i += 1
                decls = self.var_declarations()
                self.eat("punc", ";")
                return ("var", decls)
            if kw == "function" and self.peek(1)[0] == "id":
                name, params, body = self.function(True)
                return ("funcdecl", name, params, body)
            if kw == "if":
                self.i += 1
                self.expect("punc", "(")
                test = self.expression()
                self.expect("punc", ")")
                cons = self.statement()
                alt = self.statement() if self.eat("id", "else") else None
                return ("if", test, cons, alt)
            if kw == "for":
                return self.for_statement()
            if kw == "while":
                self.i += 1
                self.expect("punc", "(")
                test = self.expression()
                self.expect("punc", ")")
                return ("while", test, self.statement())
            if kw == "do":
                self.i += 1
                body = self.statement()
                self.expect("id", "while")
                self.expect("punc", "(")
                test = self.expression()
                self.expect("punc", ")")
                self.eat("punc", ";")
                return ("dowhile", body, test)
            if kw == "return":
                self.i += 1
                value = None
                if not (self.at("punc", ";") or self.at("punc", "}") or self.at("eof")):
                    value = self.expression()
                self.eat("punc", ";")
                return ("return", value)
            if kw in ("break", "continue"):
                self.i += 1
                self.eat("punc", ";")
                return (kw,)
            if kw == "switch":
                self.i += 1
                self.expect("punc", "(")
                disc = self.expression()
                self.expect("punc", ")")
                self.expect("punc", "{")
                cases = []
                while not self.eat("punc", "}"):
                    if self.eat("id", "default"):
                        test = None
                    else:
                        self.expect("id", "case")
                        test = self.expression()
                    self.expect("punc", ":")
                    body = []
                    while not (self.at("id", "case") or self.at("id", "default") or self.at("punc", "}")):
                        body.append(self.statement())
                    cases.append([test, body])
                return ("switch", disc, cases)
            if kw == "try":
                self.i += 1
                body, param, handler, final = self.block(), None, None, None
                if self.eat("id", "catch"):
                    self.expect("punc", "(")
                    param = self.expect("id")
                    self.expect("punc", ")")
                    handler = self.block()
                if self.eat("id", "finally"):
                    final = self.block()
                return ("try", body, param, handler, final)
            if kw == "throw":
                self.i += 1
                value = self.expression()
                self.eat("punc", ";")
                return ("throw", value)
        expr = self.expression()
        self.eat("punc", ";")
        return ("expr", expr)

    def for_statement(self):
        self.expect("id", "for")
        self.expect("punc", "(")
        init = None
        if self.at("id", "var") and self.peek(1)[0] == "id" and self.peek(2)[:2] == ("id", "in"):
            name = self.peek(1)[1]
            self.i += 3
            obj = self.expression()
            self.expect("punc", ")")
            return ("forin", name, True, obj, self.statement())
        if self.at("id") and self.peek(1)[:2] == ("id", "in") and self.peek()[1] != "var":
            name = self.peek()[1]
            self.i += 2
            obj = self.expression()
            self.expect("punc", ")")
            return ("forin", name, False, obj, self.statement())
        if not self.at("punc", ";"):
            self.no_in = True
            if self.eat("id", "var"):
                init = ("var", self.var_declarations())
            else:
                init = ("expr", self.expression())
            self.no_in = False
        self.expect("punc", ";")
        test = None if self.at("punc", ";") else self.expression()
        self.expect("punc", ";")
        update = None if self.at("punc", ")") else self.expression()
        self.expect("punc", ")")
        return ("for", init, test, update, self.statement())

    def expression(self):
        first = self.assignment()
        if not self.at("punc", ","):
            return first
        items = [first]
        while self.eat("punc", ","):
            items.append(self.assignment())
        return ("seq", items)

    def assignment(self):
        left = self.conditional()
        tok = self.t[self.i]
        if tok[0] == "punc" and tok[1] in _ASSIGN:
            self.i += 1
            return ("assign", tok[1], left, self.assignment())
        return left

    def conditional(self):
        test = self.binary(1)
        if self.eat("punc", "?"):
            saved, self.no_in = self.no_in, False
            a = self.assignment()
            self.no_in = saved
            self.expect("punc", ":")
            return ("cond", test, a, self.assignment())
        return test

    def binary(self, min_prec):
        left = self.unary()
        while True:
            tok = self.t[self.i]
            op = tok[1] if tok[0] in ("punc", "id") else None
            if tok[0] == "id" and op not in ("instanceof", "in"):
                op = None
            if op == "in" and self.no_in:
                op = None
            prec = _BINARY.get(op)
            if prec is None or prec < min_prec:
                return left
            self.i += 1
            right = self.binary(prec + 1)
            left = ("logical" if op in ("||", "&&") else "bin", op, left, right)

    def unary(self):
        tok = self.t[self.i]
        if tok[0] == "punc":
            if tok[1] in ("!", "-", "+", "~"):
                self.i += 1
                return ("unary", tok[1], self.unary())
            if tok[1] in ("++", "--"):
                self.i += 1
                return ("update", tok[1], True, self.unary())
        elif tok[0] == "id" and tok[1] in ("typeof", "void", "delete"):
            self.i += 1
            return ("unary", tok[1], self.unary())
        node = self.call_member()
        tok = self.t[self.i]
        if tok[0] == "punc" and tok[1] in ("++", "--"):
            self.i += 1
            return ("update", tok[1], False, node)
        return node

    def arguments(self) -> list:
        self.expect("punc", "(")
        args = []
        while not self.at("punc", ")"):
            args.append(self.assignment())
            if not self.eat("punc", ","):
                break
        self.expect("punc", ")")
        return args

    def call_member(self):
        if self.at("id", "new"):
            self.i += 1
            callee = self.primary()
            while True:
                if self.eat("punc", "."):
                    callee = ("member", callee, self.expect("id"))
                elif self.at("punc", "["):
                    self.i += 1
                    callee = ("index", callee, self.expression())
                    self.expect("punc", "]")
                else:
                    break
            node = ("new", callee, self.arguments() if self.at("punc", "(") else [])
        else:
            node = self.primary()
        while True:
            if self.eat("punc", "."):
                node = ("member", node, self.expect("id"))
            elif self.at("punc", "["):
                self.i += 1
                saved, self.no_in = self.no_in, False
                node = ("index", node, self.expression())
                self.no_in = saved
                self.expect("punc", "]")
            elif self.at("punc", "("):
                saved, self.no_in = self.no_in, False
                node = ("call", node, self.arguments())
                self.no_in = saved
            else:
                return node

    def primary(self):
        kind, val, pos = self.t[self.i]
        if kind == "num":
            self.i += 1
            return ("num", val)
        if kind == "str":
            self.i += 1
            return ("str", val)
        if kind == "regex":
            self.i += 1
            return ("regex", val[0], val[1])
        if kind == "id":
            if val == "function":
                name, params, body = self.function(False)
                return ("func", name, params, body)
            self.i += 1
            if val in _LITERALS:
                return _LITERALS[val]
            if val == "this":
                return ("this",)
            return ("id", val)
        if kind == "punc":
            if val == "(":
                self.i += 1
                saved, self.no_in = self.no_in, False
                node = self.expression()
                self.no_in = saved
                self.expect("punc", ")")
                return ("paren", node)
            if val == "[":
                self.i += 1
                items = []
                while not self.at("punc", "]"):
                    if self.at("punc", ","):
                        self.i += 1
                        items.append(("undef",))
                        continue
                    items.append(self.assignment())
                    if not self.eat("punc", ","):
                        break
                self.expect("punc", "]")
                return ("array", items)
            if val == "{":
                self.i += 1
                props = []
                while not self.at("punc", "}"):
                    k_kind, k_val, _ = self.t[self.i]
                    if k_kind not in ("id", "str", "num"):
                        raise JSError(f"bad object key {k_val!r} at offset {pos}")
                    self.i += 1
                    self.expect("punc", ":")
                    props.append([to_str(k_val) if k_kind == "num" else k_val, self.assignment()])
                    if not self.eat("punc", ","):
                        break
                self.expect("punc", "}")
                return ("object", props)
        raise JSError(f"unexpected token {val!r} at offset {pos}")


def parse(src: str) -> list:
    return Parser(src).program()


def parse_expression(src: str):
    p = Parser(src)
    node = p.expression()
    if not p.at("eof"):
        raise JSError(f"trailing text after expression at offset {p.peek()[2]}")
    return node


def walk(node):
    """Yield every AST node (tuple) under node, depth first, in source order."""
    if isinstance(node, tuple):
        yield node
        for child in node[1:]:
            if isinstance(child, (tuple, list)):
                yield from walk(child)
    elif isinstance(node, list):
        for child in node:
            if isinstance(child, (tuple, list)):
                yield from walk(child)


def unparen(node):
    while isinstance(node, tuple) and node[0] == "paren":
        node = node[1]
    return node


# ------------------------------------------------------------ value helpers

def to_num(v):
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v
    if v is None:
        return 0
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return 0
        try:
            if s[:2].lower() == "0x":
                return int(s, 16)
            f = float(s)
            return int(f) if f.is_integer() and "e" not in s.lower() and "." not in s else f
        except ValueError:
            return math.nan
    if isinstance(v, list):
        return to_num(to_str(v))
    return math.nan


def _norm(x):
    if isinstance(x, float) and x.is_integer() and abs(x) < 2 ** 53:
        return int(x)
    return x


def to_int(v) -> int:
    n = to_num(v)
    if isinstance(n, float):
        if math.isnan(n) or math.isinf(n):
            return 0
        n = int(n)
    return n


def to_int32(v) -> int:
    n = to_int(v) & 0xFFFFFFFF
    return n - 0x100000000 if n >= 0x80000000 else n


def to_str(v) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "Infinity" if v > 0 else "-Infinity"
        return str(int(v)) if v.is_integer() else repr(v)
    if v is None:
        return "null"
    if v is UNDEF:
        return "undefined"
    if isinstance(v, list):
        return ",".join("" if x is None or x is UNDEF else to_str(x) for x in v)
    if isinstance(v, JSRegex):
        return f"/{v.source}/{v.flags}"
    if isinstance(v, dict):
        return "[object Object]"
    return "function"


def truthy(v) -> bool:
    if v is None or v is UNDEF:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return not (v == 0 or (isinstance(v, float) and math.isnan(v)))
    if isinstance(v, str):
        return v != ""
    return True


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def strict_eq(a, b) -> bool:
    if _is_num(a) and _is_num(b):
        return a == b
    if type(a) is not type(b):
        return False
    if isinstance(a, (str, bool)):
        return a == b
    return a is b


def loose_eq(a, b) -> bool:
    if (a is None or a is UNDEF) and (b is None or b is UNDEF):
        return True
    if a is None or a is UNDEF or b is None or b is UNDEF:
        return False
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if isinstance(a, (list, dict)) and isinstance(b, (list, dict)):
        return a is b
    if isinstance(a, (list, dict)):
        a = to_str(a)
    if isinstance(b, (list, dict)):
        b = to_str(b)
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return to_num(a) == to_num(b)


def parse_int(text, radix=UNDEF):
    s = to_str(text).strip()
    sign = 1
    if s[:1] in "+-":
        sign = -1 if s[0] == "-" else 1
        s = s[1:]
    r = to_int(radix) if radix is not UNDEF else 0
    if r in (0, 16) and s[:2].lower() == "0x":
        s, r = s[2:], 16
    if r == 0:
        r = 10
    if not 2 <= r <= 36:
        return math.nan
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"[:r]
    end = 0
    while end < len(s) and s[end].lower() in digits:
        end += 1
    return sign * int(s[:end], r) if end else math.nan


def _unescape_percent(s: str) -> str:
    def rep(m):
        return chr(int(m.group(1) or m.group(2), 16))
    return re.sub(r"%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})", rep, s)


def _decode_uri(s: str) -> str:
    raw = re.sub(rb"%([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), s.encode("utf-8"))
    return raw.decode("utf-8", "replace")


# --------------------------------------------------------------- interpreter

class _Return(Exception):
    def __init__(self, value):
        self.value = value


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class Scope:
    __slots__ = ("vars", "parent")

    def __init__(self, parent=None):
        self.vars = {}
        self.parent = parent

    def find(self, name):
        s = self
        while s is not None:
            if name in s.vars:
                return s
            s = s.parent
        return None


class JSFunction:
    def __init__(self, name, params, body, scope):
        self.name, self.params, self.body, self.scope = name, params, body, scope


class Native:
    def __init__(self, fn, props=None):
        self.fn = fn  # fn(this, args)
        self.props = props or {}


def _idx(args, i, default=UNDEF):
    return args[i] if i < len(args) else default


def _clamp(i, n):
    return max(0, min(n, i))


def _rel(i, n):
    return max(n + i, 0) if i < 0 else min(i, n)


class Interp:
    MAX_STEPS = 4_000_000

    def __init__(self):
        self.steps = 0
        self.eval_hook = None  # callable(text) -> value; lets a caller capture what a script would eval
        self.globals = Scope()
        g = self.globals.vars
        g["String"] = Native(lambda this, a: to_str(_idx(a, 0, "")),
                             {"fromCharCode": Native(lambda this, a: "".join(chr(to_int(x) & 0xFFFF) for x in a))})
        g["Number"] = Native(lambda this, a: to_num(_idx(a, 0, 0)))
        g["parseInt"] = Native(lambda this, a: parse_int(_idx(a, 0), _idx(a, 1)))
        g["parseFloat"] = Native(lambda this, a: to_num(re.match(r"\s*[+-]?(\d+\.?\d*|\.\d+)?([eE][+-]?\d+)?", to_str(_idx(a, 0))).group().strip() or "x"))
        g["isNaN"] = Native(lambda this, a: (lambda n: isinstance(n, float) and math.isnan(n))(to_num(_idx(a, 0))))
        g["unescape"] = Native(lambda this, a: _unescape_percent(to_str(_idx(a, 0))))
        g["decodeURIComponent"] = Native(lambda this, a: _decode_uri(to_str(_idx(a, 0))))
        g["decodeURI"] = g["decodeURIComponent"]
        g["Object"] = Native(lambda this, a: JSObject())
        g["Array"] = Native(lambda this, a: self._new_array(a))
        g["Error"] = Native(lambda this, a: JSObject({"message": to_str(_idx(a, 0, ""))}))
        g["NaN"], g["Infinity"] = math.nan, math.inf
        g["Math"] = JSObject({
            "floor": Native(lambda this, a: _norm(float(math.floor(to_num(a[0]))))),
            "ceil": Native(lambda this, a: _norm(float(math.ceil(to_num(a[0]))))),
            "round": Native(lambda this, a: _norm(float(math.floor(to_num(a[0]) + 0.5)))),
            "abs": Native(lambda this, a: abs(to_num(a[0]))),
            "min": Native(lambda this, a: min(to_num(x) for x in a)),
            "max": Native(lambda this, a: max(to_num(x) for x in a)),
            "pow": Native(lambda this, a: _norm(float(to_num(a[0]) ** to_num(a[1])))),
        })

    @staticmethod
    def _new_array(a):
        if len(a) == 1 and _is_num(a[0]):
            return JSArray([UNDEF] * to_int(a[0]))
        return JSArray(a)

    # --- running code -----------------------------------------------------

    def run(self, program: list, scope=None):
        scope = scope or self.globals
        self._hoist(program, scope)
        for stmt in program:
            self.exec(stmt, scope)

    def define_only(self, program: list):
        """Bind top-level functions and literal vars; skip anything else at top level."""
        scope = self.globals
        self._hoist(program, scope)
        for stmt in program:
            if stmt[0] == "funcdecl":
                continue
            if stmt[0] == "var":
                try:
                    self.exec(stmt, scope)
                except (JSError, JSThrow):
                    for name, _ in stmt[1]:
                        scope.vars.setdefault(name, UNDEF)
            elif stmt[0] == "expr" and unparen(stmt[1])[0] == "assign":
                try:
                    self.exec(stmt, scope)
                except (JSError, JSThrow):
                    pass

    def _hoist(self, body: list, scope: Scope):
        for stmt in body:
            if stmt[0] == "funcdecl":
                scope.vars[stmt[1]] = JSFunction(stmt[1], stmt[2], stmt[3], scope)

    def call(self, fn, this=UNDEF, args=()):
        args = list(args)
        if isinstance(fn, Native):
            return fn.fn(this, args)
        if not isinstance(fn, JSFunction):
            raise JSError(f"{to_str(fn)} is not a function")
        scope = Scope(fn.scope)
        if fn.name:
            scope.vars[fn.name] = fn
        for i, p in enumerate(fn.params):
            scope.vars[p] = args[i] if i < len(args) else UNDEF
        scope.vars["arguments"] = JSArray(args)
        scope.vars["this"] = this
        self._hoist(fn.body, scope)
        try:
            for stmt in fn.body:
                self.exec(stmt, scope)
        except _Return as r:
            return r.value
        return UNDEF

    # --- statements -------------------------------------------------------

    def exec(self, s, scope: Scope):
        self.steps += 1
        if self.steps > self.MAX_STEPS:
            raise JSError("step limit exceeded")
        k = s[0]
        if k == "expr":
            self.eval(s[1], scope)
        elif k == "var":
            for name, init in s[1]:
                if init is not None:
                    scope.vars[name] = self.eval(init, scope)
                else:
                    scope.vars.setdefault(name, UNDEF)
        elif k == "if":
            if truthy(self.eval(s[1], scope)):
                self.exec(s[2], scope)
            elif s[3] is not None:
                self.exec(s[3], scope)
        elif k == "block":
            for st in s[1]:
                self.exec(st, scope)
        elif k == "for":
            if s[1] is not None:
                self.exec(s[1], scope)
            while s[2] is None or truthy(self.eval(s[2], scope)):
                try:
                    self.exec(s[4], scope)
                except _Break:
                    break
                except _Continue:
                    pass
                if s[3] is not None:
                    self.eval(s[3], scope)
        elif k == "while":
            while truthy(self.eval(s[1], scope)):
                try:
                    self.exec(s[2], scope)
                except _Break:
                    break
                except _Continue:
                    pass
        elif k == "dowhile":
            while True:
                try:
                    self.exec(s[1], scope)
                except _Break:
                    break
                except _Continue:
                    pass
                if not truthy(self.eval(s[2], scope)):
                    break
        elif k == "forin":
            obj = self.eval(s[3], scope)
            keys = [str(i) for i in range(len(obj))] if isinstance(obj, (list, str)) else list(obj) if isinstance(obj, dict) else []
            for key in keys:
                self._assign_name(s[1], key, scope, declare=s[2])
                try:
                    self.exec(s[4], scope)
                except _Break:
                    break
                except _Continue:
                    pass
        elif k == "return":
            raise _Return(UNDEF if s[1] is None else self.eval(s[1], scope))
        elif k == "break":
            raise _Break()
        elif k == "continue":
            raise _Continue()
        elif k == "switch":
            disc = self.eval(s[1], scope)
            start = next((i for i, (test, _) in enumerate(s[2])
                          if test is not None and strict_eq(disc, self.eval(test, scope))), None)
            if start is None:
                start = next((i for i, (test, _) in enumerate(s[2]) if test is None), None)
            if start is not None:
                try:
                    for _, body in s[2][start:]:
                        for st in body:
                            self.exec(st, scope)
                except _Break:
                    pass
        elif k == "try":
            try:
                try:
                    for st in s[1]:
                        self.exec(st, scope)
                except JSThrow as e:
                    if s[3] is None:
                        raise
                    scope.vars[s[2]] = e.value
                    for st in s[3]:
                        self.exec(st, scope)
            finally:
                if s[4] is not None:
                    for st in s[4]:
                        self.exec(st, scope)
        elif k == "throw":
            raise JSThrow(self.eval(s[1], scope))
        elif k == "funcdecl":
            scope.vars.setdefault(s[1], JSFunction(s[1], s[2], s[3], scope))
        elif k == "empty":
            pass
        else:
            raise JSError(f"unsupported statement {k}")

    def _assign_name(self, name, value, scope, declare=False):
        target = scope if declare and scope.find(name) is None else (scope.find(name) or self.globals)
        target.vars[name] = value

    # --- expressions ------------------------------------------------------

    def eval(self, e, scope: Scope):
        self.steps += 1
        if self.steps > self.MAX_STEPS:
            raise JSError("step limit exceeded")
        k = e[0]
        if k == "num" or k == "str" or k == "bool":
            return e[1]
        if k == "id":
            s = scope.find(e[1])
            if s is None:
                raise JSError(f"{e[1]} is not available to static evaluation")
            return s.vars[e[1]]
        if k == "paren":
            return self.eval(e[1], scope)
        if k == "index":
            return self.get(self.eval(e[1], scope), self.eval(e[2], scope))
        if k == "member":
            return self.get(self.eval(e[1], scope), e[2])
        if k == "call":
            return self._call(e, scope)
        if k == "bin":
            return self._binary(e[1], self.eval(e[2], scope), self.eval(e[3], scope))
        if k == "assign":
            return self._assign(e, scope)
        if k == "update":
            old = to_num(self.eval(e[3], scope))
            new = old + 1 if e[1] == "++" else old - 1
            self._store(e[3], new, scope)
            return new if e[2] else old
        if k == "array":
            return JSArray(self.eval(x, scope) for x in e[1])
        if k == "object":
            return JSObject((key, self.eval(v, scope)) for key, v in e[1])
        if k == "func":
            return JSFunction(e[1], e[2], e[3], scope)
        if k == "logical":
            left = self.eval(e[2], scope)
            if e[1] == "||":
                return left if truthy(left) else self.eval(e[3], scope)
            return self.eval(e[3], scope) if truthy(left) else left
        if k == "cond":
            return self.eval(e[2] if truthy(self.eval(e[1], scope)) else e[3], scope)
        if k == "unary":
            return self._unary(e, scope)
        if k == "null":
            return None
        if k == "undef":
            return UNDEF
        if k == "this":
            s = scope.find("this")
            return s.vars["this"] if s else UNDEF
        if k == "seq":
            value = UNDEF
            for x in e[1]:
                value = self.eval(x, scope)
            return value
        if k == "new":
            return self._new(e, scope)
        if k == "regex":
            return JSRegex(e[1], e[2])
        raise JSError(f"unsupported expression {k}")

    def _unary(self, e, scope):
        op = e[1]
        if op == "typeof":
            target = unparen(e[2])
            if target[0] == "id" and scope.find(target[1]) is None:
                return "undefined"
            v = self.eval(e[2], scope)
            if v is UNDEF:
                return "undefined"
            if isinstance(v, bool):
                return "boolean"
            if isinstance(v, (int, float)):
                return "number"
            if isinstance(v, str):
                return "string"
            return "function" if isinstance(v, (JSFunction, Native)) else "object"
        if op == "delete":
            target = unparen(e[2])
            if target[0] in ("member", "index"):
                obj = self.eval(target[1], scope)
                key = target[2] if target[0] == "member" else to_str(self.eval(target[2], scope))
                if isinstance(obj, dict):
                    obj.pop(key, None)
            return True
        v = self.eval(e[2], scope)
        if op == "!":
            return not truthy(v)
        if op == "-":
            return _norm(-to_num(v))
        if op == "+":
            return to_num(v)
        if op == "~":
            return ~to_int32(v)
        if op == "void":
            return UNDEF
        raise JSError(f"unsupported unary {op}")

    def _binary(self, op, a, b):
        if op == "+":
            if isinstance(a, (str, list, dict)) or isinstance(b, (str, list, dict)):
                return to_str(a) + to_str(b)
            return _norm(to_num(a) + to_num(b))
        if op == "-":
            return _norm(to_num(a) - to_num(b))
        if op == "*":
            return _norm(to_num(a) * to_num(b))
        if op == "/":
            x, y = to_num(a), to_num(b)
            if y == 0:
                return math.nan if x == 0 or (isinstance(x, float) and math.isnan(x)) else math.copysign(math.inf, x)
            return _norm(x / y)
        if op == "%":
            x, y = to_num(a), to_num(b)
            if y == 0:
                return math.nan
            return _norm(math.fmod(x, y)) if isinstance(x, float) or isinstance(y, float) else int(math.fmod(x, y))
        if op == "^":
            return to_int32(to_int32(a) ^ to_int32(b))
        if op == "&":
            return to_int32(to_int32(a) & to_int32(b))
        if op == "|":
            return to_int32(to_int32(a) | to_int32(b))
        if op == "<<":
            return to_int32(to_int32(a) << (to_int(b) & 31))
        if op == ">>":
            return to_int32(a) >> (to_int(b) & 31)
        if op == ">>>":
            return (to_int(a) & 0xFFFFFFFF) >> (to_int(b) & 31)
        if op == "==":
            return loose_eq(a, b)
        if op == "!=":
            return not loose_eq(a, b)
        if op == "===":
            return strict_eq(a, b)
        if op == "!==":
            return not strict_eq(a, b)
        if op in ("<", ">", "<=", ">="):
            if isinstance(a, str) and isinstance(b, str):
                x, y = a, b
            else:
                x, y = to_num(a), to_num(b)
                if any(isinstance(n, float) and math.isnan(n) for n in (x, y)):
                    return False
            return x < y if op == "<" else x > y if op == ">" else x <= y if op == "<=" else x >= y
        if op == "in":
            if isinstance(b, dict):
                return to_str(a) in b
            if isinstance(b, list):
                return 0 <= to_int(a) < len(b)
            return False
        if op == "instanceof":
            return False
        raise JSError(f"unsupported operator {op}")

    def _assign(self, e, scope):
        op, target = e[1], e[2]
        value = self.eval(e[3], scope)
        if op != "=":
            value = self._binary(op[:-1], self.eval(target, scope), value)
        self._store(target, value, scope)
        return value

    def _store(self, target, value, scope):
        target = unparen(target)
        k = target[0]
        if k == "id":
            self._assign_name(target[1], value, scope)
            return
        if k not in ("member", "index"):
            raise JSError("unsupported assignment target")
        obj = self.eval(target[1], scope)
        key = target[2] if k == "member" else self.eval(target[2], scope)
        if isinstance(obj, list):
            if _is_num(key) or (isinstance(key, str) and key.isdigit()):
                i = to_int(key)
                while len(obj) <= i:
                    obj.append(UNDEF)
                obj[i] = value
            elif key == "length":
                del obj[to_int(value):]
        elif isinstance(obj, dict):
            obj[to_str(key)] = value
        elif isinstance(obj, (JSFunction, Native, str)):
            pass
        else:
            raise JSError(f"cannot set property {to_str(key)!r} of {to_str(obj)}")

    def _new(self, e, scope):
        callee = unparen(e[1])
        name = callee[1] if callee[0] == "id" else None
        args = [self.eval(a, scope) for a in e[2]]
        if name in ("Object", "Array", "Error", "String", "Number"):
            return self.call(self.globals.vars[name], UNDEF, args)
        if name == "RegExp":
            return JSRegex(to_str(_idx(args, 0, "")), to_str(_idx(args, 1, "")))
        fn = self.eval(callee, scope) if name is None or scope.find(name) else None
        if isinstance(fn, JSFunction):
            this = JSObject()
            result = self.call(fn, this, args)
            return result if isinstance(result, (dict, list)) else this
        raise JSError(f"new {name or 'expression'} is not available to static evaluation")

    def _call(self, e, scope):
        callee = unparen(e[1])
        if callee[0] == "member":
            this = self.eval(callee[1], scope)
            fn = self.get(this, callee[2])
        elif callee[0] == "index":
            this = self.eval(callee[1], scope)
            fn = self.get(this, self.eval(callee[2], scope))
        else:
            if callee[0] == "id" and callee[1] == "eval":
                if self.eval_hook is None:
                    raise JSError("eval is never evaluated")
                return self.eval_hook(to_str(self.eval(e[2][0], scope)) if e[2] else "")
            this, fn = UNDEF, self.eval(callee, scope)
        if not isinstance(fn, (JSFunction, Native)):
            raise JSError(f"call target is not a function: {to_str(fn)}")
        return self.call(fn, this, [self.eval(a, scope) for a in e[2]])

    # --- property access --------------------------------------------------

    def get(self, obj, key):
        if isinstance(obj, str):
            if key == "length":
                return len(obj)
            if _is_num(key) or (isinstance(key, str) and key.isdigit()):
                i = to_int(key)
                return obj[i] if 0 <= i < len(obj) else UNDEF
            return _STRING.get(key, UNDEF)
        if isinstance(obj, list):
            if key == "length":
                return len(obj)
            if _is_num(key) or (isinstance(key, str) and key.isdigit()):
                i = to_int(key)
                return obj[i] if 0 <= i < len(obj) else UNDEF
            m = _ARRAY.get(key)
            if m is not None:
                return m
            if key == "sort":
                return Native(lambda this, a: self._sort(this, _idx(a, 0)))
            return UNDEF
        if isinstance(obj, dict):
            key = to_str(key)
            if key in obj:
                return obj[key]
            if key == "hasOwnProperty":
                return Native(lambda this, a: to_str(_idx(a, 0)) in this)
            if key == "toString":
                return Native(lambda this, a: to_str(this))
            return UNDEF
        if isinstance(obj, (JSFunction, Native)):
            if key == "call":
                return Native(lambda this, a: self.call(this, _idx(a, 0), a[1:]))
            if key == "apply":
                return Native(lambda this, a: self.call(this, _idx(a, 0), list(a[1]) if len(a) > 1 and isinstance(a[1], list) else []))
            if isinstance(obj, Native) and key in obj.props:
                return obj.props[key]
            if key == "length" and isinstance(obj, JSFunction):
                return len(obj.params)
            return UNDEF
        if isinstance(obj, JSRegex):
            if key == "test":
                return Native(lambda this, a: this.re.search(to_str(_idx(a, 0))) is not None)
            if key == "source":
                return obj.source
            return UNDEF
        if _is_num(obj) or isinstance(obj, bool):
            if key == "toString":
                return Native(lambda this, a: _radix(this, _idx(a, 0)))
            return UNDEF
        raise JSError(f"cannot read property {to_str(key)!r} of {to_str(obj)}")

    def _sort(self, arr, cmp):
        import functools
        if isinstance(cmp, (JSFunction, Native)):
            arr.sort(key=functools.cmp_to_key(lambda x, y: (lambda r: -1 if r < 0 else 1 if r > 0 else 0)(to_num(self.call(cmp, UNDEF, [x, y])))))
        else:
            arr.sort(key=to_str)
        return arr

    def replace(self, s, pattern, repl):
        def expand(m):
            if isinstance(repl, (JSFunction, Native)):
                return to_str(self.call(repl, UNDEF, [m.group(0), *m.groups(""), m.start(), s]))
            text = to_str(repl)
            return re.sub(r"\$(\$|&|\d{1,2})", lambda r: "$" if r.group(1) == "$" else m.group(0) if r.group(1) == "&"
                          else (m.group(int(r.group(1))) or "") if int(r.group(1)) <= (m.re.groups) else r.group(0), text)
        if isinstance(pattern, JSRegex):
            return pattern.re.sub(expand, s, count=0 if pattern.g else 1)
        needle = to_str(pattern)
        i = s.find(needle)
        if i < 0:
            return s
        return s[:i] + expand(re.match(re.escape(needle), s[i:])) + s[i + len(needle):]


def _radix(n, radix):
    r = to_int(radix) if radix is not UNDEF else 10
    if r == 10 or not _is_num(n) or isinstance(n, float) and not n.is_integer():
        return to_str(n)
    n, digits, out = int(n), "0123456789abcdefghijklmnopqrstuvwxyz", ""
    neg, n = n < 0, abs(n)
    while True:
        out = digits[n % r] + out
        n //= r
        if not n:
            return ("-" if neg else "") + out


def _split(this, a):
    sep, limit = _idx(a, 0), _idx(a, 1)
    if sep is UNDEF:
        parts = [this]
    elif isinstance(sep, JSRegex):
        parts = sep.re.split(this)
    elif to_str(sep) == "":
        parts = list(this)
    else:
        parts = this.split(to_str(sep))
    if limit is not UNDEF:
        parts = parts[:to_int(limit)]
    return JSArray(parts)


def _substr(this, a):
    n = len(this)
    start = _rel(to_int(_idx(a, 0, 0)), n)
    length = n - start if _idx(a, 1) is UNDEF else max(0, to_int(a[1]))
    return this[start:start + length]


def _substring(this, a):
    n = len(this)
    s = _clamp(to_int(_idx(a, 0, 0)), n)
    e = n if _idx(a, 1) is UNDEF else _clamp(to_int(a[1]), n)
    return this[min(s, e):max(s, e)]


def _slice(this, a):
    n = len(this)
    s = _rel(to_int(_idx(a, 0, 0)), n)
    e = n if _idx(a, 1) is UNDEF else _rel(to_int(a[1]), n)
    return this[s:e] if isinstance(this, str) else JSArray(this[s:e])


def _splice(this, a):
    n = len(this)
    s = _rel(to_int(_idx(a, 0, 0)), n)
    count = n - s if _idx(a, 1) is UNDEF else max(0, min(to_int(a[1]), n - s))
    removed = JSArray(this[s:s + count])
    this[s:s + count] = a[2:]
    return removed


def _concat(this, a):
    out = JSArray(this)
    for x in a:
        if isinstance(x, list):
            out.extend(x)
        else:
            out.append(x)
    return out


def _find(seq, item, start):
    for i in range(max(0, start), len(seq)):
        if strict_eq(seq[i], item):
            return i
    return -1


def _char_code(this, a):
    i = to_int(_idx(a, 0, 0))
    return ord(this[i]) if 0 <= i < len(this) else math.nan


def _char_at(this, a):
    i = to_int(_idx(a, 0, 0))
    return this[i] if 0 <= i < len(this) else ""


def _match(this, a):
    rx = _idx(a, 0)
    if not isinstance(rx, JSRegex):
        rx = JSRegex(re.escape(to_str(rx)), "")
    if rx.g:
        found = [m.group(0) for m in rx.re.finditer(this)]
        return JSArray(found) if found else None
    m = rx.re.search(this)
    return JSArray([m.group(0), *[g if g is not None else UNDEF for g in m.groups()]]) if m else None


_STRING = {
    "charAt": Native(_char_at),
    "charCodeAt": Native(_char_code),
    "indexOf": Native(lambda this, a: this.find(to_str(_idx(a, 0)), _clamp(to_int(_idx(a, 1, 0)), len(this)))),
    "lastIndexOf": Native(lambda this, a: this.rfind(to_str(_idx(a, 0)))),
    "substr": Native(_substr),
    "substring": Native(_substring),
    "slice": Native(_slice),
    "split": Native(_split),
    "toLowerCase": Native(lambda this, a: this.lower()),
    "toUpperCase": Native(lambda this, a: this.upper()),
    "concat": Native(lambda this, a: this + "".join(to_str(x) for x in a)),
    "toString": Native(lambda this, a: this),
    "valueOf": Native(lambda this, a: this),
    "match": Native(_match),
    "replace": None,  # bound per interpreter below
}
_ARRAY = {
    "push": Native(lambda this, a: (this.extend(a), len(this))[1]),
    "pop": Native(lambda this, a: this.pop() if this else UNDEF),
    "shift": Native(lambda this, a: this.pop(0) if this else UNDEF),
    "unshift": Native(lambda this, a: (this.__setitem__(slice(0, 0), a), len(this))[1]),
    "slice": Native(_slice),
    "splice": Native(_splice),
    "reverse": Native(lambda this, a: (this.reverse(), this)[1]),
    "join": Native(lambda this, a: ("," if _idx(a, 0) is UNDEF else to_str(a[0])).join(
        "" if x is None or x is UNDEF else to_str(x) for x in this)),
    "concat": Native(_concat),
    "indexOf": Native(lambda this, a: _find(this, _idx(a, 0), to_int(_idx(a, 1, 0)))),
    "toString": Native(lambda this, a: to_str(this)),
}
_REPLACER = Interp()
_STRING["replace"] = Native(lambda this, a: _REPLACER.replace(this, _idx(a, 0), _idx(a, 1, "undefined")))


def to_python(v):
    """Convert an interpreter value to plain Python data (lists, dicts, str, numbers)."""
    if isinstance(v, list):
        return [to_python(x) for x in v]
    if isinstance(v, dict):
        return {k: to_python(x) for k, x in v.items()}
    if v is UNDEF:
        return None
    return v
