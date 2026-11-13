"""A small static evaluator for the VBScript subset used by WSH triage specimens.

Nothing is ever handed to cscript/wscript: the source is tokenized, parsed into a
tree, and walked in Python. It covers Const/Dim/ReDim, assignments, arrays,
If/ElseIf/Else (block and single-line), Select Case, For/Next, For Each, Do/Loop
(While/Until, pre and post), While/Wend, Exit, Function/Sub with ByRef/ByVal,
Call, On Error (ignored), Execute/ExecuteGlobal/Eval on recovered strings, and
the string/number built-ins that decoding routines use. COM objects are not
modelled; touching one raises VBSError.

    prog = parse(source)            # list of statement tuples (also used for structure checks)
    it = Interp(prog)
    it.call("Inspect_ab12")         # -> value

Statement tuples (name fields are lower-cased):
    ("const", name, expr) ("dim", [name]) ("redim", preserve, name, [expr])
    ("assign", target, expr)  target = ("name", n) | ("call", n, [args])
    ("if", [(cond, block)], else_block) ("select", expr, [([values], block)], else_block)
    ("for", var, start, end, step, block) ("foreach", var, expr, block)
    ("do", pre_kind, pre_cond, post_kind, post_cond, block) ("while", cond, block)
    ("exit", kind) ("callstmt", expr) ("onerror", mode) ("execute", expr)
    ("func", name, [(param, byval)], block, is_sub, original_name)
Expression tuples:
    ("lit", v) ("name", n) ("call", n, [args]) ("member", base, n, [args])
    ("un", op, x) ("bin", op, a, b)
"""
import re

MAX_STEPS = 4_000_000


class VBSError(Exception):
    pass


class _Exit(Exception):
    def __init__(self, kind):
        self.kind = kind


_TOKEN = re.compile(r'''
    (?P<ws>[ \t\f]+)
  | (?P<cont>_[ \t]*\r?\n)
  | (?P<nl>\r?\n|\r)
  | (?P<colon>:)
  | (?P<comment>'[^\r\n]*)
  | (?P<str>"(?:[^"\r\n]|"")*")
  | (?P<hex>&[hH][0-9a-fA-F]+&?(?![A-Za-z0-9_]))
  | (?P<oct>&[oO][0-7]+&?(?![A-Za-z0-9_]))
  | (?P<num>\d+\.\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?|\d+(?:[eE][+-]?\d+)?)
  | (?P<id>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op><>|<=|>=|=<|=>|[-+*/\\^&=<>(),.])
''', re.X)


def tokenize(src: str) -> list:
    out, pos, n = [], 0, len(src)
    while pos < n:
        m = _TOKEN.match(src, pos)
        if not m:
            raise VBSError(f"cannot tokenize at {pos}: {src[pos:pos + 20]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind in ("ws", "cont", "comment"):
            continue
        text = m.group()
        if kind == "id" and text.lower() == "rem" and (not out or out[-1][0] in ("nl", "colon")):
            end = re.compile(r"[\r\n]").search(src, pos)
            pos = end.start() if end else n
            continue
        if kind == "str":
            out.append(("str", text[1:-1].replace('""', '"')))
        elif kind == "hex":
            out.append(("num", int(text.strip("&")[1:], 16)))
        elif kind == "oct":
            out.append(("num", int(text.strip("&")[1:], 8)))
        elif kind == "num":
            out.append(("num", float(text) if re.search(r"[.eE]", text) else int(text)))
        elif kind == "id":
            out.append(("id", text.lower(), text))
        elif kind == "op":
            out.append(("op", {"=<": "<=", "=>": ">="}.get(text, text)))
        else:
            out.append((kind, text))
    out.append(("nl", "\n"))
    out.append(("eof", ""))
    return out


_BLOCK_END = {"end", "else", "elseif", "case", "next", "loop", "wend"}
_LITERALS = {"true": True, "false": False, "empty": None, "null": None, "nothing": None,
             "vbcrlf": "\r\n", "vbcr": "\r", "vblf": "\n", "vbtab": "\t", "vbnullstring": "", "vbnewline": "\r\n",
             "vbnullchar": "\x00", "vbbinarycompare": 0, "vbtextcompare": 1}


class Parser:
    def __init__(self, tokens):
        self.t, self.i = tokens, 0

    def peek(self, k=0):
        return self.t[min(self.i + k, len(self.t) - 1)]

    def next(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def is_id(self, *words, k=0):
        tok = self.peek(k)
        return tok[0] == "id" and tok[1] in words

    def is_op(self, *ops, k=0):
        tok = self.peek(k)
        return tok[0] == "op" and tok[1] in ops

    def want_id(self, *words):
        tok = self.next()
        if tok[0] != "id" or (words and tok[1] not in words):
            raise VBSError(f"expected {words or 'identifier'}, got {tok!r}")
        return tok

    def want_op(self, op):
        tok = self.next()
        if tok != ("op", op):
            raise VBSError(f"expected {op!r}, got {tok!r}")

    def skip_seps(self):
        while self.peek()[0] in ("nl", "colon"):
            self.i += 1

    def skip_line(self):
        while self.peek()[0] not in ("nl", "eof"):
            self.i += 1

    def program(self):
        return self.block(top=True)

    def block(self, top=False):
        out = []
        while True:
            self.skip_seps()
            tok = self.peek()
            if tok[0] == "eof":
                break
            if not top and tok[0] == "id" and tok[1] in _BLOCK_END:
                break
            st = self.statement()
            if st is not None:
                out.append(st)
        return out

    # ---- statements -------------------------------------------------
    def statement(self):
        tok = self.peek()
        if tok[0] != "id":
            raise VBSError(f"unexpected token {tok!r}")
        k = tok[1]
        if k == "option":
            return self.skip_line()
        if k in ("public", "private") and self.is_id("function", "sub", "const", "default", k=1):
            self.next()
            if self.is_id("default"):
                self.next()
            k = self.peek()[1]
        if k == "const":
            self.next()
            name = self.want_id()[1]
            self.want_op("=")
            return ("const", name, self.expr())
        if k in ("dim", "public", "private", "static"):
            self.next()
            names = []
            while True:
                names.append(self.want_id()[1])
                if self.is_op("("):
                    depth = 0
                    while True:
                        t = self.next()
                        if t == ("op", "("):
                            depth += 1
                        elif t == ("op", ")"):
                            depth -= 1
                            if depth == 0:
                                break
                    names[-1] = (names[-1], True)
                if self.is_op(","):
                    self.next()
                    continue
                break
            return ("dim", names)
        if k == "redim":
            self.next()
            preserve = False
            if self.is_id("preserve"):
                self.next()
                preserve = True
            name = self.want_id()[1]
            return ("redim", preserve, name, self.args())
        if k == "set":
            self.next()
            return self.assign_or_call()
        if k == "if":
            return self.if_stmt()
        if k == "select":
            return self.select_stmt()
        if k == "for":
            return self.for_stmt()
        if k == "do":
            return self.do_stmt()
        if k == "while":
            self.next()
            cond = self.expr()
            body = self.block()
            self.want_id("wend")
            return ("while", cond, body)
        if k == "exit":
            self.next()
            return ("exit", self.want_id()[1])
        if k == "call":
            self.next()
            return ("callstmt", self.postfix())
        if k == "on":
            self.next()
            self.want_id("error")
            mode = "resume" if self.is_id("resume") else "goto0"
            self.skip_line()
            return ("onerror", mode)
        if k in ("function", "sub"):
            return self.func_stmt()
        if k in ("execute", "executeglobal"):
            self.next()
            return ("execute", self.expr())
        return self.assign_or_call()

    def assign_or_call(self):
        target = self.postfix()
        if self.is_op("="):
            self.next()
            return ("assign", target, self.expr())
        # Sub call without parentheses: Name arg1, arg2
        if target[0] == "name" and self.peek()[0] not in ("nl", "colon", "eof") and not self.is_id("else"):
            args = [self.expr()]
            while self.is_op(","):
                self.next()
                args.append(self.expr())
            return ("callstmt", ("call", target[1], args))
        # Method call without parentheses: Obj.Method arg1, arg2  (Err.Raise 5, "source", "text")
        if target[0] == "member" and not target[3] and self.peek()[0] not in ("nl", "colon", "eof") \
                and not self.is_id("else"):
            args = [self.expr()]
            while self.is_op(","):
                self.next()
                args.append(self.expr())
            return ("callstmt", ("member", target[1], target[2], args))
        return ("callstmt", target)

    def if_stmt(self):
        self.want_id("if")
        cond = self.expr()
        self.want_id("then")
        if self.peek()[0] not in ("nl", "eof"):
            # single-line form: If c Then a : b Else c
            body, other = self.inline_statements(), []
            if self.is_id("else"):
                self.next()
                other = self.inline_statements()
            if self.is_id("end") and self.is_id("if", k=1):
                self.next()
                self.next()
            return ("if", [(cond, body)], other)
        arms = [(cond, self.block())]
        other = []
        while True:
            if self.is_id("elseif"):
                self.next()
                c = self.expr()
                self.want_id("then")
                arms.append((c, self.block()))
            elif self.is_id("else"):
                self.next()
                if self.is_id("if"):  # "Else If" written as two words on one line
                    other = [self.if_stmt()]
                    return ("if", arms, other)
                other = self.block()
            else:
                break
        self.want_id("end")
        self.want_id("if")
        return ("if", arms, other)

    def inline_statements(self):
        out = []
        while self.peek()[0] not in ("nl", "eof") and not self.is_id("else") and not self.is_id("end"):
            if self.peek()[0] == "colon":
                self.next()
                continue
            out.append(self.statement())
        return out

    def select_stmt(self):
        self.want_id("select")
        self.want_id("case")
        subject = self.expr()
        arms, other = [], []
        while True:
            self.skip_seps()
            if not self.is_id("case"):
                break
            self.next()
            if self.is_id("else"):
                self.next()
                other = self.block()
                continue
            vals = [self.expr()]
            while self.is_op(","):
                self.next()
                vals.append(self.expr())
            arms.append((vals, self.block()))
        self.want_id("end")
        self.want_id("select")
        return ("select", subject, arms, other)

    def for_stmt(self):
        self.want_id("for")
        if self.is_id("each"):
            self.next()
            var = self.want_id()[1]
            self.want_id("in")
            seq = self.expr()
            body = self.block()
            self.want_id("next")
            if self.peek()[0] == "id" and self.peek()[1] == var:
                self.next()
            return ("foreach", var, seq, body)
        var = self.want_id()[1]
        self.want_op("=")
        start = self.expr()
        self.want_id("to")
        end = self.expr()
        step = ("lit", 1)
        if self.is_id("step"):
            self.next()
            step = self.expr()
        body = self.block()
        self.want_id("next")
        if self.peek()[0] == "id" and self.peek()[1] == var:
            self.next()
        return ("for", var, start, end, step, body)

    def do_stmt(self):
        self.want_id("do")
        pre_kind = pre = post_kind = post = None
        if self.is_id("while", "until"):
            pre_kind = self.next()[1]
            pre = self.expr()
        body = self.block()
        self.want_id("loop")
        if self.is_id("while", "until"):
            post_kind = self.next()[1]
            post = self.expr()
        return ("do", pre_kind, pre, post_kind, post, body)

    def func_stmt(self):
        is_sub = self.next()[1] == "sub"
        tok = self.want_id()
        params = []
        if self.is_op("("):
            self.next()
            while not self.is_op(")"):
                byval = False
                if self.is_id("byval", "byref"):
                    byval = self.next()[1] == "byval"
                pname = self.want_id()[1]
                if self.is_op("("):
                    self.next()
                    self.want_op(")")
                params.append((pname, byval))
                if self.is_op(","):
                    self.next()
            self.want_op(")")
        body = self.block()
        self.want_id("end")
        self.want_id("sub" if is_sub else "function")
        return ("func", tok[1], params, body, is_sub, tok[2])

    # ---- expressions ------------------------------------------------
    def args(self):
        self.want_op("(")
        out = []
        while not self.is_op(")"):
            if self.is_op(","):
                self.next()
                out.append(("lit", None))
                continue
            out.append(self.expr())
            if self.is_op(","):
                self.next()
        self.want_op(")")
        return out

    def _left(self, sub, words=(), ops=()):
        node = sub()
        while True:
            tok = self.peek()
            if tok[0] == "id" and tok[1] in words:
                op = tok[1]
            elif tok[0] == "op" and tok[1] in ops:
                op = tok[1]
            else:
                return node
            self.next()
            node = ("bin", op, node, sub())

    def expr(self):
        return self._left(self.e_eqv, words=("imp",))

    def e_eqv(self):
        return self._left(self.e_xor, words=("eqv",))

    def e_xor(self):
        return self._left(self.e_or, words=("xor",))

    def e_or(self):
        return self._left(self.e_and, words=("or",))

    def e_and(self):
        return self._left(self.e_not, words=("and",))

    def e_not(self):
        if self.is_id("not"):
            self.next()
            return ("un", "not", self.e_not())
        return self.e_cmp()

    def e_cmp(self):
        return self._left(self.e_cat, words=("is",), ops=("=", "<>", "<", ">", "<=", ">="))

    def e_cat(self):
        return self._left(self.e_add, ops=("&",))

    def e_add(self):
        return self._left(self.e_mod, ops=("+", "-"))

    def e_mod(self):
        return self._left(self.e_idiv, words=("mod",))

    def e_idiv(self):
        return self._left(self.e_mul, ops=("\\",))

    def e_mul(self):
        return self._left(self.e_unary, ops=("*", "/"))

    def e_unary(self):
        if self.is_op("-", "+"):
            op = self.next()[1]
            return ("un", op, self.e_unary())
        node = self.postfix()
        while self.is_op("^"):  # left-associative: 2 ^ 3 ^ 2 is 64
            self.next()
            node = ("bin", "^", node, self.e_exponent())
        return node

    def e_exponent(self):
        if self.is_op("-", "+"):
            op = self.next()[1]
            return ("un", op, self.e_exponent())
        return self.postfix()

    def postfix(self):
        tok = self.next()
        if tok[0] == "num" or tok[0] == "str":
            return ("lit", tok[1])
        if tok == ("op", "("):
            node = self.expr()
            self.want_op(")")
            return node
        if tok[0] != "id":
            raise VBSError(f"unexpected token in expression: {tok!r}")
        if tok[1] in _LITERALS and not self.is_op("("):
            return ("lit", _LITERALS[tok[1]])
        node = ("call", tok[1], self.args()) if self.is_op("(") else ("name", tok[1])
        while True:
            if self.is_op("."):
                self.next()
                member = self.want_id()[1]
                node = ("member", node, member, self.args() if self.is_op("(") else [])
            elif self.is_op("(") and node[0] in ("call", "member"):
                node = ("call", "__index__", [node] + self.args())  # a(0)(1)
            else:
                return node


def parse(src: str) -> list:
    return Parser(tokenize(src)).program()


# ---- values ---------------------------------------------------------------
def to_num(v):
    if v is None:
        return 0
    if v is True:
        return -1
    if v is False:
        return 0
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        s = v.strip()
        low = s.lower()
        try:
            if low.startswith("&h"):
                return int(low[2:].rstrip("&"), 16)
            if low.startswith("&o"):
                return int(low[2:].rstrip("&"), 8)
            return int(s)
        except ValueError:
            try:
                return float(s)
            except ValueError:
                raise VBSError(f"type mismatch: {v!r} is not numeric")
    raise VBSError(f"type mismatch: {type(v).__name__}")


def to_int(v):
    n = to_num(v)
    return int(round(n)) if isinstance(n, float) else n


def to_str(v):
    if v is None:
        return ""
    if v is True:
        return "True"
    if v is False:
        return "False"
    if isinstance(v, float):
        return str(int(v)) if v == int(v) else repr(v)
    if isinstance(v, list):
        raise VBSError("type mismatch: array used as string")
    return str(v)


def truthy(v):
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, str):
        return v.strip().lower() == "true" or (v.strip() not in ("", "false") and to_num(v) != 0)
    return to_num(v) != 0


def _split(s, d="\x20", limit=-1, *_):
    s, d = to_str(s), to_str(d)
    if s == "":
        return []
    lim = to_int(limit)
    return s.split(d, lim - 1) if lim > 0 else s.split(d)


def _mid(s, start, length=None):
    s, a = to_str(s), to_int(start) - 1
    if a < 0:
        raise VBSError("Mid: invalid start")
    return s[a:] if length is None else s[a:a + to_int(length)]


def _replace(s, find, repl, start=1, count=-1, *_):
    s, find, repl = to_str(s), to_str(find), to_str(repl)
    head = s[to_int(start) - 1:]
    return head.replace(find, repl, to_int(count)) if to_int(count) >= 0 else head.replace(find, repl)


def _instr(*a):
    if len(a) >= 3 or (a and isinstance(a[0], (int, float)) and not isinstance(a[0], bool) and len(a) > 2):
        start, s, sub = to_int(a[0]), to_str(a[1]), to_str(a[2])
    else:
        start, s, sub = 1, to_str(a[0]), to_str(a[1])
    return s.find(sub, start - 1) + 1


def _hex(v):
    n = to_int(v)
    return format(n & 0xFFFFFFFF if n < 0 else n, "X")


BUILTINS = {
    "split": _split,
    "join": lambda arr, d=" ": to_str(d).join(to_str(x) for x in arr),
    "ubound": lambda arr, *_: len(arr) - 1,
    "lbound": lambda arr, *_: 0,
    "array": lambda *a: list(a),
    "cint": to_int, "clng": to_int, "cbyte": to_int, "ccur": to_num, "csng": lambda v: float(to_num(v)),
    "cdbl": lambda v: float(to_num(v)), "cstr": to_str, "cbool": truthy,
    "int": lambda v: int(to_num(v) // 1), "fix": lambda v: int(to_num(v)), "abs": lambda v: abs(to_num(v)),
    "sgn": lambda v: (to_num(v) > 0) - (to_num(v) < 0), "round": lambda v, d=0: round(to_num(v), to_int(d)),
    "chr": lambda v: chr(to_int(v) & 0xFF), "chrw": lambda v: chr(to_int(v) & 0xFFFF), "chrb": lambda v: chr(to_int(v) & 0xFF),
    "asc": lambda s: ord(to_str(s)[0]), "ascw": lambda s: ord(to_str(s)[0]), "ascb": lambda s: ord(to_str(s)[0]) & 0xFF,
    "len": lambda v: len(v) if isinstance(v, list) else len(to_str(v)),
    "mid": _mid, "left": lambda s, n: to_str(s)[:to_int(n)],
    "right": lambda s, n: to_str(s)[len(to_str(s)) - to_int(n):] if to_int(n) > 0 else "",
    "strreverse": lambda s: to_str(s)[::-1], "replace": _replace,
    "lcase": lambda s: to_str(s).lower(), "ucase": lambda s: to_str(s).upper(),
    "trim": lambda s: to_str(s).strip(" "), "ltrim": lambda s: to_str(s).lstrip(" "), "rtrim": lambda s: to_str(s).rstrip(" "),
    "instr": _instr, "instrrev": lambda s, sub, *_: to_str(s).rfind(to_str(sub)) + 1,
    "hex": _hex, "oct": lambda v: format(to_int(v), "o"),
    "string": lambda n, c: (c if isinstance(c, str) else chr(to_int(c)))[:1] * to_int(n),
    "space": lambda n: " " * to_int(n),
    "isarray": lambda v: isinstance(v, list), "isempty": lambda v: v is None, "isnull": lambda v: False,
    "isnumeric": lambda v: isinstance(v, (int, float)) or bool(re.fullmatch(r"\s*[-+]?(\d+\.?\d*|\.\d+)\s*", to_str(v))),
    "isobject": lambda v: False, "typename": lambda v: type(v).__name__, "vartype": lambda v: 0,
    "strcomp": lambda a, b, *_: (to_str(a) > to_str(b)) - (to_str(a) < to_str(b)),
}


def _cmp(op, a, b):
    if isinstance(a, str) and isinstance(b, str):
        pass
    else:
        try:
            a, b = to_num(a), to_num(b)
        except VBSError:
            a, b = to_str(a), to_str(b)
    return {"=": a == b, "<>": a != b, "<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b, "is": a is b}[op]


def _logic(op, a, b):
    if isinstance(a, bool) and isinstance(b, bool):
        return {"and": a and b, "or": a or b, "xor": a != b, "eqv": a == b, "imp": (not a) or b}[op]
    x, y = to_int(a), to_int(b)
    return {"and": x & y, "or": x | y, "xor": x ^ y, "eqv": ~(x ^ y), "imp": (~x) | y}[op]


def _binop(op, a, b):
    if op == "&":
        return to_str(a) + to_str(b)
    if op == "+":
        if isinstance(a, str) and isinstance(b, str):
            return a + b
        return to_num(a) + to_num(b)
    if op == "-":
        return to_num(a) - to_num(b)
    if op == "*":
        return to_num(a) * to_num(b)
    if op == "/":
        if to_num(b) == 0:
            raise VBSError("division by zero")
        return to_num(a) / to_num(b)
    if op == "\\":
        x, y = to_int(a), to_int(b)
        if y == 0:
            raise VBSError("division by zero")
        q = abs(x) // abs(y)
        return q if (x < 0) == (y < 0) else -q
    if op == "mod":
        x, y = to_int(a), to_int(b)
        if y == 0:
            raise VBSError("division by zero")
        return abs(x) % abs(y) * (-1 if x < 0 else 1)
    if op == "^":
        return to_num(a) ** to_num(b)
    if op in ("=", "<>", "<", ">", "<=", ">=", "is"):
        return _cmp(op, a, b)
    return _logic(op, a, b)


class Interp:
    def __init__(self, program, max_steps=MAX_STEPS):
        self.funcs, self.globals, self.steps, self.max_steps = {}, {}, 0, max_steps
        self.load(program)

    def load(self, program):
        rest = []
        for st in program:
            if st[0] == "func":
                self.funcs[st[1]] = st
            else:
                rest.append(st)
        self.run(rest, self.globals, None)

    # ---- execution --------------------------------------------------
    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise VBSError("step budget exceeded")

    def run(self, block, env, fn):
        for st in block:
            self.exec(st, env, fn)

    def exec(self, st, env, fn):
        self.tick()
        k = st[0]
        if k == "assign":
            self.assign(st[1], self.ev(st[2], env, fn), env, fn)
        elif k == "const":
            env[st[1]] = self.ev(st[2], env, fn)
        elif k == "dim":
            for name in st[1]:
                if isinstance(name, tuple):
                    env[name[0]] = []
                else:
                    env.setdefault(name, None)
        elif k == "redim":
            size = to_int(self.ev(st[3][0], env, fn)) + 1
            old = self.lookup(st[2], env) if st[1] else None
            new = [None] * max(size, 0)
            if isinstance(old, list):
                new[:min(len(old), len(new))] = old[:len(new)]
            self.store(st[2], new, env)
        elif k == "if":
            for cond, body in st[1]:
                if truthy(self.ev(cond, env, fn)):
                    return self.run(body, env, fn)
            self.run(st[2], env, fn)
        elif k == "select":
            subject = self.ev(st[1], env, fn)
            for vals, body in st[2]:
                if any(_cmp("=", subject, self.ev(v, env, fn)) for v in vals):
                    return self.run(body, env, fn)
            self.run(st[3], env, fn)
        elif k == "for":
            i, end, step = (to_num(self.ev(x, env, fn)) for x in (st[2], st[3], st[4]))
            if step == 0:
                raise VBSError("For with Step 0")
            try:
                while (i <= end) if step > 0 else (i >= end):
                    self.store(st[1], i, env)
                    self.tick()
                    self.run(st[5], env, fn)
                    i = to_num(self.lookup(st[1], env)) + step
                self.store(st[1], i, env)
            except _Exit as e:
                if e.kind != "for":
                    raise
        elif k == "foreach":
            try:
                for item in list(self.ev(st[2], env, fn) or []):
                    self.store(st[1], item, env)
                    self.tick()
                    self.run(st[3], env, fn)
            except _Exit as e:
                if e.kind != "for":
                    raise
        elif k == "do":
            _, pre_kind, pre, post_kind, post, body = st
            try:
                while True:
                    self.tick()
                    if pre_kind and truthy(self.ev(pre, env, fn)) == (pre_kind == "until"):
                        break
                    self.run(body, env, fn)
                    if post_kind and truthy(self.ev(post, env, fn)) == (post_kind == "until"):
                        break
            except _Exit as e:
                if e.kind != "do":
                    raise
        elif k == "while":
            while truthy(self.ev(st[1], env, fn)):
                self.tick()
                self.run(st[2], env, fn)
        elif k == "exit":
            raise _Exit("function" if st[1] in ("function", "sub", "property") else st[1])
        elif k == "callstmt":
            self.ev(st[1], env, fn, statement=True)
        elif k == "execute":
            self.run_source(to_str(self.ev(st[1], env, fn)), env, fn)
        elif k in ("onerror", "func"):
            if k == "func":
                self.funcs[st[1]] = st
        else:
            raise VBSError(f"unsupported statement {k}")

    def run_source(self, text, env, fn):
        prog = parse(text)
        rest = []
        for st in prog:
            if st[0] == "func":
                self.funcs[st[1]] = st
            else:
                rest.append(st)
        self.run(rest, env, fn)

    def lookup(self, name, env):
        if name in env:
            return env[name]
        if name in self.globals:
            return self.globals[name]
        raise KeyError(name)

    def has(self, name, env):
        return name in env or name in self.globals

    def store(self, name, value, env):
        if name not in env and name in self.globals:
            self.globals[name] = value
        else:
            env[name] = value

    def assign(self, target, value, env, fn):
        if isinstance(value, list):
            value = list(value)  # VBScript arrays copy on assignment
        if target[0] == "name":
            return self.store(target[1], value, env)
        if target[0] == "call" and self.has(target[1], env):
            arr = self.lookup(target[1], env)
            if isinstance(arr, list):
                idx = to_int(self.ev(target[2][0], env, fn))
                if not 0 <= idx < len(arr):
                    raise VBSError("subscript out of range")
                arr[idx] = value
                return
        raise VBSError(f"cannot assign to {target!r}")

    # ---- expressions ------------------------------------------------
    def ev(self, node, env, fn, statement=False):
        k = node[0]
        if k == "lit":
            return node[1]
        if k == "name":
            name = node[1]
            if fn == name and name in env and not statement:
                return env[name]
            if self.has(name, env):
                return self.lookup(name, env)
            if name in self.funcs:
                return self.call(name, [], env, fn)
            if name in BUILTINS:
                return BUILTINS[name]()
            if name == "err":
                return 0
            if statement:
                raise VBSError(f"unknown procedure {name}")
            return None  # undeclared variable reads as Empty
        if k == "call":
            name, args = node[1], node[2]
            if name == "__index__":
                base = self.ev(args[0], env, fn)
                return base[to_int(self.ev(args[1], env, fn))]
            if name in self.funcs and not (self.has(name, env) and isinstance(self.lookup(name, env), list)):
                return self.call(name, args, env, fn)
            if self.has(name, env):
                arr = self.lookup(name, env)
                if isinstance(arr, list):
                    idx = to_int(self.ev(args[0], env, fn))
                    if not 0 <= idx < len(arr):
                        raise VBSError("subscript out of range")
                    return arr[idx]
                if isinstance(arr, str) and not args:
                    return arr
            if name == "eval":
                return self.ev(Parser(tokenize(to_str(self.ev(args[0], env, fn)))).expr(), env, fn)
            if name in BUILTINS:
                try:
                    return BUILTINS[name](*[self.ev(a, env, fn) for a in args])
                except (TypeError, IndexError, ValueError) as e:
                    raise VBSError(f"{name}: {e}")
            raise VBSError(f"unknown function {name}")
        if k == "member":
            base = node[1]
            if base[0] == "name" and base[1] == "err":
                if node[2] == "raise":
                    # The fixtures only reach Err.Raise on a failure path; on paper that is an error too.
                    raise VBSError("Err.Raise reached")
                return {"number": 0, "description": "", "source": ""}.get(node[2])
            raise VBSError(f"object access is not modelled: .{node[2]}")
        if k == "un":
            v = self.ev(node[2], env, fn)
            if node[1] == "not":
                return (not v) if isinstance(v, bool) else ~to_int(v)
            return -to_num(v) if node[1] == "-" else to_num(v)
        if k == "bin":
            # Left-deep chains (a & b & c ...) are walked in a loop, so a long one cannot exhaust the stack.
            spine = []
            while node[0] == "bin":
                spine.append(node)
                node = node[2]
            acc = self.ev(node, env, fn)
            while spine:
                n = spine.pop()
                acc = _binop(n[1], acc, self.ev(n[3], env, fn))
            return acc
        raise VBSError(f"unsupported expression {k}")

    def call(self, name, arg_nodes, env=None, fn=None):
        name = name.lower()
        env = self.globals if env is None else env
        f = self.funcs.get(name)
        if f is None:
            raise VBSError(f"unknown procedure {name}")
        _, _, params, body, is_sub, _ = f
        local = {}
        for i, (pname, byval) in enumerate(params):
            v = self.ev(arg_nodes[i], env, fn) if i < len(arg_nodes) else None
            local[pname] = list(v) if (byval and isinstance(v, list)) else v
        if not is_sub:
            local[name] = None
        try:
            self.run(body, local, name)
        except _Exit as e:
            if e.kind != "function":
                raise
        for i, (pname, byval) in enumerate(params):  # write ByRef parameters back
            if not byval and i < len(arg_nodes) and arg_nodes[i][0] == "name":
                self.store(arg_nodes[i][1], local[pname], env)
        return None if is_sub else local[name]
