#!/usr/bin/env python3
"""B-247 (Script lane residuals, S4): the values a modern JavaScript specimen computes at its top level, followed
statically by js_interp's side-effect-free interpreter. Nothing is run in a script host.

js_interp.py reads the ES3 subset the JScript fixtures use. A modern specimen writes the same computation with
`const`/`let`, arrow functions, template literals and a spread call:

    const descriptor_x = [118, 61, ...].map(c => String.fromCharCode(c ^ 7)).join("");
    const d = `${head}${tail}`;
    const s = String.fromCharCode(...codes);

desugar() rewrites exactly those forms into the ES3 the interpreter parses (`var`; `function (c) { return ..; }`;
`("" + (head) + "" + (tail) + "")`; `f.apply(null, codes)`), and _Modern adds the pure builtins such code calls:
`atob`, `btoa`, `Buffer.from(x, enc).toString(enc)`, `Array.from`, `String.fromCodePoint`, the array methods
`map`, `filter`, `forEach`, `reduce`, `some`, `every`, `includes`, and the string methods `repeat`, `padStart`,
`padEnd`, `trim`, `codePointAt`, `startsWith`, `endsWith`, `includes`. Anything else (I/O, `require`, a host
object, `eval`) is outside the subset and raises js_interp.JSError.

values(text) runs the top-level statements in order, each on its own, and returns the string value of every
top-level variable that is TRUSTED, with the names of the others:

  a statement that raises (it needs something outside the subset) did not do what it would have done. A string
  is immutable, so a variable's value is set by the statements up to its last assignment. It is trusted only
  when no failed statement assigns to it, and no failed statement up to that last assignment mentions a name
  joined to it there (through any statement in that window that mentions both; a function declaration mentions
  what its body mentions, wherever it stands): whatever such a statement would have done (a splice through an
  alias, a write in a helper) cannot be known. A failed statement after the value is final (`WScript.Echo(d)`)
  costs nothing.

The interpreter is bounded (MAX_STEPS operations for the whole file, MAX_SOURCE characters of source), so a
loop in a specimen costs a fixed amount. Nothing here decides a plan: residuals.js_witnesses() decodes the values
and weighs them against the file's other copies.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import js_interp as js  # noqa: E402

MAX_SOURCE = 256 << 10      # characters of source followed; a larger file is not read
MAX_STEPS = 400_000         # interpreter operations for one file
MAX_VALUE = 1 << 20         # characters of one computed string kept
JS_EXTS = frozenset(("js", "mjs", "cjs", "jsx"))


class Unsupported(Exception):
    """The source uses a modern form desugar() does not rewrite."""


# ------------------------------------------------------------------------------------------------ desugaring

_WORD = re.compile(r"[A-Za-z_$][\w$]*")
_TEMPLATE_ESC = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0", "`": "`",
                 "$": "$", "\\": "\\", "'": "'", '"': '"', "{": "{", "}": "}"}


def _cooked(raw: str) -> str:
    """A template literal's text with its escapes undone (the subset a fixture writes)."""
    out, i = [], 0
    while i < len(raw):
        c = raw[i]
        if c != "\\" or i + 1 >= len(raw):
            out.append(c)
            i += 1
            continue
        n = raw[i + 1]
        if n == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", raw[i + 2:i + 4]):
            out.append(chr(int(raw[i + 2:i + 4], 16)))
            i += 4
        elif n == "u" and re.fullmatch(r"[0-9A-Fa-f]{4}", raw[i + 2:i + 6]):
            out.append(chr(int(raw[i + 2:i + 6], 16)))
            i += 6
        elif n == "\n":
            i += 2                                  # a line continuation
        else:
            out.append(_TEMPLATE_ESC.get(n, n))
            i += 2
    return "".join(out)


class _Desugar:
    """One pass over the source: strings and comments are copied, the modern forms rewritten."""

    def __init__(self, src: str):
        self.s, self.i = src, 0

    def run(self, stop: str | None = None) -> str:
        """Rewrite until the unmatched closer `stop` (not consumed) or the end."""
        s, out, depth = self.s, [], 0
        while self.i < len(s):
            c = s[self.i]
            if stop is not None and depth == 0 and c == stop:
                break
            if c in "\"'":
                out.append(self._string(c))
                continue
            if c == "`":
                out.append(self._template())
                continue
            if s.startswith("//", self.i):
                j = s.find("\n", self.i)
                j = len(s) if j < 0 else j
                out.append(" " * (j - self.i))
                self.i = j
                continue
            if s.startswith("/*", self.i):
                j = s.find("*/", self.i + 2)
                if j < 0:
                    raise Unsupported("an unclosed block comment")
                out.append(" " * (j + 2 - self.i))
                self.i = j + 2
                continue
            if s.startswith("...", self.i):
                raise Unsupported("a spread outside a one-argument call")
            if c in "([{":
                if c == "(" and self._spread_call(out):
                    continue
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == "=" and s.startswith("=>", self.i):
                out = self._arrow(out)
                continue
            m = _WORD.match(s, self.i) if (c.isalpha() or c in "_$") else None
            if m is not None and (self.i == 0 or not (s[self.i - 1].isalnum() or s[self.i - 1] in "_$.")):
                w = m.group()
                out.append("var" if w in ("const", "let") else w)
                self.i = m.end()
                continue
            out.append(c)
            self.i += 1
        return "".join(out)

    def _string(self, q: str) -> str:
        s, j = self.s, self.i + 1
        while j < len(s) and s[j] != q:
            if s[j] == "\\":
                j += 1
            elif s[j] == "\n":
                raise Unsupported("a string literal runs past its line")
            j += 1
        if j >= len(s):
            raise Unsupported("an unclosed string literal")
        lit = s[self.i:j + 1]
        self.i = j + 1
        return lit

    def _template(self) -> str:
        s, parts, buf = self.s, [], []
        self.i += 1
        while True:
            if self.i >= len(s):
                raise Unsupported("an unclosed template literal")
            c = s[self.i]
            if c == "\\":
                buf.append(s[self.i:self.i + 2])
                self.i += 2
                continue
            if c == "`":
                self.i += 1
                break
            if s.startswith("${", self.i):
                parts.append(json.dumps(_cooked("".join(buf))))
                buf = []
                self.i += 2
                inner = self.run("}")
                if self.i >= len(s) or s[self.i] != "}":
                    raise Unsupported("an unclosed template substitution")
                self.i += 1
                parts.append("(" + inner + ")")
                continue
            buf.append(c)
            self.i += 1
        parts.append(json.dumps(_cooked("".join(buf))))
        return "(" + " + ".join(['""'] + parts) + ")"

    def _spread_call(self, out: list) -> bool:
        """`f(...x)` as `f.apply(null, x)`, when the call's one argument is the spread and `f` is a callee."""
        s = self.s
        k = self.i + 1
        while k < len(s) and s[k] in " \t\r\n":
            k += 1
        if not s.startswith("...", k):
            return False
        prev = "".join(out).rstrip()
        if not prev or not (prev[-1].isalnum() or prev[-1] in "_$)]"):
            raise Unsupported("a spread outside a one-argument call")
        self.i = k + 3
        arg = self.run(")")
        if self.i >= len(s) or s[self.i] != ")" or "," in _top_level_commas(arg):
            raise Unsupported("a spread with other arguments")
        self.i += 1
        out.append(".apply(null, " + arg + ")")
        return True

    def _arrow(self, out: list) -> list:
        """`params => body` as `(function (params) { return body; })` or `(function (params) { body })`."""
        text = "".join(out)
        t = text.rstrip()
        if t.endswith(")"):
            depth, j = 0, len(t) - 1
            while j >= 0:
                if t[j] == ")":
                    depth += 1
                elif t[j] == "(":
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            if j < 0:
                raise Unsupported("an arrow function's parameters do not open")
            params, head = t[j + 1:-1], t[:j]
        else:
            m = re.search(r"[A-Za-z_$][\w$]*$", t)
            if m is None:
                raise Unsupported("an arrow function without parameters")
            params, head = m.group(), t[:m.start()]
        if params.strip() and not re.fullmatch(r"\s*[A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*\s*", params):
            raise Unsupported("an arrow function with destructured or default parameters")
        self.i += 2
        s = self.s
        while self.i < len(s) and s[self.i] in " \t\r\n":
            self.i += 1
        if self.i < len(s) and s[self.i] == "{":
            self.i += 1
            body = self.run("}")
            if self.i >= len(s):
                raise Unsupported("an unclosed arrow function body")
            self.i += 1
            fn = f"(function ({params}) {{{body}}})"
        else:
            body = self._expression()
            fn = f"(function ({params}) {{ return {body}; }})"
        return [head, fn]

    def _expression(self) -> str:
        """An arrow function's expression body: to a depth-0 `,` `;` or closer, or a line end with nothing open."""
        s, start_out, depth = self.s, [], 0
        while self.i < len(s):
            c = s[self.i]
            if depth == 0 and (c in ",;)]}" or c == "\n"):
                break
            if c in "\"'":
                start_out.append(self._string(c))
                continue
            if c == "`":
                start_out.append(self._template())
                continue
            if c in "([{":
                start_out.append(c)
                self.i += 1
                start_out.append(self.run({"(": ")", "[": "]", "{": "}"}[c]))
                if self.i < len(s):
                    start_out.append(s[self.i])
                    self.i += 1
                continue
            if c == "=" and s.startswith("=>", self.i):
                start_out = self._arrow(start_out)
                continue
            m = _WORD.match(s, self.i) if (c.isalpha() or c in "_$") else None
            if m is not None:
                start_out.append(m.group())
                self.i = m.end()
                continue
            start_out.append(c)
            self.i += 1
        return "".join(start_out)


def _top_level_commas(src: str) -> str:
    depth, out = 0, []
    for c in src:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(c)
    return "".join(out)


def desugar(src: str) -> str:
    """The source with its modern forms written as ES3 (see the module docstring). Raises Unsupported."""
    return _Desugar(src).run()


# ------------------------------------------------------------------------------------------------ the interpreter

class _Buf(js.JSArray):
    """A Buffer: its byte values, read with toString(encoding)."""


def _bytes_of(value, enc) -> bytes:
    enc = (js.to_str(enc) if enc is not js.UNDEF else "utf8").lower().replace("-", "")
    if isinstance(value, list):
        return bytes(js.to_int(x) & 255 for x in value)
    text = js.to_str(value)
    if enc == "base64" or enc == "base64url":
        t = text.replace("-", "+").replace("_", "/")
        try:
            return base64.b64decode(t + "=" * (-len(t) % 4))
        except (binascii.Error, ValueError) as e:
            raise js.JSError(f"Buffer.from: not base64 ({e})") from None
    if enc == "hex":
        try:
            return bytes.fromhex(text[:len(text) - len(text) % 2])
        except ValueError as e:
            raise js.JSError(f"Buffer.from: not hex ({e})") from None
    if enc in ("latin1", "binary", "ascii"):
        return text.encode("latin-1", "replace")
    if enc in ("utf8", "utf16le", "ucs2"):
        return text.encode("utf-8" if enc == "utf8" else "utf-16-le")
    raise js.JSError(f"Buffer.from: encoding {enc!r} is outside the subset")


def _buf_text(buf, enc) -> str:
    raw = bytes(js.to_int(x) & 255 for x in buf)
    enc = (js.to_str(enc) if enc is not js.UNDEF else "utf8").lower().replace("-", "")
    if enc == "hex":
        return raw.hex()
    if enc == "base64":
        return base64.b64encode(raw).decode()
    if enc in ("latin1", "binary"):
        return raw.decode("latin-1")
    if enc == "ascii":
        return bytes(b & 127 for b in raw).decode("ascii")
    if enc == "utf8":
        return raw.decode("utf-8", "replace")
    if enc in ("utf16le", "ucs2"):
        return raw.decode("utf-16-le", "replace")
    raise js.JSError(f"Buffer.toString: encoding {enc!r} is outside the subset")


def _atob(a):
    t = js.to_str(js._idx(a, 0, ""))
    try:
        return base64.b64decode(re.sub(r"\s+", "", t) + "=" * (-len(re.sub(r"\s+", "", t)) % 4),
                                validate=True).decode("latin-1")
    except (binascii.Error, ValueError) as e:
        raise js.JSError(f"atob: not base64 ({e})") from None


def _btoa(a):
    t = js.to_str(js._idx(a, 0, ""))
    try:
        return base64.b64encode(t.encode("latin-1")).decode()
    except UnicodeEncodeError:
        raise js.JSError("btoa: a character outside Latin-1") from None


class _Modern(js.Interp):
    MAX_STEPS = MAX_STEPS

    def __init__(self):
        super().__init__()
        g = self.globals.vars
        N = js.Native
        g["atob"] = N(lambda this, a: _atob(a))
        g["btoa"] = N(lambda this, a: _btoa(a))
        g["Buffer"] = js.JSObject({"from": N(lambda this, a: _Buf(_bytes_of(js._idx(a, 0, ""), js._idx(a, 1))))})
        g["String"].props["fromCodePoint"] = N(lambda this, a: "".join(chr(js.to_int(x)) for x in a))
        g["Array"].props["from"] = N(lambda this, a: self._array_from(a))
        g["Array"].props["isArray"] = N(lambda this, a: isinstance(js._idx(a, 0), list))

    def _array_from(self, a):
        src = js._idx(a, 0)
        items = list(src) if isinstance(src, (str, list)) else []
        fn = js._idx(a, 1)
        if isinstance(fn, (js.JSFunction, js.Native)):
            items = [self.call(fn, js.UNDEF, [x, i]) for i, x in enumerate(items)]
        return js.JSArray(items)

    def _each(self, arr, fn):
        if not isinstance(fn, (js.JSFunction, js.Native)):
            raise js.JSError("an array method without a function")
        for i, x in enumerate(list(arr)):
            yield x, self.call(fn, js.UNDEF, [x, i, arr])

    def get(self, obj, key):
        if isinstance(obj, _Buf):
            if key == "toString":
                return js.Native(lambda this, a: _buf_text(this, js._idx(a, 0)))
            if key == "length":
                return len(obj)
        if isinstance(obj, list):
            N = js.Native
            if key == "map":
                return N(lambda this, a: js.JSArray(r for _, r in self._each(this, js._idx(a, 0))))
            if key == "filter":
                return N(lambda this, a: js.JSArray(x for x, r in self._each(this, js._idx(a, 0)) if js.truthy(r)))
            if key == "forEach":
                return N(lambda this, a: (list(self._each(this, js._idx(a, 0))), js.UNDEF)[1])
            if key == "some":
                return N(lambda this, a: any(js.truthy(r) for _, r in self._each(this, js._idx(a, 0))))
            if key == "every":
                return N(lambda this, a: all(js.truthy(r) for _, r in self._each(this, js._idx(a, 0))))
            if key == "includes":
                return N(lambda this, a: any(js.strict_eq(x, js._idx(a, 0)) for x in this))
            if key == "reduce":
                return N(lambda this, a: self._reduce(this, a))
        if isinstance(obj, str):
            N = js.Native
            if key == "repeat":
                return N(lambda this, a: this * max(0, min(js.to_int(js._idx(a, 0, 0)), MAX_VALUE // max(1, len(this)))))
            if key in ("padStart", "padEnd"):
                return N(lambda this, a, k=key: self._pad(this, a, k == "padStart"))
            if key == "trim":
                return N(lambda this, a: this.strip())
            if key == "codePointAt":
                return N(lambda this, a: ord(this[js.to_int(js._idx(a, 0, 0))]) if 0 <= js.to_int(js._idx(a, 0, 0)) < len(this) else js.UNDEF)
            if key == "startsWith":
                return N(lambda this, a: this.startswith(js.to_str(js._idx(a, 0, ""))))
            if key == "endsWith":
                return N(lambda this, a: this.endswith(js.to_str(js._idx(a, 0, ""))))
            if key == "includes":
                return N(lambda this, a: js.to_str(js._idx(a, 0, "")) in this)
        return super().get(obj, key)

    def _reduce(self, arr, a):
        fn = js._idx(a, 0)
        if not isinstance(fn, (js.JSFunction, js.Native)):
            raise js.JSError("reduce without a function")
        items = list(arr)
        if len(a) > 1:
            acc = a[1]
        elif items:
            acc = items.pop(0)
        else:
            raise js.JSError("reduce of an empty array with no initial value")
        for i, x in enumerate(items):
            acc = self.call(fn, js.UNDEF, [acc, x, i, arr])
        return acc

    @staticmethod
    def _pad(s, a, start):
        n = js.to_int(js._idx(a, 0, 0))
        fill = js.to_str(js._idx(a, 1, " ")) if js._idx(a, 1) is not js.UNDEF else " "
        if n <= len(s) or not fill:
            return s
        pad = (fill * ((n - len(s)) // len(fill) + 1))[:n - len(s)]
        return pad + s if start else s + pad


# ------------------------------------------------------------------------------------------------ values

def _ids(node) -> set:
    return {n[1] for n in js.walk(node) if n[0] == "id"}


def _declared(stmt) -> set:
    if stmt[0] == "var":
        return {name for name, _ in stmt[1]}
    if stmt[0] == "funcdecl":
        return {stmt[1]}
    return set()


class Computed:
    """What values() found: `strings` {name: value} of trusted top-level variables, `untrusted` names, `failed`
    the number of top-level statements that raised, `why` when nothing could be followed at all."""

    def __init__(self, strings=None, untrusted=(), failed=0, why=None):
        self.strings = dict(strings or {})
        self.untrusted = set(untrusted)
        self.failed = failed
        self.why = why


def values(text: str) -> Computed:
    """The string values of the top-level variables a JavaScript source computes (see the module docstring)."""
    if len(text) > MAX_SOURCE:
        return Computed(why=f"more than {MAX_SOURCE} characters: not followed")
    try:
        program = js.parse(desugar(text))
    except (Unsupported, js.JSError, RecursionError, IndexError, ValueError) as e:
        return Computed(why=f"outside the followed subset ({type(e).__name__}: {str(e)[:80]})")
    interp = _Modern()
    scope = interp.globals
    interp._hoist(program, scope)
    mentions, assigns, failed_at, failed = [], [], [], 0
    for stmt in program:
        ids = _ids(stmt) | _declared(stmt)
        mentions.append(ids)
        assigns.append(_assigned(stmt))
        if stmt[0] == "funcdecl":
            continue
        try:
            interp.exec(stmt, scope)
        except (js.JSError, js.JSThrow, RecursionError, ZeroDivisionError, OverflowError, ValueError,
                TypeError, IndexError, KeyError, AttributeError):
            failed += 1
            failed_at.append(len(mentions) - 1)
            for name in _declared(stmt):
                scope.vars.setdefault(name, js.UNDEF)
            if interp.steps > interp.MAX_STEPS:
                return Computed(why="the step bound was reached: nothing is trusted", failed=failed)
    names = {n for n, v in scope.vars.items() if isinstance(v, str) and len(v) <= MAX_VALUE}
    declared = set().union(*(_declared(s) for s in program)) if program else set()
    funcs = [i for i, s in enumerate(program) if s[0] == "funcdecl"]
    strings, untrusted = {}, set()
    for name in sorted(names & declared):
        last = max(i for i, a in enumerate(assigns) if name in a)
        # A string is immutable: after its last assignment nothing changes it. Up to it, every statement joined
        # to it through a name it shares (function bodies wherever they stand) may have shaped its value.
        window = [i for i in range(last + 1)] + [i for i in funcs if i > last]
        group, grew = {name}, True
        while grew:
            grew = False
            for i in window:
                if mentions[i] & group and not mentions[i] <= group:
                    group |= mentions[i]
                    grew = True
        if any((f <= last and mentions[f] & group) or name in assigns[f] for f in failed_at):
            untrusted.add(name)
        else:
            strings[name] = scope.vars[name]
    return Computed(strings, untrusted, failed)


def _assigned(stmt) -> set:
    """The names a statement declares or assigns to (`x = ..`, `x += ..`, `x++`), at any depth."""
    out = set(_declared(stmt))
    for n in js.walk(stmt):
        if n[0] == "var":
            out |= {name for name, _ in n[1]}
        elif n[0] == "assign" and js.unparen(n[2])[0] == "id":
            out.add(js.unparen(n[2])[1])
        elif n[0] == "update" and js.unparen(n[3])[0] == "id":
            out.add(js.unparen(n[3])[1])
    return out


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: js_modern.py <file.js> [...]   (prints the string values its top level computes)", file=sys.stderr)
        return 2
    status = 0
    for arg in argv:
        try:
            text = Path(arg).read_text("utf-8", "replace")
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})", file=sys.stderr)
            status = 1
            continue
        got = values(text)
        if got.why:
            print(f"{arg}: {got.why}")
        for name, value in got.strings.items():
            print(f"{arg}: {name} = {ascii(value)[:200]}")
        for name in sorted(got.untrusted):
            print(f"{arg}: {name} not trusted (a statement it is joined to could not be followed)")
    return status


if __name__ == "__main__":
    sys.exit(main())
