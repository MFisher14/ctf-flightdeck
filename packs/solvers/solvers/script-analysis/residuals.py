#!/usr/bin/env python3
"""B-247: the Script lane's residual readers, behind the plan grammar and the two-copy gate.

Usage:
  python3 solvers/script-analysis/residuals.py <specimen> [...]    print the copies each file's residual readers see

generic.read asks apply(info) after its own readers (plan_codec, the descriptor, descriptor_whole, blind_reader).
The shapes those readers leave unread or misread are read here, each the same way: every copy found is decoded
to a plan by the grammar alone (descriptor._is_plan_bytes), and all copies of the file must give ONE plan.

  key        the exact key HUNTRESS_DESCRIPTOR outside a Dockerfile too (backlog rows 462, 542): a YAML key
             (quoted, plain or a `|`/`>` block scalar; GitHub Actions `jobs.<id>.env`), a JSON key, a Dockerfile
             `ENV`/`ARG` (`K=V`, several pairs on one line, the old `ENV K V`), HCL and TOML (`K = "v"`, an HCL
             heredoc `<<EOT`), `.env`/shell `K=V`. Upper case only and not part of a longer name; `$K` and `${K}`
             are uses, not copies.
  comment    a `HUNTRESS_ANALYSIS_V<n>:<TAG>-<payload>` comment, decoded as descriptor.py decodes it.
  wrapped    a tagged comment wrapped over several comment lines (day12-readiness section 10): the payload's next
             lines with the same comment leader (or inside the same block comment), each one run of printable
             characters, joined. Only when the first line alone gives no plan. Its end is where its comment
             lines end, which nothing proves: alone it is ONE copy and its plan is taken without its last field,
             that field asked unsure (generic.one_copy, one_copy_wrapped).
  deep       a value no reader decodes, peeled through text layers (base64 either alphabet, hex, base32,
             ASCII85, zlib/gzip/raw deflate) to depth MAX_PEEL, with descriptor.decode's own free search at the
             first layers, and a repeating XOR whose key the plan's first field fixes (`v=<n>|<key>=` for
             every key a known version holds, so a key up to that crib's length) or a short literal of the file
             holds (any length): untagged depth and long XOR parity (coverage matrix S3). Asked of a tagged
             comment, a `descriptor_<id>` literal and an exact-key value whose own decode gives nothing.
  bat        a batch file's (.bat .cmd .btm) `set "descriptor_<id>=<payload>"` or `set descriptor_<id>=<payload>`,
             which descriptor.py's literal (a quote after the `=`) does not see: a Day 8 `.bat` whose `set` gives
             another plan than its tagged comment was answered from the comment. Whole when the value is bare text
             and the name is set once.
  js         the string values a modern JavaScript specimen computes at its top level (js_modern.values: arrow
             functions, template literals, spread calls, atob/Buffer; coverage matrix S4). A value that is a
             proper piece of another computed value is no whole copy.

The gate, the same for every kind (apply):

  agreement  two copies that give different plans leave none (the file holds two plans). A copy that gives
             another plan than the one generic.read settled withdraws that plan too: a Day 21 `.yml` or Day 27
             Dockerfile whose exact key disagrees with its tagged comment is refused, not answered from the
             comment (the `ENV A=1 HUNTRESS_DESCRIPTOR=<other> C=2` shape was answered from the comment alone).
  lift       only while the plan is open (none, cut, or one copy), or when the descriptor refused the file for
             a tagged comment it could not decode and this reader decodes it (blind_reader must then not read
             another plan). The plan must hold every field already read, with the same value, and every field
             of its version (descriptor.checked). Whole when a whole copy stands with another copy or is a
             bounded value (a quoted key, a block scalar, a heredoc, a computed value, a whole literal); a
             wrapped comment alone is one copy.

multi_host(info, name) is the bounded multi-host traversal (coverage matrix S2): a base64 script host whose
decoded script is itself such a host, to MAX_HOSTS levels (generic.encoded_host reads one), each level holding
exactly one encoded script and nothing beside it (generic._region_alone), the innermost script proving its plan
by two agreeing copies as generic.encoded_host requires.

Bounds: MAX_TEXT characters of a file, MAX_VALUES values decoded per file (more and nothing is lifted: an unread
value could be a second plan), MAX_PEEL layers, MAX_STATES alternatives per layer, MAX_OUT bytes per layer output,
MAX_KEYS in-file XOR keys, MAX_WRAP continuation lines. Nothing is executed.
"""
from __future__ import annotations

import base64
import binascii
import re
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import plan_codec  # noqa: E402

MAX_TEXT = 1 << 21
MAX_VALUES = 24
MAX_PEEL = 6
MAX_STATES = 48
MAX_OUT = 1 << 20
MAX_KEYS = 32
MAX_WRAP = 64
MAX_HOSTS = 3
MAX_DEEP_DECODES = 6         # descriptor.decode free searches asked inside one deep peel
MIN_VALUE = 16               # characters: a shorter key value or literal is no copy
KEY = "HUNTRESS_DESCRIPTOR"
COMMENT_UNREAD = "a tagged comment whose payload does not decode whole to one plan"


class MissingModule(RuntimeError):
    """An in-tree module this reader needs did not load."""

    def __init__(self, module: str):
        super().__init__(f"{module}.py (solvers/script-analysis) did not load: the residual readers cannot decode")
        self.module = module


def _desc():
    d = plan_codec.optional("descriptor")
    if d is None or not hasattr(d, "decode"):
        raise MissingModule("descriptor")
    return d


@dataclass
class Witness:
    plan_text: str
    kind: str                  # key, comment, wrapped, deep-comment, deep-literal, deep-key, js
    whole: bool
    how: str
    at: int = 0
    name: str = ""


@dataclass
class Reading:
    witnesses: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    over: bool = False         # more values than MAX_VALUES: nothing may be lifted

    def plans(self) -> list:
        out = []
        for w in self.witnesses:
            if w.plan_text not in out:
                out.append(w.plan_text)
        return out


# ------------------------------------------------------------------------------------------------ decoding

def complete(plan_text: str) -> bool:
    """A plan whose version's fields are all there and whose counts agree (descriptor.checked)."""
    d = _desc()
    try:
        return not d.checked(plan_codec.flatten(plan_text), short_ok=False)
    except Exception:  # noqa: BLE001 - a plan the check cannot read is no complete plan
        return False


def _b64(data: bytes):
    t = re.sub(rb"\s+", b"", data)
    if len(t) < 8 or not re.fullmatch(rb"[A-Za-z0-9+/_-]+={0,2}", t):
        return None
    t = t.replace(b"-", b"+").replace(b"_", b"/")
    try:
        return base64.b64decode(t + b"=" * (-len(t.rstrip(b"=")) % 4) if not t.endswith(b"=") else t, validate=True)
    except (binascii.Error, ValueError):
        return None


def _hex(data: bytes):
    t = re.sub(rb"\s+|0x|\\x|[:,.-]", b"", data)
    if len(t) < 8 or len(t) % 2 or not re.fullmatch(rb"[0-9A-Fa-f]+", t):
        return None
    return bytes.fromhex(t.decode())


def _b32(data: bytes):
    t = re.sub(rb"\s+", b"", data).upper()
    if len(t) < 8 or not re.fullmatch(rb"[A-Z2-7]+=*", t):
        return None
    try:
        return base64.b32decode(t + b"=" * (-len(t) % 8) if not t.endswith(b"=") else t)
    except (binascii.Error, ValueError):
        return None


def _a85(data: bytes):
    t = data.strip()
    if len(t) < 10 or not re.fullmatch(rb"(?:<~)?[!-uz\s]+(?:~>)?", t):
        return None
    try:
        return base64.a85decode(t, adobe=t.startswith(b"<~"), ignorechars=b" \t\r\n")
    except (binascii.Error, ValueError):
        return None


def _inflate(data: bytes):
    for wbits in (15, 31, -15):
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(data, MAX_OUT + 1)
        except zlib.error:
            continue
        if d.eof and not d.unused_data and len(out) <= MAX_OUT:
            return out
    return None


LAYERS = (("b64", _b64), ("hex", _hex), ("b32", _b32), ("a85", _a85), ("inflate", _inflate))


def _xor(data: bytes, key: bytes) -> bytes:
    n = len(data)
    stream = (key * (n // len(key) + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(n, "big")


def _cribs() -> list:
    """`v=<n>|<key>=` for every version 1..9 and every key a known version holds: the bytes a plan opens with."""
    d = _desc()
    keys = []
    for fields in getattr(d, "PLAN_KEYS", {}).values():
        keys.extend(k for k in fields if k != "v" and k not in keys)
    if "steps" not in keys:
        keys.append("steps")
    return [b"v=%d|%s=" % (n, k.encode()) for n in range(1, 10) for k in keys]


def xor_plans(data: bytes, keys=()) -> list:
    """[(plan text, how)] a repeating XOR gives: a key the crib fixes (its period proven by two crib bytes or
    more), or a key the file holds (`keys`, any length)."""
    d = _desc()
    out = {}
    n = len(data)
    if n < 16:
        return []
    for crib in _cribs():
        m = len(crib)
        if n < m:
            continue
        x = (int.from_bytes(data[:m], "big") ^ int.from_bytes(crib, "big")).to_bytes(m, "big")
        for L in range(1, m - 1):
            if x[L:] == x[:m - L]:
                t = d._is_plan_bytes(_xor(data, x[:L]))
                if t:
                    out.setdefault(t, f"xor_crib_{x[:L].hex()}")
                break
    for k in keys:
        if not k or len(k) >= n:
            continue
        t = d._is_plan_bytes(_xor(data, k))
        if t:
            out.setdefault(t, f"xor_key_{k.hex()}")
    return list(out.items())


def deep_plans(value: str, keys=()) -> list:
    """[(plan text, how)] for a value peeled through LAYERS to MAX_PEEL (see the module docstring)."""
    d = _desc()
    try:
        start = value.encode("latin-1")
    except UnicodeEncodeError:
        return []
    found, seen, frontier, asked = {}, {start}, [(start, ())], 0
    for depth in range(MAX_PEEL + 1):
        nxt = []
        for data, chain in frontier:
            if depth:
                t = d._is_plan_bytes(data)
                if t:
                    found.setdefault(t, "deep:" + "+".join(chain) + "|identity")
                    continue
                for t, how in xor_plans(data, keys):
                    found.setdefault(t, "deep:" + "+".join(chain) + "|" + how)
                if 1 <= depth <= 3 and asked < MAX_DEEP_DECODES and len(data) >= 24:
                    try:
                        text = data.decode("ascii")
                    except UnicodeDecodeError:
                        text = None
                    if text is not None and text.isprintable():
                        asked += 1
                        for row in d.decode(None, text):
                            found.setdefault(row[0], "deep:" + "+".join(chain) + "+" + str(row[1]))
            if depth == MAX_PEEL:
                continue
            for name, fn in LAYERS:
                try:
                    out = fn(data)
                except Exception:  # noqa: BLE001 - a layer that breaks on these bytes is not their layer
                    out = None
                if out and len(out) <= MAX_OUT and out not in seen:
                    seen.add(out)
                    nxt.append((out, chain + (name,)))
        frontier = nxt[:MAX_STATES]
        if not frontier:
            break
    return list(found.items())


_TAG = re.compile(r"(?P<tag>[A-Z][A-Z0-9_+>]{0,31})-(?P<payload>\S{8,})")


class _Budget:
    def __init__(self):
        self.n, self.over, self.memo = 0, False, {}


def _plans(value: str, budget: _Budget, keys=(), deep_ok=True):
    """([(plan text, how)], deep?) for one value: its tag's chain or descriptor's free search, else the deep peel."""
    memo_key = (value, deep_ok)
    if memo_key in budget.memo:
        return budget.memo[memo_key]
    if budget.n >= MAX_VALUES:
        budget.over = True
        return [], False
    budget.n += 1
    d = _desc()
    got, deep = [], False
    m = _TAG.fullmatch(value)
    try:
        if m and m.group("tag") == "LYR":
            lyr = plan_codec.optional("plan_layers")
            labels, _, rest = m.group("payload").partition("-")
            if lyr is not None and rest:
                got = [(t, "lyr:" + "+".join(chain)) for t, chain in lyr.decode_plans(labels, rest)]
        elif m:
            got = [(r[0], r[1]) for r in d.decode(m.group("tag"), m.group("payload"))]
        if not got:
            got = [(r[0], r[1]) for r in d.decode(None, value)]
        if not got and deep_ok:
            got = deep_plans(m.group("payload") if m else value, keys)
            if not got and m:
                got = deep_plans(value, keys)
            deep = bool(got)
    except RuntimeError:
        raise
    except Exception:  # noqa: BLE001 - a value that breaks a decoder is no reading
        got = []
    seen = []
    for t, how in got:
        if t not in [s[0] for s in seen]:
            seen.append((t, how))
    budget.memo[memo_key] = (seen, deep)
    return seen, deep


# ------------------------------------------------------------------------------------------------ the exact key

_KEY_AT = re.compile(r"(?<![\w$.{-])" + KEY + r"(?![\w-])")
_DQ = re.compile(r'"((?:[^"\\\r\n]|\\(?:\r?\n|.))*)"')
_SQ = re.compile(r"'((?:[^'\r\n]|'')*)'")
_POST_OK = re.compile(r"[ \t]*[,;}\]]*[ \t]*(?:(?:#|//)[^\r\n]*)?\r?$")
_PAIRS = re.compile(r"(?:[ \t]+[A-Za-z_][\w.-]*=(?:\"(?:[^\"\\\r\n]|\\.)*\"|'[^'\r\n]*'|\S*))*[ \t]*\r?$")
# A JSON or YAML flow mapping's next member behind a quoted value (`"K": "<v>", "X": 1`): the value stands whole.
_NEXT_MEMBER = re.compile(r"[ \t]*,[ \t]*(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[A-Za-z_][\w.-]*)[ \t]*:")
_BLOCK = re.compile(r"([|>])([-+]?)(\d?)[ \t]*(?:#[^\r\n]*)?\r?$")
_HEREDOC = re.compile(r"<<(-?)([A-Za-z_]\w*)[ \t]*\r?$")
_DOCKER_SPACE = re.compile(r"(?mi)^[ \t]*ENV[ \t]+" + KEY + r"[ \t]+(?!=)(?P<v>[^\r\n]*?)[ \t]*\r?$")


def _line_bounds(text: str, i: int):
    a = text.rfind("\n", 0, i) + 1
    b = text.find("\n", i)
    return a, len(text) if b < 0 else b


@dataclass
class KeyCopy:
    values: list               # the value as written, and the forms a decoder reads (whitespace dropped)
    whole: bool
    form: str
    at: int


def key_copies(text: str) -> list:
    """Every value the exact key HUNTRESS_DESCRIPTOR is given in the file (see the module docstring)."""
    out = []
    for m in _KEY_AT.finditer(text):
        ls, le = _line_bounds(text, m.start())
        line_head = text[ls:m.start()]
        j = m.end()
        if j < len(text) and text[j] in "\"'" and line_head.rstrip().endswith(text[j]):
            j += 1                                   # a quoted key: JSON, a quoted YAML key
        k = j
        while k < le and text[k] in " \t":
            k += 1
        if k >= le:
            continue
        op = text[k]
        if op not in ":=":
            continue                                 # a use or a mention, not an assignment (ENV K V: below)
        if op == ":" and text.startswith(":=", k):
            op = "="
            k += 1
        v = k + 1
        while v < le and text[v] in " \t":
            v += 1
        got = _key_value(text, v, le, op, line_head)
        if got is not None:
            values, whole, form = got
            out.append(KeyCopy(values, whole, form, m.start()))
    for m in _DOCKER_SPACE.finditer(text):
        val = m.group("v")
        if val[:1] in "\"'" and len(val) >= 2 and val[-1] == val[0]:
            val = val[1:-1]
        if len(val) >= MIN_VALUE:
            out.append(KeyCopy([val, re.sub(r"\s+", "", val)], True, "docker-env-space", m.start()))
    return out


def _key_value(text: str, v: int, le: int, op: str, line_head: str):
    c = text[v] if v < le else ""
    if c == '"':
        q = _DQ.match(text, v)
        if q is None:
            return None
        raw = q.group(1)
        body = re.sub(r"\\\r?\n[ \t]*", "", raw)               # a Dockerfile/shell line continuation
        body = re.sub(r"\\(.)", r"\1", body)
        post_end = text.find("\n", q.end())
        post = text[q.end():len(text) if post_end < 0 else post_end]
        whole = bool(_POST_OK.fullmatch(post) or _PAIRS.fullmatch(post) or (op == ":" and _NEXT_MEMBER.match(post)))
        return [body], whole, "quoted"
    if c == "'":
        q = _SQ.match(text, v)
        if q is None:
            return None
        body = q.group(1).replace("''", "'")
        post = text[q.end():le]
        return [body], bool(_POST_OK.fullmatch(post) or _PAIRS.fullmatch(post)
                            or (op == ":" and _NEXT_MEMBER.match(post))), "quoted"
    rest = text[v:le]
    if op == ":":
        b = _BLOCK.match(rest)
        if b is not None:
            return _block_scalar(text, le, line_head, b.group(1))
    if op == "=":
        h = _HEREDOC.match(rest)
        if h is not None:
            return _heredoc(text, le, h.group(2))
    bare = re.match(r"[^\s\"'#;,{}\[\]]+", rest)
    if bare is None:
        return None
    post = rest[bare.end():]
    whole = bool(re.fullmatch(r"[ \t]*(?:(?:#|//)[^\r\n]*)?\r?", post) or _PAIRS.fullmatch(post))
    return [bare.group()], whole, "bare"


def _block_scalar(text: str, le: int, line_head: str, style: str):
    indent = len(line_head) - len(line_head.lstrip(" "))
    lines, pos = [], le + 1
    while pos <= len(text):
        nl = text.find("\n", pos)
        line = text[pos:len(text) if nl < 0 else nl].rstrip("\r")
        if line.strip() and len(line) - len(line.lstrip(" ")) <= indent:
            break
        lines.append(line.strip())
        if nl < 0:
            break
        pos = nl + 1
        if len(lines) > MAX_WRAP * 4:
            return None
    while lines and not lines[-1]:
        lines.pop()
    if not lines:
        return None
    joined = ("\n" if style == "|" else " ").join(lines)
    return [joined, re.sub(r"\s+", "", joined)], True, "block"


def _heredoc(text: str, le: int, delim: str):
    lines, pos = [], le + 1
    while pos < len(text):
        nl = text.find("\n", pos)
        line = text[pos:len(text) if nl < 0 else nl].rstrip("\r")
        if line.strip() == delim:
            body = "\n".join(lines).strip()
            return [body, re.sub(r"\s+", "", body)], True, "heredoc"
        lines.append(line)
        if nl < 0 or len(lines) > MAX_WRAP * 4:
            return None
        pos = nl + 1
    return None


# ------------------------------------------------------------------------------------------------ batch `set`

BAT_EXTS = frozenset(("bat", "cmd", "btm"))
# `set "descriptor_<id>=<value>"` (the quotes around the whole assignment) or `set descriptor_<id>=<value>` to the
# line end. Not `set /a` or `set /p` (the name must follow `set` at once).
_BAT_SET = re.compile(r'(?im)^[ \t]*@?set[ \t]+(?:"descriptor_(?P<qn>\w+)=(?P<qv>[^"\r\n]*)"[ \t]*'
                      r'|descriptor_(?P<n>\w+)=(?P<v>[^\r\n]*?)[ \t]*)\r?$')
_BAT_ANY_SET = re.compile(r'(?im)^[ \t]*@?set[ \t]+(?:/[ap][ \t]+)?"?descriptor_(\w+)[ \t]*=')
# What makes an unquoted batch value something else than its text: an expansion (`%x%`, `!x!`), an escape, a
# redirection or a command joined on, a quote.
_BAT_META = re.compile(r'[%!^&|<>"\s]')


def bat_copies(text: str) -> list:
    """Every `descriptor_<id>` value a batch file's `set` gives (see the module docstring). Whole when the value is
    bare text (no expansion, escape, redirection or blank) and the name is set once in the file: a second `set`
    of it (`set descriptor_x=%descriptor_x%<rest>`) makes the first a piece."""
    counts = {}
    for m in _BAT_ANY_SET.finditer(text):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    out = []
    for m in _BAT_SET.finditer(text):
        name = m.group("qn") or m.group("n")
        value = m.group("qv") if m.group("qn") else m.group("v")
        if value is None or len(value) < MIN_VALUE:
            continue
        whole = counts.get(name, 0) == 1 and not _BAT_META.search(value)
        out.append(KeyCopy([value], whole, "descriptor_" + name, m.start()))
    return out


# ------------------------------------------------------------------------------------------------ tagged comments

_MARK = re.compile(r"HUNTRESS[_-]ANALYSIS[_-]V(\d+)[ \t]*[:=][ \t]*([^\r\n]*)")
_SPLIT_TAG = re.compile(r"(?P<tag>[A-Za-z][A-Za-z0-9_+>]{0,31}?)-(?P<payload>\S+)$")
_CLOSER = re.compile(r"[ \t]*(?:\*/|-{2,3}%?>|#>|%>|\?>|\]\]>?|=end|--\]\]|\|#|\*\)|-\}|\"\"\"|''')[ \t]*$")
_RUN = re.compile(r"[\x21-\x7e]+")
_BLOCK_OPEN = ("/*", "<!--", "<#", "{-", "(*", "--[[", "#|", '"""', "'''", "=begin", "<%--")


@dataclass
class CommentCopy:
    tag: str
    payload: str
    at: int
    lines: int                 # 1, or the comment lines a wrapped payload was joined from
    end: int


def comment_copies(text: str) -> list:
    """Each tagged comment's payload, and, when it is wrapped, the payload joined from its comment lines."""
    out = []
    for m in _MARK.finditer(text):
        raw = _CLOSER.sub("", m.group(2)).strip()
        sp = _SPLIT_TAG.match(raw)
        if sp is None:
            continue
        tag, payload = sp.group("tag"), sp.group("payload")
        ls, le = _line_bounds(text, m.start())
        out.append(CommentCopy(tag, payload, m.start(), 1, le))
        closed = _CLOSER.search(m.group(2)) is not None
        more = _continuation(text, ls, m.start(), le, closed)
        if more:
            joined = payload + "".join(p for p, _ in more)
            out.append(CommentCopy(tag, joined, m.start(), 1 + len(more), more[-1][1]))
    return out


def _continuation(text: str, ls: int, mark_at: int, le: int, closed: bool) -> list:
    """[(piece, line end)] of the lines that go on with a tagged comment's payload (see the module docstring)."""
    head = text[ls:mark_at].strip()
    opened = next((o for o in _BLOCK_OPEN if head.startswith(o)), None) if not closed else None
    leader = head if opened is None else None
    if leader is None and opened is None:
        return []
    if leader == "" and opened is None:
        return []
    pieces, pos = [], le + 1
    while pos < len(text) and len(pieces) < MAX_WRAP:
        nl = text.find("\n", pos)
        end = len(text) if nl < 0 else nl
        line = text[pos:end].rstrip("\r")
        s = line.strip()
        if opened is not None:
            s = re.sub(r"^\*+(?!/)[ \t]*", "", s)
            has_closer = _CLOSER.search(s) is not None
            s = _CLOSER.sub("", s).strip()
        else:
            if not s.startswith(leader):
                break
            s = s[len(leader):].strip()
            has_closer = _CLOSER.search(s) is not None
            s = _CLOSER.sub("", s).strip()
        if not s or not _RUN.fullmatch(s) or _MARK.search(s):
            break
        pieces.append((s, end))
        if has_closer:
            break
        pos = end + 1
    return pieces


# ------------------------------------------------------------------------------------------------ the reading

_KEY_LITERAL = re.compile(r"[\"'`]([^\s\"'`\\]{1,64})[\"'`]")


def file_keys(text: str) -> list:
    """Short literals of the file (MAX_KEYS), as bytes and, when they are hex, as the bytes they spell."""
    out = []
    for m in _KEY_LITERAL.finditer(text):
        s = m.group(1)
        for k in (s.encode("latin-1", "ignore"),
                  bytes.fromhex(s) if len(s) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", s) else b""):
            if k and k not in out:
                out.append(k)
        if len(out) >= MAX_KEYS:
            break
    return out


def reading(text: str, ext=None, settled: bool = False) -> Reading:
    """The witnesses of every residual kind in one file (see the module docstring).

    `settled`: the file's plan is already proven by two agreeing copies (a tagged comment and a descriptor literal
    that descriptor.py decoded). Its comments and literals are then not decoded again (they gave that plan; a
    second decode of each doubled the lane's read time); only the copies descriptor.py does not see (the exact key,
    a batch `set`, a computed value) are read, to be weighed against the settled plan."""
    r = Reading()
    if len(text) > MAX_TEXT:
        r.notes.append(f"more than {MAX_TEXT} characters: the residual readers are not asked")
        return r
    ext = (ext or "").lower().lstrip(".")
    budget = _Budget()
    keys = None

    def ks():
        nonlocal keys
        if keys is None:
            keys = file_keys(text)
        return keys

    # the exact key
    valued = []                                       # (value as written, its one plan) of every whole key copy
    for c in key_copies(text):
        got, deep = [], False
        for value in dict.fromkeys(c.values):
            if len(value) < MIN_VALUE:
                continue
            got, deep = _plans(value, budget, ks())
            if got:
                break
        for t, how in got:
            r.witnesses.append(Witness(t, "deep-key" if deep else "key", c.whole and len(got) == 1, how, c.at, KEY))
        if c.whole and len(got) == 1:
            valued.extend((v, got[0][0]) for v in c.values)
    # tagged comments, wrapped comments
    for c in () if settled else comment_copies(text):
        if c.lines == 1:
            got, deep = _plans(f"{c.tag}-{c.payload}", budget, ks(), deep_ok=False)
            if got:
                for t, how in got:
                    r.witnesses.append(Witness(t, "comment", len(got) == 1, how, c.at))
                continue
            got, deep = _plans(f"{c.tag}-{c.payload}", budget, ks())
            for t, how in got:
                r.witnesses.append(Witness(t, "deep-comment", len(got) == 1, how, c.at))
            if not got and len(c.payload) >= MIN_VALUE:
                # a cut comment: the head of a whole key copy's value is a piece of that copy, not another plan
                heads = {t for v, t in valued if v != c.payload and v.startswith(c.payload)}
                if len(heads) == 1:
                    r.witnesses.append(Witness(heads.pop(), "comment-piece", False, "piece", c.at))
        else:
            if any(w.at == c.at and w.kind in ("comment", "deep-comment") for w in r.witnesses):
                continue                              # its first line alone is a copy: no wrap is read
            got, _ = _plans(f"{c.tag}-{c.payload}", budget, ks())
            for t, how in got:
                r.witnesses.append(Witness(t, "wrapped", False, how + f"|wrapped:{c.lines}", c.at))
    # untagged deep literals
    d = _desc()
    for m in () if settled else d.LITERAL.finditer(text):
        body = m.group("body")
        if len(body) < MIN_VALUE:
            continue
        whole = bool(d.WHOLE_POST.fullmatch(m.group("post")))
        got = _plans(body, budget, ks(), deep_ok=False)[0]
        if got:
            # read by the readers before this one: a witness only, as a plain tagged comment is
            for t, how in got:
                r.witnesses.append(Witness(t, "literal", whole and len(got) == 1, how, m.start(), m.group(1)))
            continue
        got, deep = _plans(body, budget, ks())
        for t, how in got:
            r.witnesses.append(Witness(t, "deep-literal", whole and len(got) == 1, how, m.start(), m.group(1)))
    # a batch file's `set "descriptor_<id>=<payload>"` (descriptor.LITERAL wants a quote after the `=`)
    if ext in BAT_EXTS:
        for c in bat_copies(text):
            got, deep = _plans(c.values[0], budget, ks())
            for t, how in got:
                r.witnesses.append(Witness(t, "deep-bat" if deep else "bat", c.whole and len(got) == 1, how, c.at,
                                           c.form))
    # modern JavaScript
    if ext in _js_exts() and _JS_QUICK.search(text):
        js_witnesses(text, r, budget)
    r.over = budget.over
    if r.over:
        r.notes.append(f"more than {MAX_VALUES} values to decode: nothing is lifted by the residual readers")
    return r


_JS_QUICK = re.compile(r"=>|`|\.\.\.|fromCharCode|fromCodePoint|atob|Buffer\.from|\.map\(|\.reduce\(")


def _js_exts():
    jm = plan_codec.optional("js_modern")
    if jm is None:
        raise MissingModule("js_modern")
    return jm.JS_EXTS


def js_witnesses(text: str, r: Reading, budget: _Budget) -> None:
    jm = plan_codec.optional("js_modern")
    if jm is None:
        raise MissingModule("js_modern")
    comp = jm.values(text)
    if comp.why:
        r.notes.append(f"js_modern: {comp.why}")
        return
    if comp.untrusted:
        r.notes.append(f"js_modern: {len(comp.untrusted)} top-level value(s) not trusted (a statement joined to "
                       f"them could not be followed)")
    vals = comp.strings
    for name, value in vals.items():
        if len(value) < MIN_VALUE or value in text:
            continue                                  # as written: the readers before this one read it
        got, _deep = _plans(value, budget, (), deep_ok=False)
        if not got:
            continue
        piece = any(o != value and value in o for n, o in vals.items() if n != name)
        for t, how in got:
            r.witnesses.append(Witness(t, "js", not piece and len(got) == 1, "js:" + how, 0, name))
        if piece:
            r.notes.append(f"js_modern: {name}'s value is a piece of another computed value: no whole copy")
    if comp.untrusted and any(w.kind == "js" for w in r.witnesses):
        # a value nothing could follow may be a second plan or the value the code really builds
        for w in r.witnesses:
            if w.kind == "js":
                w.whole = False


# ------------------------------------------------------------------------------------------------ the gate

def _refuse(info: dict, why: str) -> None:
    info.update(plan={}, plan_text=None, how=None, transform=None, cut=False, ambiguous=True, source=None)
    info.pop("one_copy", None)
    info.pop("one_copy_wrapped", None)
    info["two_copies"] = False
    info["notes"].append(why)


def apply(info: dict, r: Reading | None = None) -> str | None:
    """Weigh the residual witnesses against what generic.read settled; 'refused', 'lifted', 'one_copy' or None."""
    text, ext = info["text"], info.get("ext")
    if r is None:
        settled = bool(info.get("plan")) and bool(info.get("two_copies")) and info.get("source") == "descriptor" \
            and not (info.get("cut") or info.get("one_copy") or info.get("ambiguous"))
        r = reading(text, ext, settled=settled)
    info["notes"].extend(r.notes)
    # A plain tagged comment or a `descriptor_<id>` literal that decodes as it stands is descriptor.py's own copy,
    # already weighed there: it only witnesses the new kinds.
    new = [w for w in r.witnesses if w.kind not in ("comment", "literal")]
    if not new:
        return None
    plans = []
    for w in new:
        if w.plan_text not in plans:
            plans.append(w.plan_text)
    have = info.get("plan") or {}
    if len(plans) > 1:
        kinds = sorted({w.kind for w in new})
        _refuse(info, f"B-247: {len(plans)} different plans among the file's copies ({', '.join(kinds)}): "
                      f"no plan is taken")
        return "refused"
    t = plans[0]
    plan = plan_codec.flatten(t)
    for w in r.witnesses:
        if w.kind in ("comment", "literal") and w.plan_text != t and not plan_codec.head_of(w.plan_text, t):
            _refuse(info, f"B-247: a tagged {w.kind} and a {new[0].kind} copy give different plans: no plan is taken")
            return "refused"
    differ = next((k for k, x in have.items() if k not in plan or str(plan[k]) != str(x)), None)
    if differ is not None:
        kinds = sorted({w.kind for w in new})
        _refuse(info, f"B-247: a {'/'.join(kinds)} copy gives another plan than the one read "
                      f"(differs on {ascii(str(differ))[:60]}): no plan is taken")
        return "refused"
    agreeing = [w for w in r.witnesses if w.plan_text == t]
    opened = not have or info.get("cut") or info.get("one_copy")
    unread = bool(info.get("ambiguous")) and str(info.get("descriptor_why") or "").startswith(COMMENT_UNREAD) \
        and any(w.kind in ("wrapped", "deep-comment", "comment-piece") for w in new)
    if info.get("ambiguous") and not unread:
        return None
    if not opened:
        second = next((w for w in new if w.kind in ("key", "bat") and w.whole), None)
        if second is not None and any(w.kind == "comment" for w in agreeing) and info.get("source") == "descriptor":
            info["two_copies"] = True                 # the exact key (a batch `set`) is the comment's second copy
            info["notes"].append("B-247: the exact HUNTRESS_DESCRIPTOR key agrees with the tagged comment"
                                 if second.kind == "key" else
                                 "B-247: the batch `set` of the descriptor agrees with the tagged comment")
        return None
    if r.over or not complete(t):
        return None
    if unread:
        blind = plan_codec.optional("blind_reader")
        if blind is None:
            raise MissingModule("blind_reader")
        v = blind.reading(text, ext)
        if v.plan_text and v.plan_text != t:
            return None
        if not v.plan_text and v.why and ("different" in v.why or "another" in v.why or "more than" in v.why):
            return None
    # Whole: a bounded copy, or any two copies that give the very same plan (a wrapped comment and a literal).
    whole = [w for w in agreeing if w.whole]
    full = [w for w in agreeing if w.kind != "comment-piece"]
    if whole or len(full) >= 2:
        lead = (whole or full)[0]
        rep, _, tr = lead.how.partition("|")
        info.update(plan=plan, plan_text=t, how=rep, transform=tr or "identity", cut=False, ambiguous=False,
                    source="residuals", two_copies=len(full) >= 2)
        info.pop("one_copy", None)
        info.pop("one_copy_wrapped", None)
        # a comment-piece is a cut head of a whole copy, not a copy of its own: the note counts what two_copies counts
        pieces = len(agreeing) - len(full)
        info["notes"].append(f"B-247: plan read whole by the residual readers "
                             f"({', '.join(sorted({w.kind for w in full}))}; {len(full)} "
                             f"cop{'y' if len(full) == 1 else 'ies'}"
                             + (f", and {pieces} cut tagged comment{'' if pieces == 1 else 's'} that "
                                f"{'is' if pieces == 1 else 'are'} its head" if pieces else "") + ")")
        return "lifted"
    # one copy that is not bounded (a wrapped comment, a computed piece): its last field unsure
    items = list(plan.items())
    if len(items) < 2 or "|" not in t:
        return None
    if have and set(have) - set(dict(items[:-1])):
        return None                                   # what was read already holds the field this would drop
    info.update(plan=dict(items[:-1]), plan_text=t[:t.rfind("|") + 1], how=agreeing[0].how.split("|")[0],
                transform="identity", cut=True, ambiguous=False, source="residuals", two_copies=False)
    if any(w.kind == "wrapped" for w in agreeing):
        info["one_copy"] = items[-1]
        info["one_copy_wrapped"] = True
    info["notes"].append("B-247: a wrapped tagged comment (or a value that may be a piece) is the plan's one "
                         "copy: the plan is taken without its last field (asked for, that one is unsure)")
    return "one_copy"


# ------------------------------------------------------------------------------------------------ multi-host

def _hosted(generic, text: str) -> list:
    """[(ext, a, b, script)] of the encoded scripts a host's forms hold, whatever the scripts hold."""
    if generic._ENC_QUICK.search(text) is None:
        return []
    ps = generic._PS_NAMED.search(text) is not None
    seen, out = set(), []
    for ext, rx, needs_ps in generic._ENC_FORMS:
        if needs_ps and not ps:
            continue
        for m in rx.finditer(text):
            span = m.span(1)
            if span in seen:
                continue
            seen.add(span)
            if len(seen) > generic._ENC_CANDIDATES:
                return [(None, 0, 0, "")]
            script = generic._enc_text(m.group(1))
            if script is not None:
                out.append((ext, span[0], span[1], script))
    return out


def multi_host(info: dict, name: str):
    """The plan of a script nested in base64 hosts 2..MAX_HOSTS deep (see the module docstring), put in `info`
    (True), else False. Asked only of a file with no plan that nothing refused."""
    if info.get("plan") or info.get("ambiguous"):
        return False
    generic = plan_codec.own("generic")
    text, levels = info["text"], []
    for depth in range(MAX_HOSTS):
        found = _hosted(generic, text)
        if len(found) != 1 or found[0][0] is None:
            return False
        ext, a, b, script = found[0]
        marked = generic._MARK_ANY.search(script) is not None
        if not generic._region_alone(text, text, a, b, generic._payload_len(script) if marked else 0):
            return False
        levels.append(ext)
        if marked:
            if depth == 0:
                return False                          # one level: generic.encoded_host's own reading
            if len(generic._MARK_ANY.findall(script)) != 1 or "descriptor_" not in script:
                return False
            inner = generic.read(f"{Path(name).stem}.encoded.{ext}", script, _nested=True)
            if not (inner.get("plan") and inner.get("source") == "descriptor" and inner.get("two_copies")
                    and not inner.get("cut") and not inner.get("one_copy") and not inner.get("ambiguous")
                    and not inner.get("dead_text")):
                return False
            for k in ("plan", "plan_text", "how", "transform", "two_copies", "descriptor", "descriptor_keys"):
                if k in inner:
                    info[k] = inner[k]
            info.update(cut=False, ambiguous=False, source="descriptor", route="multi_host")
            info["notes"].append(f"B-247: the plan is the one script nested {depth + 1} hosts deep "
                                 f"({' > '.join(levels)}), proven by its two agreeing copies")
            return True
        text = script
    return False


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: residuals.py <specimen> [...]   (prints the copies the residual readers see)", file=sys.stderr)
        return 2
    status = 0
    for arg in argv:
        try:
            raw = Path(arg).read_bytes()
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})", file=sys.stderr)
            status = 1
            continue
        r = reading(plan_codec.text_of(raw), Path(arg).suffix)
        if not r.witnesses:
            print(f"{arg}: no residual copy" + (f" ({'; '.join(r.notes)})" if r.notes else ""))
        for w in r.witnesses:
            shown = w.plan_text.encode("ascii", "backslashreplace").decode("ascii")
            print(f"{arg}: {w.kind}{' whole' if w.whole else ''} ({w.how}) {shown}")
        if len(r.plans()) > 1:
            print(f"{arg}: {len(r.plans())} different plans: none is taken")
    return status


if __name__ == "__main__":
    sys.exit(main())
