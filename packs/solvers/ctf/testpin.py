"""Test-pin codemod: rewrite the expected values a test file pins from fixture outputs (B-258).

When a fixture's output changes on purpose (a new reading, a corrected spelling), every test that pins
the old value must change with it. Hand-patching those files was the most repeated build-time script
(182 inline patchers on one Huntress day). This finds the pins by their shape, replaces only the
literal's own source text, and shows a unified diff; nothing is written without `write=True`.

A pin is a literal paired with a string key:

  1. an entry of a dict literal assigned to a name that matches `names` (default: EXPECT*, *_EXPECTED,
     WANT, GOLDEN, PINS, ...):  EXPECTED = {"d31_analysis_crc": "0x1234", ...}. A nested dict's entry
     has the path key `outer/inner` as well as its own key; the path is looked up first.
  2. a comparison against a subscript or .get() by a string key, either way round:
     assert out["d31_analysis_crc"] == "0x1234"      assert "0x1234" == out.get("d31_analysis_crc")
  3. any assignment or comparison with a trailing `# pin: KEY` comment on its first line: the literal
     side is the pin for KEY (it wins over the shapes above).

Only a literal (what ast.literal_eval reads) is rewritten; a pin whose current value is an expression
is reported as skipped with its line, never guessed at. A key the outputs do not hold is left alone.
An entry nested under a case id of the outputs takes only its own `case/key` value, never another
case's bare key; a pin on a bare key the cases disagree on is skipped and named.
The new text keeps the old literal's quote style, a hex int stays hex, a tuple stays a tuple. After
the edit the file must parse and every edited pin must read back as its new value, or nothing is
written (TestPinError).
"""
from __future__ import annotations

import ast
import difflib
import io
import re
import tokenize
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_NAMES = r"(?i)^_?(expect\w*|\w*_expect(ed|ations?)?|want(ed)?|golden\w*|pins?|\w*_pins?)$"
PIN_COMMENT = re.compile(r"#\s*pin:\s*(\S+)")
_MISS = object()


class TestPinError(ValueError):
    __test__ = False   # not a pytest class


@dataclass
class Site:
    key: str
    alt: str | None          # the bare key of a nested dict entry (path key first)
    node: ast.expr | None    # the literal; None when the pinned value is not a literal
    line: int
    origin: str              # dict, compare, comment


@dataclass
class Edit:
    key: str
    line: int
    start: int               # byte offsets into the UTF-8 source
    end: int
    old: str
    new: str


@dataclass
class Plan:
    edits: list = field(default_factory=list)
    unchanged: list = field(default_factory=list)    # keys whose pin already holds the value
    skipped: list = field(default_factory=list)      # (key, line, why)
    sites: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.edits)


def _literal(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return _MISS


def _str_key(node) -> str | None:
    """The string a subscript or .get(...) reads with, else None."""
    if isinstance(node, ast.Subscript):
        s = node.slice
        if isinstance(s, ast.Constant) and isinstance(s.value, str):
            return s.value
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
            and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
        return node.args[0].value
    return None


def _target_name(t) -> str | None:
    if isinstance(t, ast.Name):
        return t.id
    if isinstance(t, ast.Attribute):
        return t.attr
    return None


def _comments(source: str) -> dict[int, str]:
    """{line: key} of `# pin: KEY` comments."""
    out = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                m = PIN_COMMENT.search(tok.string)
                if m:
                    out[tok.start[0]] = m.group(1)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return out


def _dict_sites(d: ast.Dict, prefix: str, out: list) -> None:
    for k, v in zip(d.keys, d.values):
        if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
            continue
        path = f"{prefix}/{k.value}" if prefix else k.value
        if isinstance(v, ast.Dict) and v.keys and all(isinstance(x, ast.Constant) and isinstance(x.value, str)
                                                       for x in v.keys):
            # a dict of pins (a case's answers): its entries are the pins, and so is the whole dict
            _dict_sites(v, path, out)
        out.append(Site(path, k.value if prefix else None, v if _literal(v) is not _MISS else None,
                        v.lineno, "dict"))


def find_sites(source: str, names: str = DEFAULT_NAMES) -> list[Site]:
    """Every pin site in `source`, in source order."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        raise TestPinError(f"not Python: {e}") from None
    name_re = re.compile(names)
    marked = _comments(source)
    sites: list[Site] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            if node.lineno in marked:
                v = node.value
                sites.append(Site(marked[node.lineno], None, v if _literal(v) is not _MISS else None,
                                  node.lineno, "comment"))
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(node.value, ast.Dict) and any(
                    (n := _target_name(t)) is not None and name_re.search(n) for t in targets):
                _dict_sites(node.value, "", sites)
        elif isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            left, right = node.left, node.comparators[0]
            if node.lineno in marked:
                lit = right if _literal(right) is not _MISS else left if _literal(left) is not _MISS else None
                sites.append(Site(marked[node.lineno], None, lit, node.lineno, "comment"))
                continue
            for keyed, other in ((left, right), (right, left)):
                k = _str_key(keyed)
                if k is not None:
                    sites.append(Site(k, None, other if _literal(other) is not _MISS else None,
                                      node.lineno, "compare"))
                    break
    sites.sort(key=lambda s: (s.line, s.node.col_offset if s.node is not None else -1))
    return sites


# -------------------------------------------------------------------------------------------- rendering

def _is_hex_src(src: str) -> bool:
    return bool(re.fullmatch(r"-?0[xX][0-9a-fA-F_]+", src.strip()))


def render(value, old_node: ast.expr | None, old_src: str) -> str:
    """Source text for `value`, in the old literal's style where it can be kept."""
    if isinstance(value, bool) or value is None:
        return repr(value)
    if isinstance(value, int):
        if _is_hex_src(old_src):
            digits = old_src.strip().lstrip("-")[2:].replace("_", "")
            body = f"{abs(value):0{len(digits)}x}"          # the old width is kept as a minimum
            if any(c.isalpha() for c in digits) and digits == digits.upper():
                body = body.upper()
            return ("-" if value < 0 else "") + "0x" + body
        return repr(value)
    if isinstance(value, str):
        text = repr(value)
        quote = old_src.lstrip("rRbBuU")[:1] if isinstance(old_node, ast.Constant) else ""
        if quote == '"' and text.startswith("'") and '"' not in value:
            text = '"' + text[1:-1].replace("\\'", "'") + '"'
        return text
    if isinstance(value, list) and isinstance(old_node, ast.Tuple):
        value = tuple(value)
    if isinstance(value, list) and isinstance(old_node, ast.Set) and value:
        return "{" + ", ".join(repr(v) for v in value) + "}"
    return repr(value)


def _same(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if isinstance(a, (set, frozenset)) and isinstance(b, (list, tuple, set, frozenset)):
        return a == set(b)
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b


def _line_offsets(raw: bytes) -> list[int]:
    offs, pos = [0], 0
    for line in raw.splitlines(keepends=True):
        pos += len(line)
        offs.append(pos)
    return offs


# ----------------------------------------------------------------------------------------------- plans

def _owner(path: str, cases) -> str | None:
    """The case id a nested entry's path sits under (a proper prefix of it), else None."""
    parts = path.split("/")
    for i in range(len(parts) - 1, 0, -1):
        head = "/".join(parts[:i])
        if head in cases:
            return head
    return None


def _key_for(s: Site, values, cases, ambiguous) -> tuple[str | None, str | None]:
    """(key whose value this site takes, or None; why it is skipped, or None)."""
    if s.key in values:
        return s.key, None
    bare = s.alt if s.alt is not None else s.key
    if s.alt is not None and _owner(s.key, cases) is not None:
        # an entry under a case id: only its own case/key form may rewrite it, never another case's
        # bare key (`--case base` must not write base's value into the mastery entry)
        return None, None
    if bare in ambiguous:
        return bare, "cases disagree on this key: pick one (--case) or pin the case/key form"
    if s.alt is not None and s.alt in values:
        return s.alt, None
    return None, None


def plan(source: str, values: dict, names: str = DEFAULT_NAMES, *, cases=None, ambiguous=None) -> Plan:
    """What rewriting `source` with `values` ({key: new value}) would change.

    `cases` (default: `values.cases` of an expectations.Pins): the case ids of the outputs; an entry
    nested under one of them takes only its `case/key` value. `ambiguous` (default:
    `values.ambiguous`): bare keys the cases disagree on; a pin on one is skipped and named."""
    cases = frozenset(getattr(values, "cases", ()) if cases is None else cases)
    ambiguous = frozenset(getattr(values, "ambiguous", ()) if ambiguous is None else ambiguous)
    raw = source.encode("utf-8")
    offs = _line_offsets(raw)
    p = Plan()
    wanted: list[Edit] = []
    for s in find_sites(source, names):
        key, why = _key_for(s, values, cases, ambiguous)
        if key is None:
            continue
        p.sites += 1
        if why is not None:
            p.skipped.append((key, s.line, why))
            continue
        if s.node is None:
            p.skipped.append((key, s.line, "the pinned value is not a literal"))
            continue
        start = offs[s.node.lineno - 1] + s.node.col_offset
        end = offs[s.node.end_lineno - 1] + s.node.end_col_offset
        old_src = raw[start:end].decode("utf-8")
        new = values[key]
        if _same(_literal(s.node), new):
            p.unchanged.append(key)
            continue
        wanted.append(Edit(key, s.line, start, end, old_src, render(new, s.node, old_src)))
    # Overlapping pins (a nested dict pinned whole and entry by entry): the smallest span wins, so a
    # case's dict is rewritten entry by entry and never replaced whole over its own entries.
    for e in sorted(wanted, key=lambda e: (e.end - e.start, e.start)):
        if any(o.start < e.end and e.start < o.end for o in p.edits):
            inner = any(e.start <= o.start and o.end <= e.end for o in p.edits)
            p.skipped.append((e.key, e.line, "a dict whose entries are pinned one by one" if inner
                              else "overlaps another pin being rewritten"))
            continue
        p.edits.append(e)
    p.edits.sort(key=lambda e: e.start)
    return p


def apply(source: str, p: Plan) -> str:
    raw = source.encode("utf-8")
    for e in sorted(p.edits, key=lambda e: e.start, reverse=True):
        raw = raw[: e.start] + e.new.encode("utf-8") + raw[e.end:]
    return raw.decode("utf-8")


def _new_spans(p: Plan) -> set[tuple[int, int]]:
    """Where each edit's literal sits in the rewritten source (byte offsets)."""
    out, shift = set(), 0
    for e in sorted(p.edits, key=lambda e: e.start):
        n = len(e.new.encode("utf-8"))
        out.add((e.start + shift, e.start + shift + n))
        shift += n - (e.end - e.start)
    return out


def rewrite(source: str, values: dict, names: str = DEFAULT_NAMES, *, cases=None,
            ambiguous=None) -> tuple[str, Plan]:
    """(new source, plan). The new source is checked: it parses, and every edited pin now reads back
    as its value (TestPinError otherwise). The check plans the new source again with the same values
    and looks only at the edited spans: a pin left unchanged, or one skipped as overlapping, is no
    failure of the rewrite."""
    p = plan(source, values, names, cases=cases, ambiguous=ambiguous)
    if not p.changed:
        return source, p
    new = apply(source, p)
    try:
        again = plan(new, values, names, cases=cases, ambiguous=ambiguous)
    except TestPinError as e:
        raise TestPinError(f"the rewritten file does not parse ({e}); nothing written") from None
    spans = _new_spans(p)
    stale = [e for e in again.edits if (e.start, e.end) in spans]
    if stale:
        bad = ", ".join(sorted({e.key for e in stale}))
        raise TestPinError(f"pins for {bad} do not read back as their new value; nothing written")
    return new, p


def diff(old: str, new: str, path: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))


def rewrite_file(path: str | Path, values: dict, *, write: bool = False, names: str = DEFAULT_NAMES,
                 cases=None, ambiguous=None) -> tuple[str, Plan]:
    """(unified diff, plan) for one file; the file changes only with write=True."""
    path = Path(path)
    if not path.is_file():
        raise TestPinError(f"no file {path}")
    old = path.read_text(encoding="utf-8")
    try:
        new, p = rewrite(old, values, names, cases=cases, ambiguous=ambiguous)
    except TestPinError as e:
        raise TestPinError(f"{path}: {e}") from None
    if write and p.changed:
        tmp = path.with_name(path.name + ".testpin.tmp")
        tmp.write_text(new, encoding="utf-8")
        tmp.replace(path)
    return diff(old, new, str(path)), p
