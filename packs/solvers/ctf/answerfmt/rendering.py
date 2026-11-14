"""Rendering a value in the form its question's answer_format states (B-232).

    r = render(["b.txt", "a.txt"], {"kind": "exact_text", "syntax": "comma-separated, no spaces"})
    r.status        # "options": the order is not stated
    r.options       # (("file_order+stated", "b.txt,a.txt"), ("ascending+stated", "a.txt,b.txt"))
    r.axes          # ("order",)

A Rendering is one of
  plain     the contract settles the form: `value` is the one text to send;
  options   the contract leaves an axis open: `options` are (hypothesis name, text) pairs, best first,
            at most MAX_OPTIONS, each text distinct; `axes` names what they vary on (`order`, `join`,
            `spelling`). A caller never sends one plain: it probes them (`ctf.answerfmt.wire` hands
            them to labels.candidates / labels.pick);
  withheld  the value cannot be right under the contract, or cannot be rendered in it: `reason` says
            why. Nothing is sent.

List-valued answers (a list or tuple, or a string of tokens under a token contract) take two axes:
  order   `given` (ordered=True, or kind ordered_tokens: the sequence is the fact), else the order
          the contract states (`ascending`, `descending`, `file_order`), else BOTH file order and
          ascending (the Day 15 and Day 23 shapes: the reader had the list right, only its order
          was unknown). Ascending is Python's sort: numeric for ints, code point for strings; a list
          of digit strings also gets `ascending_numeric` when that differs, unless the contract says
          the elements are integers (then only numeric). An order keyed on something else (`sorted
          by size`, `digest order`) is withheld unless the caller ordered the list (ordered=True).
  join    a JSON array (kind json or a stated JSON array), the stated separator (plain when the text
          says no spaces surround it or the separator carries its own blanks, else tight and spaced),
          or, when nothing is stated, comma, comma-space, JSON and space. Spaced means `, ` after a
          comma, semicolon or colon and ` > ` around any other mark. A join an element itself
          contains is dropped (its text would not split back into the elements).
Option names are `<order>+<join>` (`file_order+comma`, `ascending+json`): each names a hypothesis,
never a value, so an accepted name answers the next variant's own list.

A string under a token contract (kind ordered_tokens, or a stated separator on a text kind) is a list
of tokens (a stated newline, `one per line`, counts as stated though it is a blank). When the stated separator is in it, it splits on that separator ALONE (`cut -d, -f1>sort`
under `>` is two tokens; the comma stays inside the first). When it is not, and exactly one common list
separator (`->`, `=>`, `>`, `,`, `|`, `;`, newline) is in it, the split is a third axis, `split`: the
options are the split reading's (`split_comma+given+tight`), then the whole string as one token
(`whole`), never plain. Several common separators and not the stated one, or an empty token (`a,,b`),
are withheld.

Scalars: an integer kind must be a base-10 integer; an enum with a closed `accepted_values` list
takes the listed spelling when the value matches one entry ignoring case, and is withheld when it
matches none; a json kind must parse; everything else is sent as given. An already-unsure string
(`??...`, solvers/common/labels.py's wire form) is withheld from rendering: it is not an answer.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .contract import AnswerFormatError, Contract, read

__all__ = ["Rendering", "Batch", "render", "render_answers", "PLAIN", "OPTIONS", "WITHHELD", "MAX_OPTIONS",
           "UNSURE_PREFIX"]

PLAIN, OPTIONS, WITHHELD = "plain", "options", "withheld"
MAX_OPTIONS = 12           # labels.MAX_OPTIONS: a key has 12 guesses in all
UNSURE_PREFIX = "??"       # labels.SENTINEL


@dataclass(frozen=True)
class Rendering:
    status: str
    value: str | None = None
    options: tuple[tuple[str, str], ...] = ()
    axes: tuple[str, ...] = ()
    reason: str = ""

    @property
    def plain(self) -> bool:
        return self.status == PLAIN

    def line(self, aid: str) -> str:
        if self.status == PLAIN:
            return f"PLAIN {aid}: {self.value!r}"
        if self.status == OPTIONS:
            return f"UNSURE {aid}: {len(self.options)} option(s) on {'+'.join(self.axes)} ({self.reason})"
        return f"HELD {aid}: {self.reason}"

    def describe(self) -> dict:
        return {"status": self.status, "value": self.value, "options": [list(o) for o in self.options],
                "axes": list(self.axes), "reason": self.reason}


def _plain(text: str, name: str) -> Rendering:
    return Rendering(PLAIN, text, ((name, text),))


def _withheld(reason: str) -> Rendering:
    return Rendering(WITHHELD, reason=reason)


def _compact(obj) -> str | None:
    try:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return None


def _item_text(x) -> str | None:
    """An element as it is written inside a joined list; None for one that has no plain text."""
    if isinstance(x, bool):
        return None
    if isinstance(x, str):
        return x
    if isinstance(x, int):
        return str(x)
    if isinstance(x, float):
        return repr(x)
    return None


_DIGITS = re.compile(r"[+-]?\d+")


def _integers_stated(c: Contract) -> bool:
    return c.kind in ("integer", "intlist", "integers") or bool(re.search(r"\bintegers?\b|\bnumbers?\b", c.syntax.lower()))


def _ascending(items: list, c: Contract) -> list[tuple[str, list]]:
    """The ascending orders of `items`: [(name, sorted list)], [] when the elements cannot be compared."""
    if all(isinstance(x, int) and not isinstance(x, bool) for x in items):
        return [("ascending", sorted(items))]
    if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in items):
        return [("ascending", sorted(items))]
    if not all(isinstance(x, str) for x in items):
        return []
    lexical = sorted(items)
    if all(_DIGITS.fullmatch(x.strip()) for x in items):
        numeric = sorted(items, key=lambda x: int(x.strip()))
        if _integers_stated(c):
            return [("ascending", numeric)]
        # when numeric equals lexical, _render_list drops the repeated text
        return [("ascending", lexical), ("ascending_numeric", numeric)]
    return [("ascending", lexical)]


def _orders(items: list, c: Contract, ordered: bool) -> tuple[list[tuple[str, list]], str]:
    """([(order name, list)], why none) for a list answer."""
    if ordered or c.kind == "ordered_tokens":
        return [("given", items)], ""
    if c.order == "keyed":
        return [], ("the contract orders the list by a key of its own (e.g. `sorted by size`, `digest order`); "
                    "order it in a handler and render it with ordered=True")
    if c.order in ("file", "any"):
        return [("file_order", items)], ""
    asc = _ascending(items, c)
    if c.order == "ascending":
        return asc, ("" if asc else "the contract asks ascending order, but the elements cannot be compared")
    if c.order == "descending":
        desc = [(n.replace("ascending", "descending"), list(reversed(s))) for n, s in asc]
        return desc, ("" if desc else "the contract asks descending order, but the elements cannot be compared")
    # an ascending list equal to the file order joins to the same text, which _render_list drops
    return [("file_order", items)] + asc, ""


def _joins(c: Contract) -> tuple[list[tuple[str, str | None]], str]:
    """([(join name, separator or None for JSON)], why none)."""
    if c.container == "json_object":
        return [], "the contract asks a JSON object; a list value is no object"
    if c.container in ("json_array", "json") or c.kind == "json":
        return [("json", None)], ""
    if c.separator is not None:
        sep = c.separator
        if c.tight or c.spaced_separator:
            return [("stated", sep)], ""
        # a comma, semicolon or colon is spaced after it (`a, b`); any other mark on both sides (`a > b`)
        return [("tight", sep), ("spaced", f"{sep} " if sep in ",;:" else f" {sep} ")], ""
    if c.kind == "ordered_tokens":
        return [("gt", ">"), ("gt_spaced", " > "), ("comma", ",")], ""
    return [("comma", ","), ("comma_space", ", "), ("json", None), ("space", " ")], ""


def _join(seq: list, sep: str | None) -> tuple[str | None, str]:
    """(the joined text, why not)."""
    if sep is None:
        text = _compact(list(seq))
        return (text, "") if text is not None else (None, "an element is not JSON")
    texts = [_item_text(x) for x in seq]
    if any(t is None for t in texts):
        return None, "an element has no plain text (only a JSON array can hold it)"
    probe = sep.strip() or sep
    if any(probe in t for t in texts):
        return None, f"an element contains the separator {sep!r}"
    return sep.join(texts), ""


def _render_list(items: list, c: Contract, ordered: bool) -> Rendering:
    if not items:
        if c.none_ok:
            return _plain("none", "literal_none")
        return _withheld("an empty list, and the contract does not allow the literal none")
    orders, why = _orders(items, c, ordered)
    if not orders:
        return _withheld(why)
    joins, why = _joins(c)
    if not joins:
        return _withheld(why)
    options, seen, whys = [], set(), []
    for oname, seq in orders:
        for jname, sep in joins:
            text, why = _join(seq, sep)
            if text is None:
                whys.append(f"{jname}: {why}")
                continue
            if text in seen:
                continue
            seen.add(text)
            options.append((f"{oname}+{jname}", text))
    options = options[:MAX_OPTIONS]
    if not options:
        return _withheld("no join renders the list: " + "; ".join(dict.fromkeys(whys)))
    if len(options) == 1:
        return Rendering(PLAIN, options[0][1], tuple(options))
    axes = []
    if len({n.split("+", 1)[0] for n, _ in options}) > 1:
        axes.append("order")
    if len({n.split("+", 1)[1] for n, _ in options}) > 1:
        axes.append("join")
    unstated = {"order": "the element order", "join": "how the elements are joined"}
    return Rendering(OPTIONS, None, tuple(options), tuple(axes),
                     "the contract does not state " + " or ".join(unstated[a] for a in axes))


_SPLITTERS = ("->", "=>", ">", ",", "|", ";", "\n")
_SPLITTER_NAMES = {"->": "arrow", "=>": "fat_arrow", ">": "gt", ",": "comma", "|": "pipe", ";": "semicolon",
                   "\n": "newline"}


def _stated_mark(c: Contract) -> str | None:
    """The mark the stated separator is found by in a string: the separator without its blanks (`" > "`
    is `>`), or a whitespace separator that is itself a list separator (`one per line` is a newline).
    None when nothing is stated, or the stated separator is a blank no string is split on (a space)."""
    if c.separator is None:
        return None
    if c.separator.strip():
        return c.separator.strip()
    return c.separator if c.separator in _SPLITTERS else None


def _tokens(value: str, c: Contract) -> tuple[list[str] | None, str | None, str]:
    """(tokens, the separator they were split on, why not) for a string list answer.

    Separator marks are found longest first (`a->b` holds `->`, not `>`). When the contract's stated
    separator is among them, the string splits on it ALONE: a token may hold another mark
    (`cut -d, -f1>sort` under `>` is two tokens). When it is not, and exactly one common list separator
    is present, the string splits on that one (the caller offers the split as an option, never plain).
    (None, None, "") when no separator is present (one token); (None, None, why) when the string cannot
    be split with confidence: several common separators and not the stated one, or an empty token."""
    text = value.strip()
    stated = _stated_mark(c)
    seps = set(_SPLITTERS) | ({stated} if stated else set())
    rx = re.compile(r"\s*(" + "|".join(re.escape(s) for s in sorted(seps, key=len, reverse=True)) + r")\s*")
    marks = [(m.start(), m.end(), m.group(1)) for m in rx.finditer(text)]
    kinds = list(dict.fromkeys(k for _, _, k in marks))
    if not kinds:
        return None, None, ""
    if stated in kinds:
        at = stated
    elif len(kinds) == 1:
        at = kinds[0]
    else:
        return None, None, (f"the string holds several list separators ({', '.join(map(repr, kinds))})"
                            + (f" and not the stated {stated!r}" if stated else "")
                            + ": its tokens cannot be told apart")
    parts, last = [], 0
    for a, b, k in marks:
        if k == at:
            parts.append(text[last:a].strip())
            last = b
    parts.append(text[last:].strip())
    if any(not p for p in parts):
        return None, None, f"the string has an empty token between {at!r} separators"
    return parts, at, ""


def _split_options(value: str, at: str, r: Rendering) -> Rendering:
    """A token string split on a separator the contract does not state: the split reading's options,
    then the whole string as one token. Never plain, since `a,b` may be one token holding a comma."""
    name = _SPLITTER_NAMES.get(at, "stated")
    if r.status == WITHHELD:
        return _withheld(f"split on {at!r}: {r.reason}")
    split = [(f"split_{name}+{n}", t) for n, t in r.options][:MAX_OPTIONS - 1]
    whole = value.strip()
    options = split + ([("whole", whole)] if whole not in {t for _, t in split} else [])
    why = f"the contract does not state {at!r} as the separator, so the string may be one token"
    return Rendering(OPTIONS, None, tuple(options), ("split",) + r.axes,
                     why + (f"; {r.reason}" if r.status == OPTIONS else ""))


_TOKEN_KINDS_NOT = ("integer", "enum", "json", "pattern", "mitre_attack_id", "number", "float", "decimal", "boolean")


def _render_str(value: str, c: Contract, ordered: bool) -> Rendering:
    if value.startswith(UNSURE_PREFIX):
        return _withheld("already an unsure answer (labels wire form); it is not rendered again")
    if c.kind == "ordered_tokens" or (c.separator is not None and c.container is None and c.kind not in _TOKEN_KINDS_NOT):
        toks, at, why = _tokens(value, c)
        if why:
            return _withheld(why)
        if toks is not None:
            r = _render_list(toks, c, ordered or c.kind == "ordered_tokens")
            return r if at == _stated_mark(c) else _split_options(value, at, r)
    if c.kind == "integer":
        t = value.strip()
        if c.none_ok and t.lower() == "none":
            return _plain("none", "literal_none")
        if not _DIGITS.fullmatch(t):
            return _withheld(f"kind integer, but {value[:40]!r} is not a base-10 integer")
        return _plain(t, "as_given")
    if c.kind == "enum" and c.accepted and not c.accepted_partial:
        if value in c.accepted:
            return _plain(value, "as_given")
        folded = [a for a in c.accepted if a.strip().casefold() == value.strip().casefold()]
        if len(folded) == 1:
            return _plain(folded[0], "listed_spelling")
        return _withheld(f"kind enum, but {value[:40]!r} is not one of {len(c.accepted)} accepted value(s)")
    if c.kind == "json":
        try:
            json.loads(value)
        except ValueError:
            return _withheld(f"kind json, but {value[:40]!r} does not parse as JSON")
    return _plain(value, "as_given")


def render(value, answer_format=None, *, question_text: str | None = None, ordered: bool = False,
           contract: Contract | None = None) -> Rendering:
    """`value` rendered in the form `answer_format` (a question's mapping, or None) states. `ordered`
    says the caller already put a list in the order the question asks (a synthesis handler), so no
    order axis is offered. `contract` skips reading the answer_format again."""
    c = contract if contract is not None else read(answer_format, question_text)
    if value is None:
        return _withheld("no value")
    if isinstance(value, (set, frozenset)):
        return _withheld("a set has no element order; pass a list in the order it was read")
    if isinstance(value, (list, tuple)):
        return _render_list(list(value), c, ordered)
    if isinstance(value, bool):
        if c.kind == "json":
            return _plain("true" if value else "false", "json")
        low = c.syntax.lower()
        if re.search(r"\btrue\b", low) and re.search(r"\bfalse\b", low) and "True" not in c.syntax:
            return _plain("true" if value else "false", "lower")
        return Rendering(OPTIONS, None, (("lower", "true" if value else "false"), ("title", "True" if value else "False")),
                         ("spelling",), "the contract does not state how a truth value is written")
    if isinstance(value, dict):
        if c.container in ("json_object", "json") or c.kind == "json":
            text = _compact(value)
            return _plain(text, "json") if text is not None else _withheld("the mapping is not JSON")
        return _withheld(f"a mapping, and the contract (kind {c.kind or 'none'}) asks no JSON object")
    if isinstance(value, (int, float)):
        return _render_str(_item_text(value), c, ordered)
    if isinstance(value, str):
        return _render_str(value, c, ordered)
    return _withheld(f"a {type(value).__name__} has no rendering")


# ------------------------------------------------------------------------------------------- batches

@dataclass
class Batch:
    """render_answers' result, by answer id."""

    plain: dict = field(default_factory=dict)       # {aid: text to send}
    unsure: dict = field(default_factory=dict)      # {aid: Rendering with options}
    held: dict = field(default_factory=dict)        # {aid: why nothing is sent}
    passed: dict = field(default_factory=dict)      # {aid: an already-unsure string, untouched}

    def lines(self) -> list[str]:
        out = [f"PLAIN {a}: {v!r}" for a, v in self.plain.items()]
        out += [r.line(a) for a, r in self.unsure.items()]
        out += [f"HELD {a}: {why}" for a, why in self.held.items()]
        out += [f"PASSED {a}: already unsure" for a in self.passed]
        return out


def _qid(q: dict):
    for k in ("id", "qid", "answer_id"):
        if isinstance(q.get(k), str) and q[k]:
            return q[k]
    return None


def _qtext(q: dict) -> str:
    for k in ("question", "text", "prompt"):
        if isinstance(q.get(k), str):
            return q[k]
    return ""


def render_answers(questions, answers: dict, answer_ids=None) -> Batch:
    """Render every answer of a delivery from its own question's answer_format.

    questions   the attempt's question mappings (`id`/`qid`, `answer_format`, `question`/`text`)
    answers     {answer id: value} (lists, ints, strings, already-unsure strings)
    answer_ids  the answer id of each question by position, when it differs from the question's id

    An answer whose id no question carries is held (its contract is unknown). A question whose
    answer_format cannot be read raises AnswerFormatError naming the id: a broken contract is not a
    reason to send an unrendered answer."""
    if not isinstance(answers, dict):
        raise AnswerFormatError(f"answers is a {type(answers).__name__}, not a mapping")
    questions = list(questions or [])
    ids = list(answer_ids) if answer_ids is not None else [_qid(q) if isinstance(q, dict) else None for q in questions]
    if len(ids) != len(questions):
        raise AnswerFormatError(f"{len(ids)} answer ids for {len(questions)} questions")
    by_id = {}
    for q, aid in zip(questions, ids):
        if isinstance(q, dict) and aid:
            by_id[aid] = q
    out = Batch()
    for aid, value in answers.items():
        if isinstance(value, str) and value.startswith(UNSURE_PREFIX):
            out.passed[aid] = value
            continue
        q = by_id.get(aid)
        if q is None:
            out.held[aid] = "no question carries this id, so its answer_format is unknown"
            continue
        try:
            r = render(value, q.get("answer_format"), question_text=_qtext(q))
        except AnswerFormatError as e:
            raise AnswerFormatError(f"{aid}: {e}") from e
        if r.status == PLAIN:
            out.plain[aid] = r.value
        elif r.status == OPTIONS:
            out.unsure[aid] = r
        else:
            out.held[aid] = r.reason
    return out
