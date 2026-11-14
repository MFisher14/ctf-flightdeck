"""ctf answer-format contract | render | batch | synth -- the answer-format renderer (B-232; ctf/answerfmt/).

    python -m ctf answer-format contract FORMAT [--question TEXT] [--json]
                                    what the answer_format states (separator, order, container, ...)
    python -m ctf answer-format render FORMAT VALUE [--question TEXT] [--ordered] [--json]
                                    one value in the form FORMAT states: exit 0 plain, 3 options
                                    (an axis is open; the options are printed), 1 withheld
    python -m ctf answer-format batch QUESTIONS ANSWERS [--json]
                                    every answer of a delivery from its own question: exit 0 all plain,
                                    3 some unsure (none held), 1 any held
    python -m ctf answer-format synth QUESTION FILES_DIR [--json]
                                    a multi-file synthesis answer routed by its answer-id suffix:
                                    exit 0 plain, 3 options, 1 withheld or no handler routes the id

FORMAT, VALUE, QUESTIONS, ANSWERS and QUESTION are JSON text or @path (a file of JSON). QUESTIONS is a
list of questions or a body with "questions" (and optional "answer_ids"); ANSWERS is {id: value} or
{"answers": {...}}. QUESTION is one question mapping (`id`, `question`, `answer_format`). Every input
is data: nothing is executed, nothing is sent. Exit 2 on unusable input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..answerfmt import AnswerFormatError, OPTIONS, PLAIN, read, render, render_answers
from ..answerfmt import synth as _synth

HELP = "render answers from their answer_format (separator, list order axis, synthesis by id suffix)"


class _Input(ValueError):
    pass


def _json(raw: str, what: str):
    try:
        text = Path(raw[1:]).read_text(encoding="utf-8") if raw.startswith("@") else raw
    except OSError as e:
        raise _Input(f"{what}: cannot read {raw[1:]}: {e.strerror or e}") from e
    try:
        return json.loads(text)
    except ValueError as e:
        raise _Input(f"{what}: not JSON ({e})") from e


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    c = sp.add_parser("contract", help="what an answer_format states")
    c.add_argument("format")
    c.add_argument("--question", default=None, help="the question text (an order may be stated there)")
    c.add_argument("--json", action="store_true")
    r = sp.add_parser("render", help="one value in the form an answer_format states")
    r.add_argument("format")
    r.add_argument("value")
    r.add_argument("--question", default=None)
    r.add_argument("--ordered", action="store_true", help="the list is already in the asked order")
    r.add_argument("--json", action="store_true")
    b = sp.add_parser("batch", help="every answer of a delivery from its own question")
    b.add_argument("questions")
    b.add_argument("answers")
    b.add_argument("--json", action="store_true")
    s = sp.add_parser("synth", help="a multi-file synthesis answer routed by answer-id suffix")
    s.add_argument("question")
    s.add_argument("files_dir")
    s.add_argument("--json", action="store_true")


def _code(status: str) -> int:
    return 0 if status == PLAIN else 3 if status == OPTIONS else 1


def _print_rendering(r, aid: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps(r.describe()))
        return
    print(r.line(aid))
    for name, text in r.options if r.status == OPTIONS else ():
        print(f"  {name}: {text!r}")


def _fmt(raw: str):
    f = _json(raw, "FORMAT")
    if f is not None and not isinstance(f, dict):
        raise _Input("FORMAT: an answer_format is a JSON object (or null)")
    return f


def run(args: argparse.Namespace) -> int:
    try:
        if args.action == "contract":
            c = read(_fmt(args.format), args.question)
            d = c.describe()
            if args.json:
                print(json.dumps(d))
            else:
                for k, v in d.items():
                    print(f"{k}: {v!r}")
            return 0
        if args.action == "render":
            r = render(_json(args.value, "VALUE"), _fmt(args.format), question_text=args.question,
                       ordered=args.ordered)
            _print_rendering(r, "value", args.json)
            return _code(r.status)
        if args.action == "batch":
            qs = _json(args.questions, "QUESTIONS")
            ids = None
            if isinstance(qs, dict):
                ids = qs.get("answer_ids")
                qs = qs.get("questions")
            if not isinstance(qs, list):
                raise _Input("QUESTIONS: a list of questions or a body with 'questions'")
            if ids is not None and (not isinstance(ids, list) or len(ids) != len(qs)):
                raise _Input("QUESTIONS: 'answer_ids' must be a list as long as 'questions'")
            ans = _json(args.answers, "ANSWERS")
            if isinstance(ans, dict) and isinstance(ans.get("answers"), dict):
                ans = ans["answers"]
            if not isinstance(ans, dict):
                raise _Input("ANSWERS: a JSON object {answer id: value}")
            out = render_answers(qs, ans, answer_ids=ids)
            if args.json:
                print(json.dumps({"plain": out.plain, "unsure": {a: r.describe() for a, r in out.unsure.items()},
                                  "held": out.held, "passed": sorted(out.passed)}))
            else:
                for line in out.lines():
                    print(line)
                print(f"ANSWER-FORMAT plain={len(out.plain)} unsure={len(out.unsure)} held={len(out.held)} "
                      f"passed={len(out.passed)}")
            return 1 if out.held else 3 if out.unsure else 0
        if args.action == "synth":
            q = _json(args.question, "QUESTION")
            if not isinstance(q, dict):
                raise _Input("QUESTION: one question mapping")
            aid = next((q[k] for k in ("id", "qid", "answer_id") if isinstance(q.get(k), str)), "")
            text = next((q[k] for k in ("question", "text", "prompt") if isinstance(q.get(k), str)), "")
            r = _synth.answer(aid, text, q.get("answer_format"), _synth.files_from_dir(args.files_dir))
            _print_rendering(r, aid or "?", args.json)
            return _code(r.status)
    except (_Input, AnswerFormatError, _synth.SynthError) as e:
        print(f"ctf answer-format: {e}", file=sys.stderr)
        return 2
    print(f"ctf answer-format: unknown action {args.action!r}", file=sys.stderr)
    return 2
