#!/usr/bin/env python3
"""Build judged_syntax.json: the (kind, syntax) pairs each Binary field was asked under in a saved attempt
that has a key.json (judged CORRECT): base and timed, history included; and, for the fields that state a
rule in the question (judged_forms.RULE: hcfg_storage and the d02 symbol fields), every question text they
were judged under, normalised. Offline, read-only on challenges/.

  .venv/bin/python solvers/binary/mk_judged_syntax.py            print whether the committed table is current
  .venv/bin/python solvers/binary/mk_judged_syntax.py --write    rewrite judged_syntax.json beside this file

answer_kinds.reform() reads "fields": a hex, digest or offset answer under a pair not listed for its field
is unsure (the Day 14 look-ahead, proposal 1 c). judged_forms.py reads both parts (the Day 18 look-ahead,
B1): a list or text answer under an unlisted pair whose syntax asks another form, and a rule field's answer
under a question text not listed, are unsure. Run it with --write after a day whose Binary attempts are
CORRECT, before the tree is tagged: a pair or a text the judge has taken since is then judged too.
tests/test_day14_binary.py holds "fields" against build(), tests/test_day18_binary_lookahead.py "texts"
against build_texts(), when the attempts are on disk.

The attempts are read from $CTF_WORKDIR, else the challenges/ folder labels.challenges_root()
names (a linked worktree reads its main checkout's).
"""
import collections
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TABLE = HERE / "judged_syntax.json"
LANE = "binary-reverse-engineering-*"


def norm(text) -> str:
    return " ".join(str(text or "").lower().split())


def tail(answer_id: str) -> str:
    return re.sub(r"^d\d\d_", "", re.sub(r"^set\d+\.", "", str(answer_id))).lower()


def _judged(challenges: Path):
    """(answer id, question) of every question of every judged Binary attempt, and the number of attempts."""
    rows, attempts = [], 0
    for path in sorted(Path(challenges).glob(f"day-*/{LANE}/**/attempt.json")):
        try:
            json.loads((path.parent / "key.json").read_text())
            attempt = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        attempts += 1
        questions = attempt.get("questions") or []
        ids = attempt.get("answer_ids") or [q.get("id") for q in questions]
        rows += [(answer_id, q) for answer_id, q in zip(ids, questions)]
    return rows, attempts


def build(challenges: Path) -> tuple:
    """({field tail: sorted [[kind, syntax], ...]}, the number of judged attempts read)."""
    fields = collections.defaultdict(set)
    rows, attempts = _judged(challenges)
    for answer_id, q in rows:
        fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        fields[tail(answer_id)].add((norm(fmt.get("kind")), norm(fmt.get("syntax"))))
    return {k: sorted(map(list, v)) for k, v in sorted(fields.items())}, attempts


def build_texts(challenges: Path) -> dict:
    """{slot: sorted [normalised question text, ...]} of every field's judged questions (judged_forms.text_slot:
    the rule field for a rule field, the field's tail for any other), the texts that only ask left out
    (judged_forms.text_kept: the lane's generic sentence, `What is <id>?`, and for a rule field a text with no
    rule word). Since the Day 19 look-ahead (B1 b) every field's, not only the rule fields'."""
    sys.path.insert(0, str(HERE))
    import judged_forms
    texts = collections.defaultdict(set)
    for answer_id, q in _judged(challenges)[0]:
        text = judged_forms.norm_text(q.get("question"))
        if judged_forms.text_kept(answer_id, text):
            texts[judged_forms.text_slot(answer_id)].add(text)
    return {k: sorted(v) for k, v in sorted(texts.items())}


def challenges_dir() -> Path:
    sys.path.insert(0, str(HERE.parent / "common"))
    import labels
    return Path(labels.challenges_root())


def main(argv) -> int:
    challenges = challenges_dir()
    fields, attempts = build(challenges)
    if not attempts:
        print(f"mk_judged_syntax.py: no judged Binary attempt under {challenges}")
        return 1
    texts = build_texts(challenges)
    current = json.loads(TABLE.read_text()) if TABLE.exists() else {}
    if "--write" in argv:
        about = ("answer_kinds.reform(): a hex, digest or offset answer under a (kind, syntax) pair not listed for "
                 "its field is unsure. judged_forms.py: a list or text answer under an unlisted pair whose syntax "
                 "asks another form, and a rule field's answer under a question text not listed in `texts`, are "
                 f"unsure. Built by solvers/binary/mk_judged_syntax.py from {attempts} judged attempts.")
        TABLE.write_text(json.dumps({"_about": about, "fields": fields, "texts": texts}, indent=1) + "\n")
        print(f"wrote {TABLE.name}: {len(fields)} fields, {sum(map(len, fields.values()))} pairs, "
              f"{sum(map(len, texts.values()))} rule texts of {len(texts)} fields from {attempts} attempts")
        return 0
    same = current.get("fields") == fields and current.get("texts") == texts
    print(f"{TABLE.name} is {'current' if same else 'NOT current'}: {len(fields)} fields, "
          f"{sum(map(len, fields.values()))} pairs, {sum(map(len, texts.values()))} rule texts from {attempts} "
          "judged attempts")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
