"""B-216 on the saved Huntress Binary attempts: every answer speed_solver gives equals the judged key.

Reads $CTF_REAL_CHALLENGES (ctf.paths.saved_challenges_root(); read only): every
day-NN/binary-*/[time_trial|mastery/...]/ folder with attempt.json, key.json and artifact/*.zip. The delivery is
opened in memory with the lane's own archive passwords (members._decrypt); no file there is executed or written.
Not run when the variable is unset; set to a missing folder, the FileNotFoundError fails it.
"""
import json

import pytest

from ctf import paths

import members as lane_members
import speed_solver as sp


def _sets(root):
    for att in sorted(root.glob("day-*/binary-*/**/attempt.json")):
        base = att.parent
        zips = sorted((base / "artifact").glob("*.zip")) if (base / "artifact").is_dir() else []
        if (base / "key.json").is_file() and zips:
            yield base, att, base / "key.json", zips[0]


def test_speed_solver_agrees_with_every_saved_binary_key():
    root = paths.saved_challenges_root()
    if root is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved past-event attempts)")
    sets = list(_sets(root))
    if not sets:
        pytest.skip(f"no saved Binary attempt with key.json and a delivery under {root}")
    answered, wrong, unread = 0, [], []
    for base, att, key, delivery in sets:
        questions = json.loads(att.read_text()).get("questions") or []
        judged = json.loads(key.read_text()).get("answers") or {}
        blob = delivery.read_bytes()
        files = lane_members._decrypt(blob)
        if not files:
            unread.append(str(base.relative_to(root)))
            continue
        groups = {}
        for q in questions:
            q = dict(q, qid=q.get("id"))
            groups.setdefault(q["qid"].split("_", 1)[0].lower(), []).append(q)
        for prefix, qs in groups.items():
            got, _ = sp.solve(prefix, qs, files, {"delivery": blob, "delivery_name": delivery.name})
            for qid, value in got.items():
                if value is None or qid not in judged:
                    continue
                answered += 1
                if str(value).strip() != str(judged[qid]).strip():
                    wrong.append((str(base.relative_to(root)), qid, str(value)[:40], str(judged[qid])[:40]))
    assert not unread, f"deliveries the lane's passwords do not open: {unread[:5]}"
    assert answered > 0, "the speed solver answered no id of any saved set"
    assert not wrong, f"{len(wrong)} of {answered} answers differ from the judged key: {wrong[:10]}"
