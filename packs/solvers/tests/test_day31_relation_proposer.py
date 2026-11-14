#!/usr/bin/env python3
"""Finale coverage: relation digest groups are byte-derived candidates, never plain guesses."""
import hashlib
import importlib.util
import io
import json
import sys
import time
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import labels  # noqa: E402
import proposer_enum as pe  # noqa: E402

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(f"{'pass' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))


def archive(rows):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for name, body in rows:
            z.writestr(name, body)
    return out.getvalue()


def question(digest="sha256", member="cluster-001.zip"):
    qid = f"cluster-001-relation-identical-{digest}-groups"
    return {
        "qid": qid,
        "answer_id": qid,
        "member": member,
        "question": f"Inspect `{member}`. Determine relation.identical_{digest}_groups for {member}.",
        "answer_format": {"kind": "json", "syntax": "compact JSON array of duplicate member groups"},
        "normalization": "exact",
    }


def propose(blob, digest="sha256", files=None, q=None):
    q = q or question(digest)
    files = files or {q["member"]: blob}
    ctx = {"set": 0, "delivery_name": "evidence.zip", "delivery": b"", "attempt": {},
           "lane": "metadata-forensics", "open": [q["qid"]], "shipped": {}, "rejected": {}, "budget_s": 5}
    return pe.propose([q], files, ctx, time.time() + 5).get(q["qid"], [])


ROWS = [
    ("zulu-02.bin", b"zulu"),
    ("alpha-02.txt", b"alpha"),
    ("unique.dat", b"unique"),
    ("zulu-01.bin", b"zulu"),
    ("alpha-01.txt", b"alpha"),
]
TRUTH = '[["alpha-01","alpha-02"],["zulu-01","zulu-02"]]'


def test_sha256_and_order():
    first = propose(archive(ROWS))
    shuffled = propose(archive(list(reversed(ROWS))))
    check("sha256 truth is the first byte-derived rendering", first and first[0][1] == TRUTH, first[:3])
    check("central-directory shuffling leaves the canonical candidate unchanged",
          shuffled and shuffled[0][1] == TRUTH, shuffled[:3])
    wrapped = pe.as_candidates("metadata", question()["qid"], first)
    parsed = labels.parse(wrapped)
    check("production form is unsure candidates, never a plain answer",
          parsed is not None and parsed.options and parsed.options[0][1] == TRUTH, wrapped[:100])


def test_digest_variants_and_guards():
    crc = propose(archive(ROWS), "crc32")
    check("novel crc32 relation uses the same proved partition", crc and crc[0][1] == TRUTH, crc[:3])

    collision_rows = [("a/same.txt", b"x"), ("b/same.bin", b"x")]
    collision = propose(archive(collision_rows))
    names = [n for n, _ in collision]
    path_truth = '[["a/same.txt","b/same.bin"]]'
    check("stem collisions suppress lossy stem candidates but retain exact paths",
          not any("stems_" in n for n in names) and path_truth in [v for _, v in collision], collision[:5])

    damaged = propose(archive(ROWS)[:-7])
    check("damaged archives produce no relation candidate",
          not [n for n, _ in damaged if n.startswith("relation:")], damaged[:4])

    q = question(member=None)
    q.pop("member")
    ambiguous = propose(b"", files={"one.zip": archive(ROWS), "two.zip": archive(ROWS)}, q=q)
    check("an unnamed choice between two archives is refused",
          not [n for n, _ in ambiguous if n.startswith("relation:")], ambiguous[:4])


def test_bare_digest_array_pruned():
    fam = pe.families()
    spec = pe.Spec(question(), {"lane": "metadata-forensics"})
    pool = pe.Pool(spec, [])
    values = [hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"b").hexdigest()]
    pool.add("enum:bare_digest_array", json.dumps(values, separators=(",", ":")), 99)
    fam.prune_relation_group_noise(spec, pool)
    check("a groups property never receives a bare array of digest literals", not pool.items, pool.items)


if __name__ == "__main__":
    test_sha256_and_order()
    test_digest_variants_and_guards()
    test_bare_digest_array_pruned()
    if not all(RESULTS):
        raise SystemExit(1)
    print(f"day31 relation proposer: {len(RESULTS)} passed")
