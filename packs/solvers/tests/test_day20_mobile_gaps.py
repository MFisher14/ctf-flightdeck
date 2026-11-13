#!/usr/bin/env python
"""Day 20 gaps build, Mobile: the branch list with `when` back on (codec_search.WHEN_BRANCHES), never plain on
another document.

Item 6 of the Day 20 build was withdrawn because four reviews each found a header that chooses a branch by its
position: once the judge accepted `base64:when=release` under `mobile.codec/base64+branches_when#candidates`, a
variant whose header pointed at the other branch was answered PLAIN and WRONG. Now the candidate key carries the
fingerprint of the whole puzzle document (`when_fingerprint`: the full SHA-256 of its canonical JSON),
so an accepted name is plain only for the document it was judged on, and every other document stays a candidate
pick (probed on an untimed base or a no-deadline attempt, never inside a deadline, row 346).

  [K] the key's shape: `mobile.codec/<codec>+branches_<field>@doc-<sha256>#candidates`, release first
  [P] plain only for the same document, once its name is accepted; a swapped or re-valued variant stays unsure
  [R] the four reviews' position-choosing headers, each with an accepted name of the base: never plain, never wrong
  [O] an accepted name under the OLD key (no fingerprint) answers nothing plain
  [G] what still gives None: a selector, a top-level condition field, a second list, place labels, a non-empty data
  [S] scalar headers beside the list (hint, note, version) now give the candidate pick
  [L] the key is never cut by the label key's 64 characters (a long codec and the field `environment`)
  [T] seconds: a branch list of 8 items under xor solves in a few milliseconds
"""
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mobile_codec_env as T  # noqa: E402  (its environment: a private ledger, no token, no network)

C, labels = T.C, T.labels
b64, doc, apk, solve, options, check, fresh = T.b64, T.doc, T.apk, T.solve, T.options, T.check, T.fresh
KEY_RE = re.compile(r"^mobile\.codec/base64\+branches_when@doc-[0-9a-f]{64}#candidates$")


def learn(key, name):
    labels.learn(key, name, "accepted", attempt_id="t", answer_ids=["answer"])


def branch_doc(rel_data, dbg_data, order="dr", field="when", **more):
    rel, dbg = {field: "release", "data": b64(rel_data.encode())}, {field: "debuggable", "data": b64(dbg_data.encode())}
    items = [dbg, rel] if order == "dr" else [rel, dbg]
    return doc("base64", "", branches=items, **more)


def key_shape():
    real, fake = T.code_for("G1"), T.decoy_for("G1")
    fresh()
    out, _, _ = solve(apk(branch_doc(real, fake)))
    k, opts = options(out)
    check("[K] a when-branch list is a candidate pick under a fingerprinted key", labels.is_candidate(out)
          and bool(KEY_RE.match(k or "")), k)
    check("[K] ... the release-like condition first, its code the truth", opts[:1] == [("base64:when=release", real)], opts)
    check("[K] ... the hostile branch second", opts[1:2] == [("base64:when=debuggable", fake)], opts)
    short, _, _ = solve(apk(branch_doc(real, fake)), deliveries=5)
    check("[K] ... the same answer under a five-delivery Mastery's budget", short == out, short)
    same = C.when_fingerprint(branch_doc(real, fake)) == C.when_fingerprint(dict(reversed(list(branch_doc(real, fake).items()))))
    check("[K] the fingerprint does not depend on the JSON's key order", same)


def plain_same_doc_only():
    real, fake = T.code_for("G2"), T.decoy_for("G2")
    fresh()
    base = apk(branch_doc(real, fake))
    out, _, _ = solve(base)
    k, _ = options(out)
    learn(k, "base64:when=release")
    again, _, _ = solve(base)
    check("[P] accepted on the base: the same document replays plain, the truth", again == real, again)
    real2, fake2 = T.code_for("G2b"), T.decoy_for("G2b")
    v2, _, _ = solve(apk(branch_doc(real2, fake2)))
    check("[P] ... a variant with other codes (same fields) stays a candidate pick, never plain",
          labels.is_candidate(v2) and options(v2)[0] != k, (options(v2), k))
    v3, _, _ = solve(apk(branch_doc(real, fake, order="rd")))
    check("[P] ... the same branches in the other order: another key, unsure", labels.is_candidate(v3)
          and options(v3)[0] != k, options(v3))
    # the hostile branch is the real one on this variant: a candidate pick, both offered, never the decoy plain
    v4, _, _ = solve(apk(branch_doc(fake2, real2)))
    check("[P] ... a variant whose real code sits under the hostile condition: unsure, the truth offered",
          labels.is_candidate(v4) and real2 in [v for _, v in options(v4)[1]], options(v4))
    fresh()


def reviews_repro():
    """The four reviews' headers that choose a branch by position (fix1 to fix3 and the withdrawal note): accept the
    release name on a base with the header, then a variant with the items' codes swapped and the same header."""
    real, fake = T.code_for("G3"), T.decoy_for("G3")
    for field, value in (("hint", "the first entry is live"), ("hint", "use item 2"), ("hint", "Branch 2 is active"),
                         ("note", 1), ("version", 2), ("day", "use entry 2"), ("encoding", "the second entry is live"),
                         ("active_key", "1"), ("env_key", "2"), ("secret", "x"), ("key_index", 1), ("hint", 2),
                         ("description", "the debug build is the one the backend checks")):
        fresh()
        base = apk(branch_doc(real, fake, **{field: value}))
        out, _, _ = solve(base)
        if labels.is_candidate(out):
            learn(options(out)[0], "base64:when=release")
        # the swapped variant: the code the header picks moved to the other branch
        var, _, _ = solve(apk(branch_doc(fake, real, **{field: value})))
        check("[R] %s=%r: after an accepted name on the base, the swapped variant is never plain" % (field, value),
              var is None or labels.is_unsure(var), var)
    fresh()


def old_key():
    real, fake = T.code_for("G4"), T.decoy_for("G4")
    fresh()
    learn("mobile.codec/base64+branches_when#candidates", "base64:when=release")
    out, _, _ = solve(apk(branch_doc(real, fake)))
    check("[O] an accepted name under the old key (no fingerprint) answers nothing plain", labels.is_candidate(out), out)
    fresh()


def still_none():
    real, fake = T.code_for("G5"), T.decoy_for("G5")
    for field, value in (("use", "branches.1.data"), ("env", "debug"), ("env", "release"), ("when", "release"),
                         ("build_type", "debug"), ("other", ["a", "b"]), ("cfg", {"x": 1})):
        fresh()
        out, _, _ = solve(apk(branch_doc(real, fake, **{field: value})))
        check("[G] %s=%r beside the branches: no candidate pick of the branch list, never the decoy plain" % (field, value),
              (out is None or not labels.is_candidate(out)) and out != fake, options(out) if out else out)
    for field, labs in (("when", ("1", "2")), ("when", ("a", "b")), ("variant", ("debug", "release")),
                        ("when", ("beta", "release"))):
        T.none("[G] branches labelled %s=%s/%s" % ((field,) + labs),
               apk(doc("base64", "", branches=[{field: labs[0], "data": b64(fake.encode())},
                                               {field: labs[1], "data": b64(real.encode())}])))
    fresh()
    o, _, _ = solve(apk(doc("base64", b64(fake.encode()), branches=[{"when": "release", "data": b64(real.encode())},
                                                                     {"when": "debug", "data": b64(fake.encode())}])))
    check("[G] a non-empty top-level data beside the branches: no branch candidate pick",
          not labels.is_candidate(o) and not any(n.startswith("base64:when=") for n, _ in options(o)[1]), options(o))
    fresh()
    o2, _, _ = solve(apk(doc("base64", "", branches=[{"when": "release", "data": b64(real.encode())},
                                                     {"when": "debug", "data": b64(real.encode())}])))
    check("[G] branches that agree: no candidate pick (one code)", not labels.is_candidate(o2), o2)
    fresh()


def scalar_headers():
    real, fake = T.code_for("G6"), T.decoy_for("G6")
    for field, value in (("hint", "the release branch is what the store build shows"), ("note", 3), ("version", 2),
                         ("description", None), ("flag", True)):
        fresh()
        out, _, _ = solve(apk(branch_doc(real, fake, **{field: value})))
        check("[S] %s=%r beside the branches: the candidate pick, release first" % (field, value),
              labels.is_candidate(out) and options(out)[1][:1] == [("base64:when=release", real)], options(out))
    fresh()


def long_key():
    real, fake = T.code_for("G7"), T.decoy_for("G7")
    fresh()
    long_codec = "base64+reverse+reverse+reverse+reverse+reverse"
    d = doc(long_codec, "", branches=[{"environment": "debuggable", "data": b64(fake.encode()[::-1])},
                                      {"environment": "release", "data": b64(real.encode()[::-1])}])
    out, _, _ = solve(apk(d))
    k = options(out)[0] if out else None
    ok = k is None or re.search(r"@doc-[0-9a-f]{64}#candidates$", k) is not None
    check("[L] a long codec and the field `environment`: the key keeps the full fingerprint (or no pick)", ok, k)
    check("[L] the fingerprinted key carries the complete SHA-256",
          len(C.when_fingerprint(branch_doc(real, fake))) == 64)
    fresh()


def seconds():
    import base64 as B
    fresh()
    items = []
    for i in range(8):
        cond = ("release" if i == 3 else "debug_%d" % i)
        code = T.code_for("G8_%d" % i)
        items.append({"when": cond, "data": B.b64encode(bytes(c ^ 21 for c in code.encode())).decode()})
    blob = apk(doc("xor", "", key=21, branches=items))
    best = 9.0
    for _ in range(3):
        t0 = time.perf_counter()
        out, _, _ = solve(blob)
        best = min(best, time.perf_counter() - t0)
    check("[T] an 8-branch xor list solves in under 30 ms (%.1f ms), a candidate pick or None" % (best * 1e3),
          best < 0.03 and (out is None or labels.is_candidate(out)), out)
    fresh()


def when_on():
    check("[K] WHEN_BRANCHES is on", C.WHEN_BRANCHES is True)


PARTS = (when_on, key_shape, plain_same_doc_only, reviews_repro, old_key, still_none, scalar_headers, long_key, seconds)


@pytest.mark.parametrize("part", PARTS, ids=lambda f: f.__name__)
def test_day20_mobile_gaps(part):
    T.run_part(part)


def main():
    return T.run_parts(PARTS)


if __name__ == "__main__":
    sys.exit(main())
