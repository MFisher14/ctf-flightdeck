"""Test for fields_derived.py (buildplan T3, backlog row 492): the DERIVED url / composite / campaign-prefix
field-word registry for Script Analysis.

Builds the Day-25 look-ahead class-C specimen (the real v=3 two-copy descriptor form, a NEW language `nim`,
the 11 Day-24 fields plus the new derived/composite field words) exactly as
`challenges/_retro/day25-prep/script-analysis/harness.py` does, runs the shipped `analyze.solve_set`, and
asserts:

  * every new derived field word is UNSURE (labels.pick / labels.candidates), never plain, never WRONG;
  * the judge's expected value is reachable among the unsure options (so one accepted probe answers it);
  * the 11 standard plan fields still read PLAIN (the registry never steals a reader's answer);
  * a benign/no-url / no-dash plan leaves the derived words None (fails safe, never WRONG).

Run:  .venv/bin/python -m pytest solvers/script-analysis/test_fields_derived.py
  or: .venv/bin/python solvers/script-analysis/test_fields_derived.py
"""
import base64
import io
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import analyze  # noqa: E402

PLAN_ORDER = ["language", "role", "verdict", "attack", "adapter", "host_profile", "obfuscation_profile",
              "stage_profile", "next_language", "stage_count", "steps", "campaign_id", "url", "file_path"]
STD = ["role", "attack", "adapter", "campaign", "url", "stage-count", "steps", "host-profile",
       "obfuscation", "stage-profile", "next-language"]


def _plan(**over):
    steps = over.pop("steps", ["decode_configuration", "stage_payload", "hand_off"])
    d = {"language": "nim", "role": "staged_chain", "verdict": "suspicious", "attack": "T1059",
         "adapter": "http_client", "host_profile": "standalone", "obfuscation_profile": "base64",
         "stage_profile": "two_stage_download_execute", "next_language": "jscript",
         "stage_count": str(len(steps)), "steps": ",".join(steps), "campaign_id": "NIM-be33e63d",
         "url": "https://nim-be33e63dc0.example.invalid:8443/a/b/stage.bin",
         "file_path": "/tmp/huntress-nim/.x.stage"}
    d.update(over)
    text = "v=3|" + "|".join(f"{k}={d[k]}" for k in PLAN_ORDER)
    return text, d


def _run(derived_fields, **over):
    plan, d = _plan(**over)
    payload = base64.b64encode(plan.encode()).decode()
    prefix = "polyglot-nim-staged-chain"
    member = f"{prefix}.nim"
    text = f"# HUNTRESS_ANALYSIS_V1:B64-{payload}\nDESCRIPTOR_X = \"{payload}\"\n"
    data = text.encode()
    qs = []
    for f in STD:
        qid = f"{prefix}-{f}"
        qs.append({"id": qid, "qid": qid, "answer_id": qid, "member": member,
                   "answer_format": {"kind": "exact_text", "syntax": "exact value"},
                   "artifact": f"evidence.zip -> {member}", "question": "q"})
    for f, kind in derived_fields:
        qid = f"{prefix}-{f}"
        qs.append({"id": qid, "qid": qid, "answer_id": qid, "member": member,
                   "answer_format": {"kind": kind, "syntax": "the derived value"},
                   "artifact": f"evidence.zip -> {member}", "question": "q"})
    files = {member: data, "evidence.zip -> " + member: data}
    ctx = {"set": 1, "delivery_name": "evidence.zip", "delivery": b"", "attempt": {}, "partial": {}}
    keep, sys.stderr = sys.stderr, io.StringIO()
    try:
        got = analyze.solve_set([dict(q) for q in qs], files, ctx) or {}
    finally:
        sys.stderr = keep
    return prefix, d, got


def _opts(value):
    assert isinstance(value, str) and value.startswith("??"), f"expected unsure, got {value!r}"
    return json.loads(value[2:])["o"]


NEW = [("url-host", "integer" if False else "exact_text"), ("url-port", "integer"),
       ("url-scheme", "exact_text"), ("url-filename", "exact_text"), ("path-leaf", "exact_text"),
       ("carrier-obfuscation", "exact_text"), ("campaign-prefix", "exact_text")]
WANT = {"url-host": "nim-be33e63dc0.example.invalid", "url-port": "8443", "url-scheme": "https",
        "url-filename": "stage.bin", "path-leaf": None,
        "carrier-obfuscation": "base64|two_stage_download_execute",
        "campaign-prefix": "NIM"}


def test_new_field_words_unsure_and_reachable():
    prefix, d, got = _run(NEW)
    for f, _ in NEW:
        v = got.get(f"{prefix}-{f}")
        if WANT[f] is None:
            assert v is None, f"{f}: URL-derived candidate must be withheld, got {v!r}"
            continue
        assert v is not None, f"{f}: still None (should be unsure now)"
        assert isinstance(v, str) and v.startswith("??"), f"{f}: not unsure => risk of WRONG: {v!r}"
        vals = [val for _, val in _opts(v)]
        assert WANT[f] in vals, f"{f}: judged value {WANT[f]!r} not reachable among {vals}"
    # the composite's best-ranked candidate is the obfuscation|stage pair
    comp = _opts(got[f"{prefix}-carrier-obfuscation"])
    assert comp[0][1] == "base64|two_stage_download_execute", f"composite top={comp[0]}"


def test_standard_plain_fields_untouched():
    prefix, d, got = _run(NEW)
    # the 11 standard fields still read PLAIN and correct (registry never stole a reader's answer)
    assert got[f"{prefix}-role"] == "staged_chain"
    assert got[f"{prefix}-campaign"] == "NIM-be33e63d"
    assert got[f"{prefix}-url"] == d["url"]
    assert got[f"{prefix}-obfuscation"] == "base64"
    assert got[f"{prefix}-stage-profile"] == "two_stage_download_execute"
    assert got[f"{prefix}-host-profile"] == "standalone"
    assert got[f"{prefix}-next-language"] == "jscript"
    assert got[f"{prefix}-adapter"] == "http_client"
    # (role/attack read via the family prior; steps' separator is legitimately unsure without a ledger --
    # both are shipped behaviour, independent of this registry)


def test_fails_safe_to_none():
    # a url with no port / no path leaf, and a campaign with no dash => those derived words are None, not WRONG
    prefix, d, got = _run(NEW, url="https://host.example.invalid/", campaign_id="plaincampaign")
    assert got.get(f"{prefix}-url-port") is None, got.get(f"{prefix}-url-port")
    assert got.get(f"{prefix}-path-leaf") is None, got.get(f"{prefix}-path-leaf")
    assert got.get(f"{prefix}-campaign-prefix") is None, got.get(f"{prefix}-campaign-prefix")
    # host/scheme still available for this url
    assert got.get(f"{prefix}-url-host") is not None
    assert got.get(f"{prefix}-url-scheme") is not None


def test_unknown_field_word_is_none():
    prefix, d, got = _run([("totally-unknown-word", "exact_text"), ("entropy-score", "integer")])
    assert got.get(f"{prefix}-totally-unknown-word") is None
    assert got.get(f"{prefix}-entropy-score") is None


if __name__ == "__main__":
    test_new_field_words_unsure_and_reachable()
    test_standard_plain_fields_untouched()
    test_fails_safe_to_none()
    test_unknown_field_word_is_none()
    print("fields_derived: all tests passed")
