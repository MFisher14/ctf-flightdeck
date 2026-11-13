#!/usr/bin/env python3
"""Day 31: speculative decoder fragments never become proposer candidates."""
import base64
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import proposer_enum as pe  # noqa: E402


def question(qid, text):
    return {
        "qid": qid,
        "answer_id": qid,
        "question": text,
        "answer_format": {"kind": "exact_text", "syntax": "exact artifact-derived value only"},
        "normalization": "trim",
        "member": "sample.csx",
    }


def proposed(record, q):
    encoded = base64.b64encode(record.encode()).decode()
    # Deliberately an unquoted run: quoted literals are a declared whole value,
    # while the false positives under test come from speculative run carving.
    files = {"sample.csx": f"payload({encoded});".encode()}
    ctx = {"open": [q["qid"]], "lane": "script-analysis", "shipped": {}, "rejected": {}}
    return pe.propose([q], files, ctx, time.time() + 3).get(q["qid"], [])


def test_fragments():
    profile = question("sample-stage-profile", "Recover the staging profile name recorded in sample.csx.")
    assert ("kv:tion_profile", "b64_f") not in proposed("tion_profile=b64_f", profile)
    path_rows = proposed("tage|file_path=/tm", question("sample-file-path", "Recover the exact file path."))
    assert all(value != "/tm" for _name, value in path_rows)

    complete = "role=downloader|stage_profile=layered_bridge|stage_count=3"
    assert proposed(complete, profile)[0][1] == "layered_bridge"

    url = "https://node-31.example.invalid/finale/component"
    one = proposed(f"url={url}", question("sample-url", "Recover the exact URL."))
    assert any(value == url for _name, value in one)


def main():
    test_fragments()
    print("day31 proposer fragments: 4 passed")


if __name__ == "__main__":
    main()
