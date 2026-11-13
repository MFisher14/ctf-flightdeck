#!/usr/bin/env python3
"""Day 31: a C# nullable directive is not an LYR payload continuation.

The specimen is inert text.  It goes through the real Script ``solve_set`` entry point; nothing in
it is executed.  Negative controls keep the Day-27 wrapped-prefix guard fail-closed.
"""
import base64
import contextlib
import io
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SA = REPO / "solvers" / "script-analysis"
COMMON = REPO / "solvers" / "common"
for path in (SA, COMMON):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import analyze  # noqa: E402
import day23_fold  # noqa: E402
import labels  # noqa: E402


PLAN = (
    "v=3|language=csharp_script|role=benign_utility|verdict=benign|attack=none|"
    "adapter=local_parser|host_profile=standalone|obfuscation_profile=b64_frag_b64|"
    "stage_profile=cobalt_ladder|next_language=rust|stage_count=3|"
    "steps=decode_embedded,build_schedule,return_configuration|campaign_id=CSHARP_SCRIPT-9dc2a9e8|"
    "url=https://csharp_script-9dc2a9e846.example.invalid/stage|"
    "file_path=/tmp/huntress-csharp_script/.9dc2a9e84664d2e3.stage"
)
_INNER = base64.b64encode(PLAN.encode()).decode()
PAYLOAD = base64.b64encode(".".join(_INNER[i:i + 24] for i in range(0, len(_INNER), 24)).encode()).decode()
MEMBER = "polyglot-csharp_script-staged-chain.csx"
QUESTIONS = [
    {
        "id": "polyglot-csharp_script-31c0de-role",
        "qid": "polyglot-csharp_script-31c0de-role",
        "member": MEMBER,
        "artifact": "evidence.zip -> " + MEMBER,
        "question": "Recover the role recorded in the decoded analysis descriptor.",
        "answer_format": {"kind": "enum", "accepted_values": ["benign_utility", "staged_chain"]},
    },
    {
        "id": "polyglot-csharp_script-31c0de-steps",
        "qid": "polyglot-csharp_script-31c0de-steps",
        "member": MEMBER,
        "artifact": "evidence.zip -> " + MEMBER,
        "question": "Recover the ordered behavior graph using > separators.",
        "answer_format": {"kind": "ordered_tokens", "syntax": "exact tokens joined by >"},
    },
    {
        "id": "polyglot-csharp_script-31c0de-stage-count",
        "qid": "polyglot-csharp_script-31c0de-stage-count",
        "member": MEMBER,
        "artifact": "evidence.zip -> " + MEMBER,
        "question": "Recover the exact number of modeled stages.",
        "answer_format": {"kind": "integer", "syntax": "base-10 integer"},
    },
]


def solve(text, member=MEMBER):
    questions = [dict(q, member=member, artifact="evidence.zip -> " + member) for q in QUESTIONS]
    with contextlib.redirect_stderr(io.StringIO()):
        return analyze.solve_set(questions, {member: text.encode()}, {}) or {}


def fixture(payload=PAYLOAD, directive="#nullable enable", literal=PAYLOAD, extra=""):
    return (
        f"// HUNTRESS_ANALYSIS_V1:LYR-b64_frag_b64-{payload}\n"
        f"{directive}\n"
        f'string descriptor_31c0de = "{literal}";\n'
        f"{extra}"
    )


def test_real_solve_set_accepts_proven_nullable_boundary():
    got = solve(fixture())
    assert got[QUESTIONS[0]["qid"]] == "benign_utility", got
    steps = labels.parse(got[QUESTIONS[1]["qid"]])
    assert steps is not None and (
        "gt", "decode_embedded>build_schedule>return_configuration"
    ) in steps.options, got
    assert got[QUESTIONS[2]["qid"]] == "3", got


def test_boundary_requires_csx_one_equal_literal_and_two_copies():
    controls = (("different literal", fixture(literal=PAYLOAD[:-4] + "AAAA")),)
    for label, text in controls:
        assert day23_fold._rewrite(text, MEMBER) is None, label
    assert day23_fold._rewrite(fixture(), "same-shape.bsh") is None

    nine = fixture(extra="".join(
        f'string descriptor_extra_{i} = "{PAYLOAD}";\n' for i in range(2, 10)
    ))
    assert day23_fold._rewrite(nine, MEMBER) is None


def test_redundant_identical_literals_are_candidate_only_with_truth():
    text = fixture(extra=f'string descriptor_second = "{PAYLOAD}";\n')
    assert day23_fold._rewrite(text, MEMBER) is not None
    got = solve(text)
    truths = {
        QUESTIONS[0]["qid"]: "benign_utility",
        QUESTIONS[1]["qid"]: "decode_embedded>build_schedule>return_configuration",
        QUESTIONS[2]["qid"]: "3",
    }
    for qid, truth in truths.items():
        assert got.get(qid) != truth, (qid, got.get(qid))
        parsed = labels.parse(got.get(qid))
        assert parsed is not None and any(value == truth for _name, value in parsed.options), (qid, got.get(qid))


if __name__ == "__main__":
    test_real_solve_set_accepts_proven_nullable_boundary()
    test_boundary_requires_csx_one_equal_literal_and_two_copies()
    test_redundant_identical_literals_are_candidate_only_with_truth()
    print("day31 script nullable boundary: 3 passed")
