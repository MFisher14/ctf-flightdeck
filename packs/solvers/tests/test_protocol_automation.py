from __future__ import annotations

import json

import pytest

from solvers.toolkits import protocol_automation as P


TRANSCRIPT = """\
S> Round 1: What is 2 + 3?
C> 5
S> Round 2: What is 10 + 20?
C> 30
S> Round 3: What is 7 + 8?
"""


def test_saved_transcript_inference_repeated_states_and_inert_scaffold():
    report = P.infer_protocol(TRANSCRIPT)
    assert len(report["rounds"]) == 3 and len(report["states"]) == 1
    assert report["rounds"][0]["recorded_response_shape"] == "integer"
    assert report["sent"] is False and report["driver_plan"]["network_enabled"] is False
    scaffold = P.render_inert_scaffold(report["driver_plan"])
    low = scaffold.lower()
    assert "candidate_answer" in scaffold and "sent': false" in low
    assert "socket" not in low and "connect(" not in low
    namespace = {}
    exec(scaffold, namespace)
    classified = namespace["classify_saved_receive"]("round 99: what is 1 + 1?")
    assert classified["state"] == "state_0" and classified["sent"] is False


def test_json_and_ansi_transcripts_are_normalized_without_transport():
    value = {"messages": [
        {"role": "assistant", "content": "\x1b[31mPrime 10?\x1b[0m"},
        {"role": "user", "content": "29"},
    ]}
    events = P.parse_transcript(value)
    assert events == [
        {"direction": "recv", "text": "Prime 10?", "source_index": 0},
        {"direction": "send", "text": "29", "source_index": 1},
    ]


def test_plain_delimiters_preserve_continuations_and_do_not_split_inner_markers():
    events = P.parse_transcript("recv: first\ninner S> marker\nsend: answer\ncontinued")
    assert events == [
        {"direction": "recv", "text": "first\ninner S> marker", "source_index": 0},
        {"direction": "send", "text": "answer\ncontinued", "source_index": 2},
    ]


def test_finite_differences_and_exact_recurrence_have_holdout_replay():
    polynomial = P.finite_difference_predict([0, 1, 4, 9, 16], count=3)
    assert polynomial["degree"] == 2 and polynomial["predictions"] == [25, 36, 49]
    assert polynomial["holdout_verified"] is True

    fibonacci = P.exact_recurrence_predict([0, 1, 1, 2, 3, 5, 8, 13], count=3)
    assert fibonacci["order"] == 2 and fibonacci["coefficients"] == [1, 1]
    assert fibonacci["predictions"] == [21, 34, 55]
    with pytest.raises(P.Refuse):
        P.exact_recurrence_predict([1, 4, 2, 9, 7, 3, 20])
    constant = P.finite_difference_predict([7, 7, 7, 7], count=2)
    assert constant["degree"] == 0 and constant["predictions"] == [7, 7]
    rational = P.exact_recurrence_predict([16, 8, 4, 2, 1], count=1)
    assert rational["coefficients"] == [{"numerator": 1, "denominator": 2}]
    assert rational["predictions"] == [{"numerator": 1, "denominator": 2}]
    with pytest.raises(P.Refuse, match="computational bound"):
        P.exact_recurrence_predict(list(range(P.MAX_RECURRENCE_TERMS + 1)))
    with pytest.raises(P.Refuse, match="bit-work"):
        P.exact_recurrence_predict([1 << 4000] * 300)


def test_modular_recurrence_and_generalized_crt_verify_every_value():
    modular = P.berlekamp_massey([0, 1, 1, 2, 3, 5, 8, 13], 101, count=2)
    assert modular["coefficients"] == [1, 1] and modular["predictions"] == [21, 34]
    assert modular["full_replay_verified"] is True and modular["holdout_verified"] is True
    with pytest.raises(P.Refuse, match="prime"):
        P.berlekamp_massey([1, 2, 3], 100)
    with pytest.raises(P.Refuse, match="holdout"):
        P.berlekamp_massey([0, 1, 1, 2, 3, 5, 99], 101)

    classic = P.crt([[2, 3], [3, 5], [2, 7]])
    assert classic == {"value": 23, "modulus": 105, "verified": True,
                       "candidate_only": True, "requires_human_review": True}
    generalized = P.crt([[2, 6], [8, 14]])
    assert generalized["verified"] and generalized["value"] % 6 == 2 and generalized["value"] % 14 == 8
    redundant = P.crt([[2, 6], [2, 3]])
    assert redundant["value"] == 2 and redundant["modulus"] == 6
    with pytest.raises(P.Refuse, match="inconsistent"):
        P.crt([[0, 2], [1, 4]])
    with pytest.raises(P.Refuse, match="invalid"):
        P.crt([[0, 1 << (P.MAX_BITS + 1)]])
    with pytest.raises(P.Refuse, match="invalid"):
        P.crt([[True, 3]])


def test_sequence_aggregator_never_selects_an_answer_and_bounds_inputs():
    report = P.solve_sequence([0, 1, 1, 2, 3, 5, 8, 13], modulus=101)
    assert report["answer"] is None and len(report["candidates"]) == 2
    assert all(row["candidate_only"] for row in report["candidates"])
    with pytest.raises(P.Refuse, match="3..4096"):
        P.solve_sequence([1, 2])
    with pytest.raises(P.Refuse, match="oversized"):
        P.solve_sequence([1, 2, 1 << (P.MAX_BITS + 1)])
    with pytest.raises(P.Refuse, match="prime"):
        P.solve_sequence([1, 2, 3, 4], modulus=100)


def test_scaffold_validates_state_shape_and_quotes_untrusted_text_as_data():
    with pytest.raises(P.Refuse, match="invalid plan state"):
        P.render_inert_scaffold({"network_enabled": False, "states": [{"name": 1}]})
    marker = "x'); __import__('os').environ['R5G_BAD']='1'; #"
    plan = {"network_enabled": False, "states": [{
        "name": "state_0", "expect_prefix": marker, "handler_lead": "unclassified",
    }]}
    scaffold = P.render_inert_scaffold(plan)
    namespace = {}
    exec(scaffold, namespace)
    assert namespace["classify_saved_receive"](marker)["state"] == "state_0"


def test_guarded_cli(tmp_path, capsys):
    assert P.main([]) == 2
    assert "protocol_automation:" in capsys.readouterr().err
    path = tmp_path / "sequence.json"
    path.write_text(json.dumps([0, 1, 4, 9, 16]), encoding="utf-8")
    assert P.main(["sequence", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["answer"] is None and output["candidates"][0]["predictions"] == [25]
