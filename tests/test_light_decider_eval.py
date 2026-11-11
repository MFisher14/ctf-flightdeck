"""eval-local with a decider column (light.DeciderLight): `--engine decider --base-url URL`,
`--compare decider@URL` and `--threshold`, over real HTTP to the fake decider server
(fake_decider.py). The scorecard shows a decision model's unsure answers in a row of their own,
apart from the failures, and summary cases as n/a; one call per hint and judge case, said first.
"""

from __future__ import annotations

import json
import re
import socket

import pytest
import typer
from typer.testing import CliRunner

from ctf_flightdeck import light as L
from ctf_flightdeck import localmodel as lm
from ctf_flightdeck import localmodel_cli
from fake_decider import FakeDeciderServer, detail, picks

URL = "http://127.0.0.1:8000"
DESC = "A numbers station. There is a picture in it if you scan it slowly enough."
runner = CliRunner()


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def mount() -> typer.Typer:
    root = typer.Typer()
    root.add_typer(localmodel_cli.app)
    return root


def write_cases(path, *cases: lm.Case):
    path.write_text("\n".join(json.dumps({"kind": c.kind, "input": c.input, "expected": c.expected}) for c in cases) + "\n")
    return path


def hint_case(expected: str, description: str) -> lm.Case:
    return lm.Case("hint", {"description": description}, expected)


def judge_case(expected: str, steps) -> lm.Case:
    return lm.Case("judge", {"description": DESC, "technique": "sstv",
                             "steps": [{"command": c, "output": o} for c, o in steps]}, expected)


def summary_case() -> lm.Case:
    return lm.Case("summary", {"steps": [{"command": "ls", "output": "a.wav"}]}, "sstv")


def table(text: str) -> dict[str, list[str]]:
    out = {}
    for line in text.splitlines():
        cells = re.split(r"\s{2,}", line.strip())
        if cells and cells[0] in ("hint", "judge", "summary", "overall", "unsure", "refused", "failed", "no answer",
                                  "time per job", "cost per job", "cases"):
            out[cells[0]] = cells[1:]
    return out


def test_eval_local_scores_the_decider_beside_the_rules_with_unsure_apart_and_summaries_na(tmp_path):
    cases = write_cases(tmp_path / "cases.jsonl",
                        hint_case("sstv", "Decode the slow scan picture."),
                        hint_case("xor", "A repeating single-byte key."),
                        judge_case("yes", [("qsstv -i a.wav", "")]),
                        judge_case("no", [("strings a.wav", "")]),
                        summary_case())
    replies = [picks("sstv", 0.97), picks("xor", 0.5), picks("yes", 0.95), detail(500, "boom")]
    with FakeDeciderServer(replies) as server:
        result = runner.invoke(mount(), ["eval-local", "--engine", "decider", "--base-url", server.base_url,
                                         "--cases", str(cases)])
        assert len(server.asked()) == 4  # one call per hint and judge case, none for the summary, no retry
    assert result.exit_code == 0, result.output
    assert (f"flightdeck: decider at {server.base_url}: at most 4 calls to the decision model server, one per hint "
            "and judge case (no retries); its 1 summary case is n/a: a decision model writes no text; an answer "
            "below confidence 0.9 counts as unsure") in result.output
    rows = table(result.output)
    assert rows["cases"] == ["rules", f"decider {server.base_url}"]
    assert rows["hint"] == ["2", "2/2 100%", "1/1 100%"]  # the unsure xor is neither right nor wrong
    assert rows["judge"] == ["2", "2/2 100%", "1/2 50%"]  # the rules see qsstv; the decider's HTTP 500 scores wrong
    assert rows["summary"] == ["1", "n/a", "n/a"]  # not applicable, not a failure
    assert rows["overall"] == ["4", "4/4 100%", "2/3 67%"]
    assert rows["unsure"] == ["-", "1/4 25%"] and rows["failed"] == ["-", "1/4 25%"] and rows["no answer"] == ["-", "0/4 0%"]
    assert rows["cost per job"] == ["$0", "$0"] and rows["time per job"][1].endswith(("ms", "s"))
    assert ("unsure: the decision model's confidence was below its threshold, so in a run the rules' answer stands. "
            "An unsure job counts neither right nor wrong") in " ".join(result.output.split())


def scorecard(cases, *replies) -> dict[str, list[str]]:
    """The scorecard's rows for a decider column answering `replies`, one per hint or judge case."""
    with FakeDeciderServer(replies) as server:
        result = runner.invoke(mount(), ["eval-local", "--engine", "decider", "--base-url", server.base_url,
                                         "--cases", str(cases)])
    assert result.exit_code == 0, result.output
    return table(result.output)


def test_an_unsure_answer_is_neither_right_nor_wrong_so_the_accuracy_is_over_the_answers_it_was_sure_of(tmp_path):
    cases = write_cases(tmp_path / "cases.jsonl", hint_case("sstv", "Decode the slow scan picture."),
                        hint_case("xor", "A repeating single-byte key."))
    unsure = scorecard(cases, picks("sstv", 0.97), picks("xor", 0.5))  # sure and right; then unsure
    wrong = scorecard(cases, picks("sstv", 0.97), picks("sstv", 0.97))  # sure and right; then sure and wrong
    assert unsure["hint"] == ["2", "2/2 100%", "1/1 100%"] and unsure["unsure"] == ["-", "1/2 50%"]
    assert unsure["overall"] == ["2", "2/2 100%", "1/1 100%"]  # in a run the rules answer the unsure one
    assert wrong["hint"] == ["2", "2/2 100%", "1/2 50%"] and wrong["unsure"] == ["-", "0/2 0%"]


def test_a_kind_the_decider_was_unsure_of_throughout_says_so_and_is_not_n_a(tmp_path):
    cases = write_cases(tmp_path / "cases.jsonl", hint_case("sstv", "Decode the slow scan picture."),
                        judge_case("yes", [("qsstv -i a.wav", "")]), summary_case())
    rows = scorecard(cases, picks("sstv", 0.3), picks("yes", 0.95))
    assert rows["hint"] == ["1", "1/1 100%", "all unsure"]  # it ran the job: not "n/a", which is a job it does not do
    assert rows["judge"] == ["1", "1/1 100%", "1/1 100%"] and rows["summary"] == ["1", "n/a", "n/a"]
    assert rows["overall"] == ["2", "2/2 100%", "1/1 100%"] and rows["unsure"] == ["-", "1/2 50%"]


def test_eval_local_compares_a_decider_column_at_the_threshold_given(tmp_path):
    cases = write_cases(tmp_path / "cases.jsonl", hint_case("sstv", "Decode the slow scan picture."),
                        judge_case("yes", [("qsstv -i a.wav", "")]))
    with FakeDeciderServer([picks("sstv", 0.7), picks("yes", 0.65)]) as server:
        result = runner.invoke(mount(), ["eval-local", "--engine", "rules", "--compare", f"decider@{server.base_url}",
                                         "--threshold", "0.6", "--cases", str(cases)])
    assert result.exit_code == 0, result.output
    rows = table(result.output)
    assert rows["cases"] == ["rules", f"decider {server.base_url}"]
    assert rows["overall"] == ["2", "2/2 100%", "2/2 100%"] and rows["unsure"] == ["-", "0/2 0%"]
    assert "below confidence 0.6 counts as unsure" in result.output


def test_eval_local_without_a_decider_column_has_no_unsure_row():
    rules = lm.EvalReport("rules", (lm.CaseResult("hint", "x", "x", True),), 0, 0.0, "rules")
    model = lm.EvalReport("openai m", (lm.CaseResult("hint", "x", "x", True),), 0, 0.0, "openai")
    decider = lm.EvalReport("decider d", (lm.CaseResult("hint", "x", "y", False, answered=False, failure=L.UNSURE),),
                            0, 0.0, "decider")
    assert "unsure" not in table(lm.format_scorecard([rules, model]))
    rows = table(lm.format_scorecard([rules, model, decider]))
    assert rows["unsure"] == ["-", "-", "1/1 100%"]
    assert decider.unanswered == 0 and decider.unsure == 1  # unsure is counted apart from failures


def test_the_report_leaves_unsure_jobs_out_of_its_accuracy_and_counts_them_apart():
    unsure = lm.CaseResult("hint", "xor", "xor", False, answered=False, failure=L.UNSURE)  # leaned right: still not right
    decider = lm.EvalReport("decider d", (lm.CaseResult("hint", "sstv", "sstv", True), unsure,
                                          lm.CaseResult("judge", "no", "yes", False),
                                          lm.CaseResult("judge", "no", "", False, answered=False, failure=L.ERROR)),
                            0, 0.0, "decider")
    assert decider.by_kind() == {"hint": (1, 1), "judge": (0, 2)}  # a failure still scores wrong
    assert decider.correct == 1 and decider.accuracy == 1 / 3 and decider.total == 4  # four jobs run, three graded
    assert decider.unsure == 1 and decider.unanswered == 1
    only_unsure = lm.EvalReport("decider d", (unsure,), 0, 0.0, "decider")
    assert only_unsure.by_kind() == {"hint": (0, 0)} and only_unsure.accuracy == 0.0


def test_a_decider_that_is_unsure_on_every_job_still_measures_it(tmp_path):
    cases = write_cases(tmp_path / "cases.jsonl", hint_case("sstv", "slow scan"), hint_case("xor", "repeating key"))
    with FakeDeciderServer([picks("sstv", 0.3), picks("xor", 0.2)]) as server:
        result = runner.invoke(mount(), ["eval-local", "--engine", "decider", "--base-url", server.base_url,
                                         "--cases", str(cases)])
    assert result.exit_code == 0, result.output  # unsure is the model saying it does not know, not a failure
    rows = table(result.output)
    assert rows["unsure"] == ["-", "2/2 100%"] and rows["hint"][2] == rows["overall"][2] == "all unsure"


def test_eval_local_stops_a_decider_that_is_not_there(tmp_path):
    cases = write_cases(tmp_path / "cases.jsonl", *[hint_case("sstv", "slow scan")] * 5)
    url = f"http://127.0.0.1:{closed_port()}"
    result = runner.invoke(mount(), ["eval-local", "--engine", "decider", "--base-url", url, "--cases", str(cases)])
    assert result.exit_code == 2
    assert f"flightdeck: the decision model at {url} failed: no answer from the decision model" in result.output


@pytest.mark.parametrize("args, says", [
    (["--engine", "decider"], "--engine decider needs --base-url, its server's address, e.g. http://127.0.0.1:8000"),
    (["--engine", "decider", "--base-url", URL, "--key-env", "SOME_KEY"], "--key-env is not for --engine decider"),
    (["--engine", "decider", "--base-url", URL + "/v1/systemone"], "--base-url must be the server's address without /v1/systemone"),
    (["--engine", "decider", "--base-url", "127.0.0.1:8000"], "--base-url must start with http:// or https://"),
    (["--engine", "decider", "--base-url", URL, "--threshold", "0"], "--threshold must be a number above 0 and at most 1"),
    (["--engine", "decider", "--base-url", URL, "--threshold", "1.5"], "--threshold must be a number above 0"),
    (["--engine", "rules", "--threshold", "0.8"], "--threshold is for a decider column"),
    (["--engine", "decider", "--base-url", URL, "--price", "1,2"], "--price is not for --engine decider"),
    (["--engine", "rules", "--compare", "decider@ftp://x"], "--compare takes rules"),
    (["--engine", "rules", "--compare", f"decider@{URL}/v1"], "--compare must be the server's address without /v1/systemone"),
])
def test_eval_local_refuses_decider_options_it_cannot_use(tmp_path, args, says):
    cases = write_cases(tmp_path / "cases.jsonl", hint_case("sstv", "slow scan"))
    result = runner.invoke(mount(), ["eval-local", *args, "--cases", str(cases)])
    assert result.exit_code == 2 and says in result.output
