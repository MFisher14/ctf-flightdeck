"""Synthetic, offline tests for solvers/web/ssti_helper.py."""

import json

import pytest

import ssti_helper as ssti


def test_probe_manifest_has_engine_specific_wrapped_expectations():
    probes = ssti.fingerprint_probes()
    assert {engine for probe in probes for engine in probe["engines"]} == set(ssti.ENGINES)
    for probe in probes:
        for expected in probe["expected"].values():
            # The proof string appears only after evaluation, never in the raw
            # request value.  This is what makes a plain reflector a miss.
            assert expected not in probe["payload"]
            assert expected.startswith("CSCTF_SSTI_")


@pytest.mark.parametrize(
    ("response", "engine"),
    [
        ("<p>CSCTF_SSTI_A7777777CSCTF_SSTI_Z</p>", "jinja2"),
        ("<p>CSCTF_SSTI_A49CSCTF_SSTI_Z</p>", "twig"),
        ("CSCTF_SSTI_F49CSCTF_SSTI_Z", "freemarker"),
        ("CSCTF_SSTI_E49CSCTF_SSTI_Z", "erb"),
        ("CSCTF_SSTI_V49CSCTF_SSTI_Z", "velocity"),
    ],
)
def test_detects_each_engine_from_evaluated_marker(response, engine):
    result = ssti.detect_response(response)
    assert result[0]["engine"] == engine
    assert result[0]["confidence"] == "high"
    assert result[0]["score"] == 100
    assert "wrapped marker evaluated" in result[0]["evidence"][0]


def test_reflected_probe_and_bare_arithmetic_result_do_not_confirm():
    raw = ssti.fingerprint_probes()[0]["payload"]
    assert ssti.detect_response("you sent: " + raw) == []
    assert ssti.detect_response("the answer is 49") == []


def test_engine_named_error_is_a_ranked_lead_not_high_confidence():
    response = "freemarker.core.InvalidReferenceException at template line 4"
    result = ssti.detect_response(response)
    assert result[0]["engine"] == "freemarker"
    assert result[0]["confidence"] == "medium"
    assert result[0]["score"] == 55


@pytest.mark.parametrize("engine", ssti.ENGINES)
def test_every_engine_emits_ranked_read_and_rce_candidates(engine):
    reads = ssti.build_payloads(engine, read_file="/tmp/a'b")
    rce = ssti.build_payloads(engine, command="printf 'ok'")
    for action, rows in (("read_file", reads), ("rce", rce)):
        assert rows
        assert [row["rank"] for row in rows] == list(range(1, len(rows) + 1))
        assert all(row["engine"] == engine for row in rows)
        assert all(row["action"] == action for row in rows)
        assert all(row["offline"] is True and row["payload"] for row in rows)
        assert all(row["requirements"] for row in rows)


def test_analyze_response_builds_only_for_top_ranked_engine():
    result = ssti.analyze_response(
        "CSCTF_SSTI_A7777777CSCTF_SSTI_Z", read_file="/etc/hostname"
    )
    assert result["flag"] is None
    assert result["candidates"][0]["engine"] == "jinja2"
    assert result["payloads"]
    assert {row["engine"] for row in result["payloads"]} == {"jinja2"}


def test_builder_refuses_ambiguous_or_invalid_actions():
    with pytest.raises(ValueError, match="exactly one"):
        ssti.build_payloads("twig")
    with pytest.raises(ValueError, match="exactly one"):
        ssti.build_payloads("twig", read_file="/x", command="id")
    with pytest.raises(ValueError, match="unknown engine"):
        ssti.build_payloads("made-up", command="id")
    with pytest.raises(ValueError, match="NUL"):
        ssti.build_payloads("erb", read_file="/tmp/a\x00b")


def test_cli_json_is_machine_readable_and_offline(capsys):
    assert ssti.main([
        "detect", "CSCTF_SSTI_A49CSCTF_SSTI_Z", "--rce", "id", "--json"
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["offline"] is True
    assert result["flag"] is None
    assert result["candidates"][0]["engine"] == "twig"
    assert result["payloads"][0]["action"] == "rce"


def test_default_probe_cli_is_human_readable(capsys):
    assert ssti.main(["probes"]) == 0
    output = capsys.readouterr().out
    assert "curly" not in output  # probe labels are engine names, not an inferred syntax family
    assert "jinja2, twig" in output
    assert "CSCTF_SSTI_A{{7*'7'}}CSCTF_SSTI_Z" in output


def test_twig_read_candidates_include_non_loader_primitives():
    payloads = [row["payload"] for row in ssti.build_payloads("twig", read_file="/etc/passwd")]
    assert any("file_excerpt" in payload for payload in payloads)
    assert any("filter('system')" in payload for payload in payloads)

