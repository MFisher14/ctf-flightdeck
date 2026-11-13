"""Independent syntax locks and fail-closed checks for offline injection builders.

SQL is parsed by sqlglot using the stated vendor dialect. Mongo-style JSON and
form values use the standard-library decoders. LDAP filters use a small direct
implementation of RFC 4515's prefix grammar, and XPath 1.0 expressions are
compiled and evaluated by lxml. No test opens a socket or executes SQL.
"""
from __future__ import annotations

import inspect
import json
import random
import re
import urllib.parse

from lxml import etree
import pytest
from sqlglot import ErrorLevel, expressions as sql_exp, parse

import injection_builders as injection
import sqli_helper
import sqli_rce_plans as rce


def _row(rows, technique, variant):
    return next(row for row in rows
                if row["technique"] == technique and row["variant"] == variant)


def _only_declared(call, error, result_type=None):
    """Accept a clean result or exactly the documented validation exception."""
    try:
        result = call()
    except Exception as exc:  # the assertion below exposes any stdlib leak
        assert type(exc) is error, f"leaked {type(exc).__name__}: {exc}"
    else:
        if result_type is not None:
            assert isinstance(result, result_type)


@pytest.mark.parametrize(
    ("dialect", "sqlglot_dialect", "error_token", "time_token"),
    [
        ("mysql", "mysql", "EXTRACTVALUE", "SLEEP"),
        ("postgresql", "postgres", "CAST", "pg_sleep"),
        ("mssql", "tsql", "CONVERT", "WAITFOR"),
        ("oracle", "oracle", "DRITHSX", "DBMS_PIPE"),
    ],
)
def test_per_database_sqli_payloads_parse_in_their_declared_dialect(
        dialect, sqlglot_dialect, error_token, time_token):
    """Vendor fragments are embedded in the numeric context they claim."""
    rows = sqli_helper.generate_payloads(
        3, context="numeric", dialect=dialect, reflected_column=2,
        marker="O'Brien", delay=3,
    )
    assert [(row["technique"], row["variant"]) for row in rows] == [
        ("union", "reflected_marker"), ("error", "version_leak"),
        ("boolean", "true"), ("boolean", "false"),
        ("time", "true"), ("time", "false"),
    ]
    for row in rows:
        payload = row["payload"]
        assert payload is not None and payload.endswith(" -- ")
        fragment = payload.removesuffix(" -- ")
        statement = ("SELECT 1" if row["technique"] == "union"
                     else "SELECT 1 WHERE 1=1") + fragment
        trees = parse(statement, read=sqlglot_dialect, error_level=ErrorLevel.RAISE)
        assert len(trees) == (2 if dialect == "mssql" and row["technique"] == "time" else 1)
        assert all(isinstance(tree, sql_exp.Expression) for tree in trees)

    union = _row(rows, "union", "reflected_marker")["payload"]
    assert "NULL" in union and "O''Brien" in union
    assert ("N'O''Brien'" in union) is (dialect == "mssql")
    assert (" FROM dual" in union) is (dialect == "oracle")
    assert error_token in _row(rows, "error", "version_leak")["payload"]
    assert time_token in _row(rows, "time", "true")["payload"]


def test_all_dialects_aggregator_preserves_each_concrete_dialect_and_rank():
    rows = sqli_helper.generate_all_dialects(2, context="numeric", marker="CSCTF_MARK")
    assert [row["rank"] for row in rows] == list(range(1, len(rows) + 1))
    assert {row["dialect"] for row in rows} == set(sqli_helper.DIALECTS[1:])
    assert all(row["offline"] is True for row in rows)


@pytest.mark.parametrize(
    ("database", "capabilities", "plan_id", "rank", "evidence", "precondition"),
    [
        ("postgresql", ["pg_execute_server_program"], "copy_program", 100,
         {"pg_execute_server_program"}, "superuser or has pg_execute_server_program"),
        ("mysql", ["FILE privilege", "secure_file_priv"], "udf_plugin", 100,
         {"file privilege", "secure_file_priv"}, "FILE and function-creation privileges"),
        ("mssql", ["xp_cmdshell", "sysadmin"], "xp_cmdshell", 108,
         {"xp_cmdshell", "sysadmin"}, "sysadmin or executes through an authorized proxy"),
        ("oracle", ["DBMS_SCHEDULER", "CREATE EXTERNAL JOB"], "dbms_scheduler", 98,
         {"dbms_scheduler", "create external job"}, "CREATE JOB and any required external-job privilege"),
    ],
)
def test_database_rce_plan_preconditions_match_vendor_documentation(
        database, capabilities, plan_id, rank, evidence, precondition):
    plans = rce.build_sql_rce_plans(
        database, injection_mode="stacked", capabilities=capabilities,
        marker="CSCTF_PLAN",
    )
    top = plans[0]
    assert (top.plan_id, top.rank, set(top.evidence), top.readiness) == (
        plan_id, rank, evidence, "evidence_supported")
    assert any(precondition in item for item in top.preconditions)
    assert top.inert and top.offline
    assert top.sql_emitted is top.command_emitted is False
    assert top.descriptor == (
        f"R5D_SQL_RCE_PLAN|database={database}|plan={plan_id}|marker=CSCTF_PLAN"
        "|sql=NOT_EMITTED|command=NOT_EMITTED|action=REVIEW_ONLY"
    )


def test_mysql_outfile_plan_keeps_all_documented_file_gates():
    plans = rce.build_sql_rce_plans(
        "mysql", injection_mode="stacked",
        capabilities=["FILE privilege", "secure_file_priv", "INTO OUTFILE"],
    )
    row = next(plan for plan in plans if plan.plan_id == "outfile_interpreter_chain")
    assert set(row.evidence) == {"into outfile", "file privilege", "secure_file_priv"}
    assert any("secure_file_priv" in item for item in row.preconditions)
    assert any("database service account can write" in item for item in row.preconditions)


def test_database_plan_matrix_contains_each_documented_family_without_payloads():
    plans = rce.database_plan_matrix(injection_mode="stacked", marker="CSCTF_PLAN")
    assert {plan.database for plan in plans} == set(rce.DATABASES)
    assert {(plan.database, plan.plan_id) for plan in plans}.issuperset({
        ("postgresql", "copy_program"), ("mysql", "udf_plugin"),
        ("mssql", "xp_cmdshell"), ("oracle", "dbms_scheduler"),
    })
    assert all(plan.inert and not plan.sql_emitted and not plan.command_emitted for plan in plans)


def test_sql_metadata_known_product_strings_map_to_their_vendor():
    samples = {
        "PostgreSQL 16 pg_roles": "postgresql",
        "MariaDB 11 secure_file_priv": "mysql",
        "Microsoft SQL Server xp_cmdshell": "mssql",
        "ORA-01031 DBMS_SCHEDULER": "oracle",
    }
    for text, database in samples.items():
        rows = rce.analyze_sql_metadata(text)
        assert any(row.database == database and row.kind == "product" for row in rows)


def test_sql_metadata_does_not_misclassify_explicit_sql_server_as_mysql():
    findings = rce.analyze_sql_metadata("Microsoft SQL Server uses @@VERSION")
    assert {(row.database, row.kind) for row in findings} == {("mssql", "product")}


def test_mongodb_json_payloads_match_documented_operator_shapes():
    rows = {row.name: row for row in injection.nosql_payloads("account", "CSCTF_MARK")}
    assert json.loads(rows["json_ne_null"].value) == {"account": {"$ne": None}}
    assert json.loads(rows["json_regex_prefix"].value) == {
        "account": {"$regex": "^CSCTF_MARK"}}
    assert json.loads(rows["json_expr_true"].value) == {"$expr": {"$eq": [1, 1]}}


def test_mongodb_form_payloads_round_trip_through_form_url_decoder():
    rows = {row.name: row for row in injection.nosql_payloads("account", "CSCTF_MARK")}
    assert urllib.parse.parse_qsl(rows["form_ne"].value, strict_parsing=True) == [
        ("account[$ne]", "CSCTF_MARK")]
    assert urllib.parse.parse_qsl(rows["form_regex"].value, strict_parsing=True) == [
        ("account[$regex]", "^CSCTF_MARK")]
    assert urllib.parse.parse_qsl(rows["duplicate_scalar_operator"].value,
                                 strict_parsing=True) == [
        ("account", "CSCTF_MARK"), ("account[$ne]", "CSCTF_MARK")]


_LDAP_DESCRIPTOR = r"[A-Za-z][A-Za-z0-9-]*"
_LDAP_NUMERICOID = r"[0-9]+(?:\.[0-9]+)+"
_LDAP_OPTION = r"[A-Za-z0-9-]+"
_LDAP_ATTR = re.compile(
    rf"(?:{_LDAP_DESCRIPTOR}|{_LDAP_NUMERICOID})(?:;{_LDAP_OPTION})*\Z")


def _parse_rfc4515_filter(text):
    """Validate the RFC 4515 forms emitted here; returns only on exact EOF."""
    pos = 0

    def one():
        nonlocal pos
        assert pos < len(text) and text[pos] == "("
        pos += 1
        if pos < len(text) and text[pos] in "&|":
            pos += 1
            count = 0
            while pos < len(text) and text[pos] == "(":
                one()
                count += 1
            assert count >= 1
        elif pos < len(text) and text[pos] == "!":
            pos += 1
            one()
        else:
            equal = text.find("=", pos)
            assert equal >= pos
            attribute = text[pos:equal]
            assert _LDAP_ATTR.fullmatch(attribute)
            pos = equal + 1
            while pos < len(text) and text[pos] != ")":
                char = text[pos]
                if char == "\\":
                    assert pos + 2 < len(text)
                    assert all(c in "0123456789abcdefABCDEF" for c in text[pos + 1:pos + 3])
                    pos += 3
                else:
                    assert char not in "\x00(\\"
                    pos += 1
        assert pos < len(text) and text[pos] == ")"
        pos += 1

    one()
    assert pos == len(text)


def _ldap_interpolation(attribute, payload):
    return f"(&({attribute}={payload})(objectClass=person))"


def test_ldap_wildcard_and_balanced_breakout_follow_rfc4515_grammar():
    rows = {row.name: row for row in injection.ldap_payloads("uid", "CSCTF_MARK")}
    for name in ("wildcard_value", "close_or_wildcard"):
        _parse_rfc4515_filter(_ldap_interpolation("uid", rows[name].value))


@pytest.mark.parametrize("name", ["or_objectclass", "false_control", "escaped_or_percent"])
def test_ldap_breakout_is_well_formed_in_stated_outer_and_context(name):
    rows = {row.name: row for row in injection.ldap_payloads("uid", "CSCTF_MARK")}
    payload = urllib.parse.unquote(rows[name].value)
    _parse_rfc4515_filter(_ldap_interpolation("uid", payload))


def test_ldap_builder_accepts_rfc4512_numeric_oid_attribute():
    try:
        rows = injection.ldap_payloads("2.5.4.3", "CSCTF_MARK")
    except injection.InjectionInputError:
        rows = None
    assert rows is not None and len(rows) == 5


def test_ldap_builder_rejects_invalid_dotted_descriptor():
    rejected = False
    try:
        injection.ldap_payloads("uid.name", "CSCTF_MARK")
    except injection.InjectionInputError:
        rejected = True
    assert rejected


def test_xpath_payloads_compile_and_have_documented_xpath1_semantics():
    xml = etree.fromstring(
        b"<root><user><name>CSCTF_MARK</name></user>"
        b"<user><name>other</name></user><other/></root>")
    rows = {row.name: row for row in injection.xpath_payloads("CSCTF_MARK")}
    expressions = {
        "single_quote_true": f"boolean(/root/user[name='{rows['single_quote_true'].value}'])",
        "single_quote_false": f"boolean(/root/user[name='{rows['single_quote_false'].value}'])",
        "double_quote_true": f'boolean(/root/user[name="{rows["double_quote_true"].value}"])',
        "numeric_true": f"/root/user[position()={rows['numeric_true'].value}]",
        "node_union": f"/root/user[name='{rows['node_union'].value}']",
        "contains_marker": f"/root/user[name='{rows['contains_marker'].value}']",
    }
    results = {name: etree.XPath(expression)(xml) for name, expression in expressions.items()}
    assert results["single_quote_true"] is True
    assert results["single_quote_false"] is False
    assert results["double_quote_true"] is True
    assert len(results["numeric_true"]) == 2
    assert xml in results["node_union"] and len(results["node_union"]) >= 6
    assert len(results["contains_marker"]) == 1


def test_filter_bypass_decode_matches_stdlib_transforms():
    source = "ＵＮ/**/ＩＯＮ%2520ＳＥＬ/**/ＥＣＴ%2520%2527CSCTF%2527"
    first = urllib.parse.unquote(source)
    second = urllib.parse.unquote(first)
    assert second == "ＵＮ/**/ＩＯＮ ＳＥＬ/**/ＥＣＴ 'CSCTF'"
    result = sqli_helper.decode_filter_bypasses(source)
    assert result["canonical"] == "UNION SELECT 'CSCTF'"
    assert result["url_decode_rounds"] == 2
    assert result["keywords"] == ["UNION", "SELECT"]


def test_injection_evidence_helpers_are_offline_and_deterministic():
    baseline = b"HTTP/1.1 401 Unauthorized\r\n\r\ndenied\n"
    candidate = (b"HTTP/1.1 500 Error\r\n\r\nCSCTF_MARK\n"
                 b"MongoServerError: unknown query operator\n")
    result = injection.compare_saved_responses(baseline, candidate, marker="CSCTF_MARK")
    assert result["baseline_status"] == 401 and result["candidate_status"] == 500
    assert result["marker_reflected"] is True
    assert result["new_error_families"] == ("nosql",)
    assert result["offline"] is True and result["network_requests"] == 0
    serialized = injection.rows_as_dicts(injection.injection_matrix(marker="CSCTF_MARK"))
    assert len(serialized) == 17
    assert all(row["offline"] and row["network_requests"] == 0 for row in serialized)


def test_sqli_helper_builders_fail_closed_on_ordinary_odd_parameters():
    calls = [
        lambda: sqli_helper.generate_payloads(None),
        lambda: sqli_helper.generate_payloads(""),
        lambda: sqli_helper.generate_payloads(0),
        lambda: sqli_helper.generate_payloads(129),
        lambda: sqli_helper.generate_payloads(2, reflected_column=0),
        lambda: sqli_helper.generate_payloads(2, reflected_column=3),
        lambda: sqli_helper.generate_payloads(1, delay=0),
        lambda: sqli_helper.generate_payloads(1, delay=31),
        lambda: sqli_helper.generate_payloads(1, context="bad"),
        lambda: sqli_helper.generate_payloads(1, dialect="bad"),
        lambda: sqli_helper.generate_payloads(1, marker="x\0y"),
        lambda: sqli_helper.generate_payloads(1, marker="x" * 1025),
        lambda: sqli_helper.generate_all_dialects(0),
        lambda: sqli_helper.generate_all_dialects(1, context="bad"),
        lambda: sqli_helper.decode_filter_bypasses("x", max_url_rounds=""),
        lambda: sqli_helper.decode_filter_bypasses("x", max_url_rounds=-1),
        lambda: sqli_helper.decode_filter_bypasses("x", max_url_rounds=9),
        lambda: sqli_helper.decode_filter_bypasses("x" * 1_000_001),
    ]
    for call in calls:
        _only_declared(call, ValueError)


@pytest.mark.parametrize("parameter", ["column_count", "reflected_column", "delay"])
def test_sqli_generate_infinite_parameters_use_validation_error(parameter):
    kwargs = {"column_count": 1, "reflected_column": 1, "delay": 3}
    kwargs[parameter] = float("inf")
    caught = None
    try:
        sqli_helper.generate_payloads(**kwargs)
    except Exception as exc:
        caught = exc
    assert type(caught) is ValueError


@pytest.mark.parametrize("rounds", [None, [], {}, float("inf")])
def test_sqli_decode_odd_round_count_uses_validation_error(rounds):
    caught = None
    try:
        sqli_helper.decode_filter_bypasses("SELECT", max_url_rounds=rounds)
    except Exception as exc:
        caught = exc
    assert type(caught) is ValueError


@pytest.mark.parametrize("argv,expected", [([], 2), (["--help"], 0), (["unknown"], 2)])
def test_sqli_cli_argparse_is_fail_closed(argv, expected):
    result = None
    try:
        result = sqli_helper.main(argv)
    except SystemExit as exc:
        result = exc
    assert type(result) is int and result == expected


def test_sql_rce_entrypoints_raise_only_declared_error_for_odd_input():
    calls = [
        lambda: rce.normalize_database(None),
        lambda: rce.normalize_database(""),
        lambda: rce.build_sql_rce_plans("unknown"),
        lambda: rce.build_sql_rce_plans("mssql", injection_mode=None),
        lambda: rce.build_sql_rce_plans("mssql", injection_mode=[]),
        lambda: rce.build_sql_rce_plans("mssql", capabilities=None),
        lambda: rce.build_sql_rce_plans("mssql", capabilities=[""]),
        lambda: rce.build_sql_rce_plans("mssql", capabilities=["x\0y"]),
        lambda: rce.build_sql_rce_plans("mssql", capabilities=["x"] * 129),
        lambda: rce.build_sql_rce_plans("mssql", marker="bad-marker"),
        lambda: rce.build_sql_rce_plans("mssql", limit=0),
        lambda: rce.build_sql_rce_plans("mssql", limit=True),
        lambda: rce.database_plan_matrix(injection_mode="bad"),
        lambda: rce.database_plan_matrix(marker="x"),
        lambda: rce.analyze_sql_metadata(None),
        lambda: rce.analyze_sql_metadata(memoryview(b"PostgreSQL")),
        lambda: rce.analyze_sql_metadata("x" * (rce.MAX_TEXT_CHARS + 1)),
        lambda: rce.analyze_sql_metadata(b"x" * (rce.MAX_TEXT_BYTES + 1)),
    ]
    for call in calls:
        _only_declared(call, rce.SQLRCEInputError)


def test_injection_builders_raise_only_declared_error_for_odd_input():
    odd = [None, "", 0, [], {}, b"uid", "a b", "x\0y", "x" * 1000]
    calls = []
    for value in odd:
        calls.extend((
            lambda value=value: injection.nosql_payloads(value, "CSCTF"),
            lambda value=value: injection.nosql_payloads("username", value),
            lambda value=value: injection.ldap_payloads(value, "CSCTF"),
            lambda value=value: injection.ldap_payloads("uid", value),
            lambda value=value: injection.xpath_payloads(value),
            lambda value=value: injection.injection_matrix(field=value, marker="CSCTF"),
            lambda value=value: injection.injection_matrix(attribute=value, marker="CSCTF"),
            lambda value=value: injection.injection_matrix(marker=value),
        ))
    for call in calls:
        _only_declared(call, injection.InjectionInputError, tuple)


def _mutated_text_corpus():
    rng = random.Random(0x53514C49)
    seed = b"HTTP/1.1 500 Error\r\n\r\nMongoServerError: Invalid predicate CSCTF_MARK"
    rows = [b"", b"\0" * 32, b"\xff" * 32]
    rows.extend(rng.randbytes(rng.randrange(129)) for _ in range(64))
    rows.extend(seed[:i] for i in range(len(seed) + 1))
    for _ in range(64):
        changed = bytearray(seed)
        changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
        rows.append(bytes(changed))
    return rows


def test_saved_text_and_decoder_seeded_fail_closed_corpus():
    for raw in _mutated_text_corpus():
        _only_declared(lambda raw=raw: sqli_helper.decode_filter_bypasses(raw), ValueError, dict)
        _only_declared(lambda raw=raw: rce.analyze_sql_metadata(raw),
                       rce.SQLRCEInputError, tuple)
        _only_declared(lambda raw=raw: injection.analyze_injection_text(raw),
                       injection.InjectionInputError, tuple)
        _only_declared(
            lambda raw=raw: injection.compare_saved_responses(b"baseline", raw),
            injection.InjectionInputError, dict)


def test_public_entrypoint_inventory_is_explicit():
    expected = {
        sqli_helper: {"generate_payloads", "generate_all_dialects",
                      "decode_filter_bypasses", "main"},
        rce: {"normalize_database", "build_sql_rce_plans",
              "database_plan_matrix", "analyze_sql_metadata"},
        injection: {"nosql_payloads", "ldap_payloads", "xpath_payloads",
                    "injection_matrix", "analyze_injection_text",
                    "compare_saved_responses", "rows_as_dicts"},
    }
    for module, names in expected.items():
        actual = {name for name, value in vars(module).items()
                  if inspect.isfunction(value) and value.__module__ == module.__name__
                  and not name.startswith("_")}
        assert actual == names
