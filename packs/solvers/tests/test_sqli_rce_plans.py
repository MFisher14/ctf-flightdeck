"""Tests for non-wire SQL-injection-to-RCE escalation plans."""

import ast
from pathlib import Path

import pytest

import sqli_rce_plans as sqlrce


@pytest.mark.parametrize("database", sqlrce.DATABASES)
def test_every_database_has_deterministic_inert_plans(database):
    first = sqlrce.build_sql_rce_plans(database, injection_mode="stacked")
    second = sqlrce.build_sql_rce_plans(database, injection_mode="stacked")
    assert first == second
    assert first
    for plan in first:
        assert plan.database == database
        assert plan.inert and plan.offline
        assert plan.sql_emitted is plan.command_emitted is False
        assert plan.preconditions and len(plan.derivation) >= 4
        assert plan.descriptor.startswith("R5D_SQL_RCE_PLAN|")
        assert "sql=NOT_EMITTED" in plan.descriptor
        assert "command=NOT_EMITTED" in plan.descriptor


def test_stacked_context_and_evidence_rank_postgresql_program_plan():
    plans = sqlrce.build_sql_rce_plans(
        "postgres",
        injection_mode="stacked",
        capabilities=["current role has pg_execute_server_program"],
    )
    assert plans[0].plan_id == "copy_program"
    assert plans[0].readiness == "evidence_supported"
    assert "pg_execute_server_program" in plans[0].evidence
    assert plans[0].unmet_context == ()


def test_union_context_blocks_statement_only_but_not_existing_function_paths():
    sqlite = sqlrce.build_sql_rce_plans("sqlite", injection_mode="union")
    assert next(row for row in sqlite if row.plan_id == "application_udf").unmet_context == ()
    assert next(row for row in sqlite if row.plan_id == "attach_side_effect_chain").readiness == "blocked_by_context"
    mssql = sqlrce.build_sql_rce_plans("mssql", injection_mode="union")
    assert all(row.readiness == "blocked_by_context" for row in mssql)


@pytest.mark.parametrize(
    ("text", "database", "kind"),
    [
        ("PostgreSQL 16 role rolsuper=false", "postgresql", "product"),
        ("MariaDB 11 secure_file_priv=/safe", "mysql", "product"),
        ("Microsoft SQL Server xp_cmdshell disabled", "mssql", "product"),
        ("ORA-01031 DBMS_SCHEDULER", "oracle", "product"),
        ("SQLite compile_options OMIT_LOAD_EXTENSION", "sqlite", "product"),
        ("H2 Database org.h2.jdbc.JdbcSQLSyntaxErrorException", "h2", "product"),
    ],
)
def test_saved_metadata_detection_by_database_family(text, database, kind):
    rows = sqlrce.analyze_sql_metadata(text)
    assert any(row.database == database and row.kind == kind for row in rows)
    assert all(row.precondition for row in rows)


def test_metadata_findings_are_offset_sorted_and_stable():
    text = "SQLite load_extension then PostgreSQL pg_roles"
    first = sqlrce.analyze_sql_metadata(text)
    second = sqlrce.analyze_sql_metadata(text)
    assert first == second
    assert [row.offset for row in first] == sorted(row.offset for row in first)


def test_alias_matrix_and_input_bounds(monkeypatch):
    assert sqlrce.normalize_database("MariaDB") == "mysql"
    assert sqlrce.normalize_database("SQLServer") == "mssql"
    matrix = sqlrce.database_plan_matrix(injection_mode="stacked")
    assert {row.database for row in matrix} == set(sqlrce.DATABASES)
    with pytest.raises(sqlrce.SQLRCEInputError, match="unknown database"):
        sqlrce.build_sql_rce_plans("unknown")
    with pytest.raises(sqlrce.SQLRCEInputError, match="injection_mode"):
        sqlrce.build_sql_rce_plans("sqlite", injection_mode="magic")
    with pytest.raises(sqlrce.SQLRCEInputError, match="capability cap"):
        sqlrce.build_sql_rce_plans("h2", capabilities=(str(i) for i in range(129)))
    monkeypatch.setattr(sqlrce, "MAX_TEXT_CHARS", 8)
    with pytest.raises(sqlrce.SQLRCEInputError, match="exceeds"):
        sqlrce.analyze_sql_metadata("x" * 9)
    monkeypatch.setattr(sqlrce, "MAX_TEXT_BYTES", 8)
    with pytest.raises(sqlrce.SQLRCEInputError, match="bytes"):
        sqlrce.analyze_sql_metadata(b"x" * 9)


def test_descriptors_are_not_sql_or_command_payloads():
    descriptors = "\n".join(row.descriptor for row in sqlrce.database_plan_matrix(injection_mode="stacked"))
    forbidden = (";", "--", "/*", "xp_cmdshell(", "COPY ", "CREATE ", "SELECT ", "powershell", "/bin/", "cmd.exe")
    assert all(item not in descriptors for item in forbidden)


def test_module_has_no_database_process_eval_or_network_runtime():
    tree = ast.parse(Path(sqlrce.__file__).read_text(encoding="utf-8"))
    forbidden_imports = {"sqlite3", "psycopg", "pymysql", "pyodbc", "cx_Oracle", "subprocess", "os", "socket", "requests", "httpx"}
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    assert not imports.intersection(forbidden_imports)
    assert not calls.intersection({"eval", "exec", "compile", "__import__"})

