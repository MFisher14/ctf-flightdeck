#!/usr/bin/env python3
"""Static SQL-injection-to-RCE escalation planning by database family.

This module emits no SQL statement and no operating-system command.  It only
returns bounded metadata plans that separate observed evidence, unverified
preconditions, and injection-context blockers for PostgreSQL, MySQL/MariaDB,
Microsoft SQL Server, Oracle, SQLite, and H2.  Supplied text is scanned with
regular expressions only; no database or network connection is possible.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from itertools import islice
from typing import Iterable


DATABASES: tuple[str, ...] = (
    "postgresql",
    "mysql",
    "mssql",
    "oracle",
    "sqlite",
    "h2",
)
INJECTION_MODES: tuple[str, ...] = ("unknown", "boolean", "error", "union", "stacked", "procedure")
MAX_CAPABILITIES = 128
MAX_CAPABILITY_CHARS = 256
MAX_TEXT_CHARS = 512_000
MAX_TEXT_BYTES = 1_048_576
MAX_PLANS = 64
_MARKER_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{3,31}\Z")
_ALIASES = {
    "postgres": "postgresql", "pgsql": "postgresql",
    "mariadb": "mysql", "sqlserver": "mssql", "sql_server": "mssql",
    "microsoft_sql_server": "mssql", "ora": "oracle", "h2database": "h2",
}


class SQLRCEInputError(ValueError):
    """A SQL planning input is malformed or exceeds a fixed cap."""


@dataclass(frozen=True)
class SQLRCEPlan:
    database: str
    plan_id: str
    primitive: str
    descriptor: str
    evidence: tuple[str, ...]
    preconditions: tuple[str, ...]
    derivation: tuple[str, ...]
    unmet_context: tuple[str, ...]
    readiness: str
    rank: int
    inert: bool = True
    sql_emitted: bool = False
    command_emitted: bool = False
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        for key in ("evidence", "preconditions", "derivation", "unmet_context"):
            row[key] = list(row[key])
        return row


@dataclass(frozen=True)
class SQLMetadataFinding:
    database: str
    kind: str
    evidence: str
    offset: int
    confidence: str
    precondition: str
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class _PlanSpec:
    database: str
    plan_id: str
    primitive: str
    evidence_tokens: tuple[str, ...]
    preconditions: tuple[str, ...]
    derivation: tuple[str, ...]
    statement_control: bool = True
    rank: int = 50


_PLAN_SPECS: tuple[_PlanSpec, ...] = (
    _PlanSpec(
        "postgresql", "copy_program", "COPY PROGRAM server-side process capability",
        ("rolsuper", "pg_execute_server_program", "copy program", "superuser"),
        ("the injection supports a separate server-side statement", "the database role is superuser or has pg_execute_server_program", "COPY PROGRAM is available on the server version", "the database service account is permitted to start the reviewed marker-only process"),
        ("confirm PostgreSQL and exact version from saved output", "confirm stacked-statement behavior without side effects", "inspect saved role/privilege metadata", "choose the primitive only if every privilege gate is evidenced", "prepare a marker-only command separately for Docker review; this planner never emits it"),
        rank=95,
    ),
    _PlanSpec(
        "postgresql", "untrusted_language", "untrusted procedural-language function",
        ("plpythonu", "plperlu", "pg_language", "create language"),
        ("an untrusted procedural language is installed or can be created", "the role can create a function/language", "the injection supports statement execution", "the language runtime exposes the intended marker-only capability"),
        ("inventory pg_language evidence", "check CREATE privilege separately", "pin language/version semantics", "draft a non-wire function plan", "execute nothing outside the networkless challenge sandbox"),
        rank=75,
    ),
    _PlanSpec(
        "postgresql", "native_udf", "native shared-library function metadata",
        ("create function", "language c", "dynamic_library_path", "lo_export"),
        ("the role can create C-language functions", "a compatible reviewed library already exists or can be placed", "library search/path and architecture match", "statement execution is available"),
        ("collect version and architecture evidence", "collect function-creation privilege evidence", "review file-placement feasibility", "keep library construction outside this planner", "record a sandbox-only validation plan"),
        rank=55,
    ),
    _PlanSpec(
        "mysql", "udf_plugin", "native UDF plugin metadata",
        ("file privilege", "plugin_dir", "secure_file_priv", "create function", "udf"),
        ("the account has FILE and function-creation privileges", "plugin_dir is known and writable through an authorized primitive", "a matching reviewed library can be placed", "the server permits loading the UDF", "multi-statement or equivalent function setup is possible"),
        ("identify MySQL versus MariaDB and version", "inspect FILE privilege and secure_file_priv evidence", "inspect plugin_dir and architecture", "keep library bytes and SQL outside this planner", "validate only in Docker after human review"),
        rank=90,
    ),
    _PlanSpec(
        "mysql", "outfile_interpreter_chain", "server file-write to separately evidenced interpreter path",
        ("into outfile", "into dumpfile", "file privilege", "secure_file_priv", "document root"),
        ("the account has FILE privilege", "secure_file_priv permits the exact destination", "the database service account can write there", "a separate application interpreter serves that path", "the injection controls a standalone statement"),
        ("confirm file-write privilege metadata", "confirm allowed output directory", "correlate a saved server path with a separately assigned web target", "create no file from this planner", "defer any marker-only validation to the sandbox/scoped workflow"),
        rank=78,
    ),
    _PlanSpec(
        "mysql", "general_log_chain", "general-log path redirection metadata",
        ("general_log", "general_log_file", "system_variables_admin", "super"),
        ("the account can change global log settings", "the log destination is writable and separately interpreted", "configuration restoration is authorized and planned", "multi-statement execution is available"),
        ("inspect variable-admin privilege evidence", "inspect current log settings from saved output", "correlate path handling without changing it", "record rollback prerequisites", "emit no SET statement or content"),
        rank=58,
    ),
    _PlanSpec(
        "mssql", "xp_cmdshell", "xp_cmdshell configuration/execution metadata",
        ("xp_cmdshell", "sysadmin", "show advanced options", "sp_configure"),
        ("the login is sysadmin or executes through an authorized proxy", "xp_cmdshell is enabled or configuration change is authorized", "stacked/procedure execution reaches the extended procedure", "the SQL Server service/proxy account has the reviewed capability"),
        ("confirm Microsoft SQL Server version", "inspect role membership and xp_cmdshell configuration evidence", "distinguish direct sysadmin from proxy context", "prepare only a marker-output sandbox plan", "emit neither SQL nor command text here"),
        rank=98,
    ),
    _PlanSpec(
        "mssql", "sql_agent_job", "SQL Server Agent job-step metadata",
        ("sqlagent", "sql server agent", "sp_add_job", "sqlagentoperatorrole"),
        ("SQL Server Agent is running", "the login has an Agent role or sysadmin", "job creation and execution are authorized", "cleanup of job metadata is planned"),
        ("inspect Agent service state evidence", "inspect msdb role membership", "derive job ownership/security context", "record cleanup requirements", "keep job and command bodies out of this planner"),
        rank=72,
    ),
    _PlanSpec(
        "mssql", "unsafe_clr", "UNSAFE CLR assembly metadata",
        ("clr enabled", "unsafe assembly", "trustworthy", "create assembly", "strict security"),
        ("CLR integration is enabled", "assembly creation permission exists", "trust/signing policy permits the reviewed assembly", "compatible assembly bytes are supplied only through the sandbox workflow"),
        ("collect CLR and strict-security settings", "collect database trust/signing evidence", "pin server architecture/runtime", "keep assembly bytes and SQL outside this planner", "review cleanup before validation"),
        rank=60,
    ),
    _PlanSpec(
        "oracle", "dbms_scheduler", "DBMS_SCHEDULER external-job metadata",
        ("dbms_scheduler", "create job", "create external job", "run_job"),
        ("the user has CREATE JOB and any required external-job privilege", "Scheduler is enabled and configured", "credential/service-account context is known", "a standalone PL/SQL action can be reached"),
        ("identify Oracle version/edition", "inspect scheduler and privilege evidence", "resolve credential and service context", "record job cleanup", "emit no PL/SQL block or external command"),
        rank=88,
    ),
    _PlanSpec(
        "oracle", "java_stored_procedure", "Oracle JVM stored-procedure metadata",
        ("javavm", "javauserpriv", "create java", "dbms_java"),
        ("Oracle JVM is installed", "CREATE JAVA and required Java permissions are granted", "a callable wrapper can be created", "statement/PLSQL execution is available"),
        ("inspect installed-component evidence", "inspect Java policy and user privileges", "pin JVM/database version", "keep Java source/class bytes outside this planner", "record object cleanup requirements"),
        rank=68,
    ),
    _PlanSpec(
        "oracle", "external_table_preprocessor", "external-table preprocessor metadata",
        ("oracle_loader", "preprocessor", "create any directory", "read on directory"),
        ("the user can create/use a DIRECTORY object", "external-table preprocessors are supported", "the reviewed executable path already exists", "statement/PLSQL execution is available"),
        ("inspect DIRECTORY privileges", "inspect version and external-table support", "verify existing path without creating it", "keep DDL and executable arguments out of this planner", "plan cleanup"),
        rank=52,
    ),
    _PlanSpec(
        "sqlite", "load_extension", "SQLite extension-loader metadata",
        ("load_extension", "enable_load_extension", "omit_load_extension", "compile_options"),
        ("the host application enabled extension loading", "a compatible reviewed extension already exists at an allowed path", "the SQL interface exposes load_extension", "the application process has filesystem/loader permission"),
        ("inspect SQLite version and compile options", "inspect application extension-loader policy", "pin architecture and ABI", "keep extension bytes and invocation SQL outside this planner", "validate only in sandbox"),
        statement_control=False,
        rank=92,
    ),
    _PlanSpec(
        "sqlite", "application_udf", "host-registered function capability",
        ("create_function", "sqlite3_create_function", "custom function", "udf"),
        ("the embedding application registered a consequential function", "the injection can invoke that function in its expression context", "argument constraints are known", "the function behavior is authorized for marker-only validation"),
        ("inventory function names from supplied source/errors", "map arity and argument policy", "distinguish pure functions from side-effecting functions", "emit no invocation SQL", "record expected marker-only observation"),
        statement_control=False,
        rank=80,
    ),
    _PlanSpec(
        "sqlite", "attach_side_effect_chain", "ATTACH/file-side-effect metadata",
        ("attach database", "writable directory", "sqlite_master", "vacuum into"),
        ("the SQLite build/path policy permits a controlled file destination", "a separate application component interprets the resulting file", "the injection supports the required statements", "file creation is authorized and cleanup is planned"),
        ("inspect writable-path evidence", "correlate only an assigned application consumer", "review required statement sequence", "emit no ATTACH/VACUUM statement", "defer file effects to explicit sandbox validation"),
        rank=48,
    ),
    _PlanSpec(
        "h2", "create_alias", "H2 Java alias metadata",
        ("create alias", "org.h2", "source_compiler", "admin"),
        ("the H2 user is admin or has alias creation rights", "Java compilation/reflection support is available for the exact version", "the injection supports a standalone statement", "the database runs in a process context appropriate for marker-only validation"),
        ("confirm H2 and exact version", "inspect admin/alias rights", "inspect compiler/runtime availability", "keep alias source and SQL outside this planner", "plan alias cleanup before sandbox validation"),
        rank=95,
    ),
    _PlanSpec(
        "h2", "existing_alias", "existing H2 alias/function invocation metadata",
        ("information_schema.function_aliases", "routines", "alias_name", "java_method"),
        ("a pre-existing callable alias is evidenced", "its arguments and side effects are understood", "the current injection expression can call it", "marker-only use is authorized"),
        ("inventory aliases from saved metadata", "map Java method and arity", "rank only already-evidenced capabilities", "emit no invocation SQL", "validate output without side effects"),
        statement_control=False,
        rank=75,
    ),
)


_EVIDENCE_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str], str], ...] = (
    ("postgresql", "product", "high", re.compile(r"(?i)\bPostgreSQL\b|\bpg_(?:roles|language|execute_server_program)\b"), "exact role/version still needs confirmation"),
    ("postgresql", "server_program_privilege", "high", re.compile(r"(?i)\b(?:rolsuper|pg_execute_server_program|COPY\s+PROGRAM)\b"), "the saved text must describe the current database role/session"),
    ("mysql", "product", "high", re.compile(r"(?i)\b(?:MySQL|MariaDB)\b"), "exact fork/version still needs confirmation"),
    ("mysql", "file_plugin_surface", "medium", re.compile(r"(?i)\b(?:secure_file_priv|plugin_dir|FILE privilege|INTO\s+(?:OUTFILE|DUMPFILE))\b"), "the value must apply to the current account/server"),
    ("mssql", "product", "high", re.compile(r"(?i)\bMicrosoft SQL Server\b|\bxp_cmdshell\b|@@version"), "exact edition/version still needs confirmation"),
    ("mssql", "privileged_surface", "medium", re.compile(r"(?i)\b(?:sysadmin|sp_configure|clr enabled|SQL Server Agent)\b"), "saved output must reflect the current login and instance"),
    ("oracle", "product", "high", re.compile(r"(?i)\bOracle Database\b|\bORA-\d{5}\b"), "exact version/edition still needs confirmation"),
    ("oracle", "execution_surface", "medium", re.compile(r"(?i)\b(?:DBMS_SCHEDULER|CREATE EXTERNAL JOB|JAVAUSERPRIV|ORACLE_LOADER)\b"), "the current schema must hold the corresponding privilege"),
    ("sqlite", "product", "high", re.compile(r"(?i)\bSQLite\b|sqlite_version\s*\("), "the embedding application's policy remains decisive"),
    ("sqlite", "extension_surface", "medium", re.compile(r"(?i)\b(?:load_extension|enable_load_extension|OMIT_LOAD_EXTENSION|sqlite3_create_function)\b"), "source/configuration must apply to the running embedding application"),
    ("h2", "product", "high", re.compile(r"(?i)\bH2 Database\b|org\.h2\.|JdbcSQL"), "exact H2 version still needs confirmation"),
    ("h2", "alias_surface", "medium", re.compile(r"(?i)\b(?:CREATE ALIAS|FUNCTION_ALIASES|JAVA_METHOD)\b"), "the current user and version must permit the alias path"),
)


def normalize_database(database: str) -> str:
    if not isinstance(database, str):
        raise SQLRCEInputError("database must be text")
    name = _ALIASES.get(database.strip().lower(), database.strip().lower())
    if name not in DATABASES:
        raise SQLRCEInputError(f"unknown database {database!r}; choose one of: {', '.join(DATABASES)}")
    return name


def _capabilities(values: Iterable[str] | str) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    try:
        rows = list(islice(iter(values), MAX_CAPABILITIES + 1))
    except TypeError as exc:
        raise SQLRCEInputError("capabilities must be iterable") from exc
    if len(rows) > MAX_CAPABILITIES:
        raise SQLRCEInputError(f"capability cap exceeded ({MAX_CAPABILITIES})")
    result: list[str] = []
    for row in rows:
        if not isinstance(row, str) or not row or len(row) > MAX_CAPABILITY_CHARS or "\x00" in row:
            raise SQLRCEInputError("capability entries must be bounded non-empty text without NUL")
        if row not in result:
            result.append(row)
    return tuple(result)


def build_sql_rce_plans(
    database: str,
    *,
    injection_mode: str = "unknown",
    capabilities: Iterable[str] | str = (),
    marker: str = "R5D_MARKER",
    limit: int = MAX_PLANS,
) -> tuple[SQLRCEPlan, ...]:
    """Return DB-specific non-wire escalation plans in evidence-ranked order."""

    canonical = normalize_database(database)
    if injection_mode not in INJECTION_MODES:
        raise SQLRCEInputError(f"injection_mode must be one of: {', '.join(INJECTION_MODES)}")
    if not isinstance(marker, str) or not _MARKER_RE.fullmatch(marker):
        raise SQLRCEInputError("marker must be 4-32 letters, digits, or underscores")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PLANS:
        raise SQLRCEInputError(f"limit must be 1..{MAX_PLANS}")
    observed = _capabilities(capabilities)
    haystack = "\n".join(observed).casefold()
    compact = re.sub(r"[^a-z0-9]+", "", haystack)
    ranked: list[tuple[int, int, SQLRCEPlan]] = []
    for index, spec in enumerate(_PLAN_SPECS):
        if spec.database != canonical:
            continue
        matches = tuple(
            token for token in spec.evidence_tokens
            if token.casefold() in haystack
            or re.sub(r"[^a-z0-9]+", "", token.casefold()) in compact
        )
        unmet: list[str] = []
        if spec.statement_control and injection_mode not in ("stacked", "procedure"):
            unmet.append("standalone statement/procedure control is not evidenced")
        if injection_mode == "unknown":
            unmet.append("injection context has not been classified")
        readiness = "blocked_by_context" if unmet else "evidence_supported" if matches else "preconditions_unverified"
        descriptor = (
            "R5D_SQL_RCE_PLAN"
            f"|database={canonical}"
            f"|plan={spec.plan_id}"
            f"|marker={marker}"
            "|sql=NOT_EMITTED"
            "|command=NOT_EMITTED"
            "|action=REVIEW_ONLY"
        )
        plan = SQLRCEPlan(
            database=canonical,
            plan_id=spec.plan_id,
            primitive=spec.primitive,
            descriptor=descriptor,
            evidence=matches,
            preconditions=spec.preconditions,
            derivation=spec.derivation,
            unmet_context=tuple(unmet),
            readiness=readiness,
            rank=max(0, spec.rank + 5 * len(matches) - 15 * len(unmet)),
        )
        ranked.append((-plan.rank, index, plan))
    ranked.sort(key=lambda row: (row[0], row[1]))
    return tuple(row[2] for row in ranked[:limit])


def database_plan_matrix(
    *, injection_mode: str = "unknown", marker: str = "R5D_MARKER"
) -> tuple[SQLRCEPlan, ...]:
    return tuple(
        plan
        for database in DATABASES
        for plan in build_sql_rce_plans(database, injection_mode=injection_mode, marker=marker)
    )


def analyze_sql_metadata(saved_text: str | bytes | bytearray) -> tuple[SQLMetadataFinding, ...]:
    """Find product/privilege/feature leads in supplied saved text only."""

    if isinstance(saved_text, str):
        text = saved_text
    elif isinstance(saved_text, (bytes, bytearray)):
        raw = bytes(saved_text)
        if len(raw) > MAX_TEXT_BYTES:
            raise SQLRCEInputError(f"saved_text exceeds {MAX_TEXT_BYTES} bytes")
        text = raw.decode("utf-8", "replace")
    else:
        raise SQLRCEInputError("saved_text must be text or bytes")
    if len(text) > MAX_TEXT_CHARS:
        raise SQLRCEInputError(f"saved_text exceeds {MAX_TEXT_CHARS} characters")
    rows: list[SQLMetadataFinding] = []
    for database, kind, confidence, pattern, precondition in _EVIDENCE_PATTERNS:
        match = pattern.search(text)
        if match:
            rows.append(SQLMetadataFinding(
                database=database,
                kind=kind,
                evidence=text[max(0, match.start() - 40):min(len(text), match.end() + 80)],
                offset=match.start(),
                confidence=confidence,
                precondition=precondition,
            ))
    rows.sort(key=lambda row: (row.offset, DATABASES.index(row.database), row.kind))
    return tuple(rows)

