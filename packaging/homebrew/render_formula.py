#!/usr/bin/env python3
"""Render the Homebrew formula for a release: the template next to this file, with the
release's sdist (its URL and SHA-256) and one `resource` for every package the locked
dependency set installs with it.

    python3 -I packaging/homebrew/render_formula.py \\
        --url https://files.pythonhosted.org/packages/source/c/ctf-flightdeck/ctf_flightdeck-X.Y.Z.tar.gz \\
        --sha256 <the sdist's sha256> --lock uv.lock --output Formula/ctf-flightdeck.rb

The resources come from uv.lock: the packages ctf-flightdeck depends on, and theirs, without
its extras and its development group. Homebrew builds each from its sdist, so a package the
lock has no sdist for stops the rendering, by name. A dependency behind an environment marker
is a resource when the marker can hold on macOS or Linux (a Python version or a machine type
may hold; Windows and emscripten never do). A marker this script cannot read stops it too.

Standard library only, no network: the release workflow runs it, and so do the tests.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

PROJECT = "ctf-flightdeck"
TEMPLATE = Path(__file__).with_name("ctf-flightdeck.rb.in")
PLACEHOLDERS = ("{{URL}}", "{{SHA256}}", "{{RESOURCES}}")

# Where Homebrew installs: a marker on one of these names is decided against both rows.
PLATFORMS = (
    {"sys_platform": "darwin", "platform_system": "Darwin", "os_name": "posix"},
    {"sys_platform": "linux", "platform_system": "Linux", "os_name": "posix"},
)
# Markers that depend on the Python or the machine the formula is built with: taken as "may
# hold", so the package is a resource. An extra pure-Python resource costs a moment; a missing
# one breaks the install.
MAY_HOLD = ("python_version", "python_full_version", "platform_machine")
CLAUSE = re.compile(r"^(\w+) (==|!=|<=|>=|<|>) '([^']*)'$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FormulaError(Exception):
    """The formula cannot be rendered: the message says why."""


@dataclass(frozen=True)
class Resource:
    name: str
    url: str
    sha256: str


def marker_can_hold(marker: str) -> bool:
    """Whether `marker` can be true where Homebrew installs (macOS or Linux)."""
    if "(" in marker or ")" in marker:
        raise FormulaError(f"cannot read the marker {marker!r}: it has brackets, which this script does not parse")
    return any(_holds(marker, platform) for platform in PLATFORMS)


def _holds(marker: str, platform: dict[str, str]) -> bool:
    return any(all(_clause(clause.strip(), marker, platform) for clause in alternative.split(" and "))
               for alternative in marker.split(" or "))


def _clause(clause: str, marker: str, platform: dict[str, str]) -> bool:
    match = CLAUSE.match(clause)
    if not match:
        raise FormulaError(f"cannot read the marker {marker!r}: {clause!r} is not `name op 'value'`")
    name, op, value = match.groups()
    if name in MAY_HOLD:
        return True
    if name not in platform:
        raise FormulaError(f"cannot read the marker {marker!r}: this script does not know {name!r}")
    if op not in ("==", "!="):
        raise FormulaError(f"cannot read the marker {marker!r}: {name} is compared with {op}, not == or !=")
    return (platform[name] == value) == (op == "==")


def locked_resources(lock: dict, project: str = PROJECT) -> list[Resource]:
    """The packages `project` installs with it, by name: what its dependencies need, without
    its own extras and development groups."""
    packages: dict[str, dict] = {}
    for package in lock.get("package", []):
        if package["name"] in packages:
            raise FormulaError(f"the lock has two versions of {package['name']}: one formula can hold one")
        packages[package["name"]] = package
    if project not in packages:
        raise FormulaError(f"the lock has no package named {project}")

    wanted: set[str] = set()
    seen: set[tuple[str, str]] = set()
    queue = [(dep, project) for dep in packages[project].get("dependencies", [])]
    while queue:
        dep, parent = queue.pop()
        marker = dep.get("marker")
        if marker and not marker_can_hold(marker):
            continue
        name = dep["name"]
        if name not in packages:
            raise FormulaError(f"{parent} depends on {name}, which the lock does not hold")
        wanted.add(name)
        for part in ("", *dep.get("extra", [])):  # "" is the package itself; the rest are its extras this dependency asks for
            if (name, part) in seen:
                continue
            seen.add((name, part))
            package = packages[name]
            if part:
                optional = package.get("optional-dependencies", {})
                if part not in optional:
                    raise FormulaError(f"{parent} depends on {name}[{part}], and the lock has no such extra of {name}")
                more = optional[part]
            else:
                more = package.get("dependencies", [])
            queue.extend((child, name) for child in more)
    wanted.discard(project)

    resources = []
    for name in sorted(wanted):
        package = packages[name]
        sdist = package.get("sdist")
        if not sdist or "url" not in sdist:
            raise FormulaError(f"the lock has no sdist for {name} {package.get('version', '')}".rstrip()
                               + ": Homebrew builds every resource from source")
        digest = sdist.get("hash", "")
        if not digest.startswith("sha256:") or not SHA256.match(digest[len("sha256:"):]):
            raise FormulaError(f"the lock's hash for {name}'s sdist is not a sha256: {digest!r}")
        resources.append(Resource(name, _checked_url(sdist["url"], f"{name}'s sdist"), digest[len("sha256:"):]))
    return resources


def _checked_url(url: str, what: str) -> str:
    """A URL that is safe inside the formula's double quotes."""
    if not re.match(r"^https://[A-Za-z0-9._~:/?&=%+@-]+$", url):
        raise FormulaError(f"the URL of {what} is not a plain https URL: {url!r}")
    return url


def render(template: str, url: str, sha256: str, resources: list[Resource]) -> str:
    for placeholder in PLACEHOLDERS:
        if template.count(placeholder) != 1:
            raise FormulaError(f"the template must hold {placeholder} once, and holds it {template.count(placeholder)} times")
    url = _checked_url(url, "the release's sdist")
    if not url.endswith(".tar.gz"):
        raise FormulaError(f"the URL of the release's sdist does not end in .tar.gz: {url!r}")
    if not SHA256.match(sha256):
        raise FormulaError(f"the release's sha256 must be 64 lowercase hex digits, not {sha256!r}")
    if not resources:
        raise FormulaError("no resources: a formula without its dependencies cannot install")
    blocks = "\n\n".join(f'  resource "{r.name}" do\n    url "{r.url}"\n    sha256 "{r.sha256}"\n  end' for r in resources)
    line = next(line for line in template.splitlines() if "{{RESOURCES}}" in line)
    if line != "{{RESOURCES}}":
        raise FormulaError("the template's {{RESOURCES}} must be a line of its own, with no indent")
    return template.replace("{{URL}}", url).replace("{{SHA256}}", sha256).replace("{{RESOURCES}}", blocks)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render the Homebrew formula of a ctf-flightdeck release.")
    parser.add_argument("--url", required=True, help="the release's sdist on PyPI")
    parser.add_argument("--sha256", required=True, help="that file's SHA-256")
    parser.add_argument("--lock", type=Path, required=True, help="uv.lock of the release")
    parser.add_argument("--template", type=Path, default=TEMPLATE, help="the formula template (default: the one next to this script)")
    parser.add_argument("--output", type=Path, help="where to write the formula (default: standard output)")
    args = parser.parse_args(argv)
    try:
        try:
            lock = tomllib.loads(args.lock.read_text(encoding="utf-8"))
            template = args.template.read_text(encoding="utf-8")
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise FormulaError(str(exc)) from None
        formula = render(template, args.url, args.sha256, locked_resources(lock))
    except FormulaError as exc:
        print(f"render_formula: {exc}", file=sys.stderr)
        return 1
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(formula, encoding="utf-8")
    else:
        sys.stdout.write(formula)
    return 0


if __name__ == "__main__":
    sys.exit(main())
