"""packaging/homebrew/render_formula.py: the Homebrew formula of a release, from the sdist's
URL and SHA-256 and the locked dependency set. A synthetic lock, no network; the script is
loaded from its file (it is not part of the package)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "packaging" / "homebrew" / "render_formula.py"

spec = importlib.util.spec_from_file_location("render_formula", SCRIPT)
render_formula = importlib.util.module_from_spec(spec)
sys.modules["render_formula"] = render_formula  # dataclasses looks its module up there
spec.loader.exec_module(render_formula)
FormulaError, Resource = render_formula.FormulaError, render_formula.Resource

URL = "https://files.pythonhosted.org/packages/ab/cd/ctf_flightdeck-9.9.9.tar.gz"
SHA = "0123456789abcdef" * 4


def sha(letter: str) -> str:
    return letter * 64


def package(name: str, *, deps: str = "", extras: str = "", sdist: bool = True, source: str = "") -> str:
    lines = ["[[package]]", f'name = "{name}"', 'version = "1.0"',
             source or 'source = { registry = "https://pypi.org/simple" }']
    if deps:
        lines.append(f"dependencies = [{deps}]")
    if sdist:
        lines.append(f'sdist = {{ url = "https://files.example/{name}-1.0.tar.gz", hash = "sha256:{sha(name[0])}" }}')
    lines.append(f'wheels = [{{ url = "https://files.example/{name}-1.0-py3-none-any.whl", hash = "sha256:{sha("f")}" }}]')
    if extras:
        lines.append(f"\n[package.optional-dependencies]\n{extras}")
    return "\n".join(lines) + "\n"


# ctf-flightdeck needs alpha and bravo[fast]; alpha needs charlie everywhere and winonly on
# Windows; bravo's extra `fast` needs delta, its extra `slow` needs unused; charlie needs
# alpha back (a cycle) and echo on old Pythons. devtool is the development group's, extraonly
# an extra's of the project itself.
LOCK = "version = 1\n\n" + "\n".join([
    package("ctf-flightdeck", source='source = { editable = "." }', sdist=False,
            deps='{ name = "alpha" }, { name = "bravo", extra = ["fast"] }',
            extras='cactus = [{ name = "extraonly" }]\n\n[package.dev-dependencies]\ndev = [{ name = "devtool" }]'),
    package("alpha", deps='{ name = "charlie" }, { name = "winonly", marker = "sys_platform == \'win32\'" }'),
    package("bravo", extras='fast = [{ name = "delta" }]\nslow = [{ name = "unused" }]'),
    package("charlie", deps='{ name = "alpha" }, { name = "echo", marker = "python_full_version < \'3.13\'" }'),
    package("delta"), package("echo"), package("winonly"), package("unused"), package("devtool"), package("extraonly"),
])

TEMPLATE = 'class X < Formula\n  url "{{URL}}"\n  sha256 "{{SHA256}}"\n\n{{RESOURCES}}\n\n  def install\n  end\nend\n'


def resources(lock_text: str = LOCK):
    return render_formula.locked_resources(tomllib.loads(lock_text))


def test_the_resources_are_what_the_project_installs_and_nothing_else():
    found = resources()
    assert [r.name for r in found] == ["alpha", "bravo", "charlie", "delta", "echo"]  # sorted; no project, extra, dev or Windows package
    assert found[0] == Resource("alpha", "https://files.example/alpha-1.0.tar.gz", sha("a"))  # the sdist, never the wheel


def test_the_rendered_formula_holds_the_release_and_each_resource():
    formula = render_formula.render(TEMPLATE, URL, SHA, resources()[:2])
    assert formula == f'''class X < Formula
  url "{URL}"
  sha256 "{SHA}"

  resource "alpha" do
    url "https://files.example/alpha-1.0.tar.gz"
    sha256 "{sha("a")}"
  end

  resource "bravo" do
    url "https://files.example/bravo-1.0.tar.gz"
    sha256 "{sha("b")}"
  end

  def install
  end
end
'''


@pytest.mark.parametrize("marker, holds", [
    ("sys_platform == 'win32'", False),
    ("sys_platform == 'emscripten'", False),
    ("sys_platform != 'emscripten'", True),
    ("sys_platform == 'darwin'", True),  # macOS only: still a resource
    ("sys_platform == 'linux'", True),
    ("platform_system == 'Windows'", False),
    ("os_name == 'nt'", False),
    ("python_full_version < '3.13'", True),
    ("platform_machine == 'aarch64' or platform_machine == 'x86_64'", True),
    ("python_full_version < '3.13' and sys_platform == 'win32'", False),
    ("sys_platform == 'win32' or sys_platform == 'linux'", True),
    ("sys_platform == 'win32' or python_version >= '3.12' and os_name == 'nt'", False),  # `and` binds tighter
])
def test_a_marker_is_decided_for_macos_and_linux(marker, holds):
    assert render_formula.marker_can_hold(marker) is holds


@pytest.mark.parametrize("marker, why", [
    ("(sys_platform == 'win32')", "it has brackets"),
    ("implementation_name == 'pypy'", "does not know 'implementation_name'"),
    ("extra == 'fast'", "does not know 'extra'"),
    ("sys_platform < 'win32'", "sys_platform is compared with <"),
    ("sys_platform in 'win32'", "is not `name op 'value'`"),
])
def test_a_marker_the_script_cannot_read_stops_it_rather_than_guessing(marker, why):
    with pytest.raises(FormulaError, match=why):
        render_formula.marker_can_hold(marker)


def test_a_dependency_without_an_sdist_stops_the_rendering_by_name():
    lock = LOCK.replace(package("delta"), package("delta", sdist=False))
    assert lock != LOCK
    with pytest.raises(FormulaError, match="the lock has no sdist for delta 1.0: Homebrew builds every resource from source"):
        resources(lock)
    resources(LOCK.replace(package("unused"), package("unused", sdist=False)))  # one nothing installs is no problem


@pytest.mark.parametrize("change, why", [
    (lambda lock: lock.replace(package("echo"), ""), "charlie depends on echo, which the lock does not hold"),
    (lambda lock: lock.replace('extra = ["fast"]', 'extra = ["quick"]'), r"depends on bravo\[quick\], and the lock has no such extra"),
    (lambda lock: lock.replace(f"sha256:{sha('d')}", "md5:abc"), "hash for delta's sdist is not a sha256"),
    (lambda lock: lock.replace("https://files.example/delta-1.0.tar.gz", 'https://files.example/d\\"; system \\"x'), "URL of delta's sdist is not a plain https URL"),
    (lambda lock: lock.replace("https://files.example/delta", "http://files.example/delta"), "URL of delta's sdist is not a plain https URL"),
    (lambda lock: lock + package("delta"), "the lock has two versions of delta"),
    (lambda lock: lock.replace('name = "ctf-flightdeck"', 'name = "other"'), "the lock has no package named ctf-flightdeck"),
])
def test_a_lock_that_cannot_give_a_formula_stops_the_rendering(change, why):
    changed = change(LOCK)
    assert changed != LOCK
    with pytest.raises(FormulaError, match=why):
        resources(changed)


@pytest.mark.parametrize("template, url, digest, found, why", [
    (TEMPLATE.replace("{{SHA256}}", "x"), URL, SHA, None, "must hold {{SHA256}} once, and holds it 0 times"),
    (TEMPLATE + "{{URL}}", URL, SHA, None, "must hold {{URL}} once, and holds it 2 times"),
    (TEMPLATE.replace("{{RESOURCES}}", "  {{RESOURCES}}"), URL, SHA, None, "must be a line of its own"),
    (TEMPLATE, URL, SHA.upper(), None, "64 lowercase hex digits"),
    (TEMPLATE, URL, SHA[:-1], None, "64 lowercase hex digits"),
    (TEMPLATE, URL.replace(".tar.gz", ".whl"), SHA, None, "does not end in .tar.gz"),
    (TEMPLATE, 'https://x/a".tar.gz', SHA, None, "not a plain https URL"),
    (TEMPLATE, URL, SHA, [], "no resources"),
])
def test_a_release_or_template_that_is_wrong_stops_the_rendering(template, url, digest, found, why):
    with pytest.raises(FormulaError, match=why):
        render_formula.render(template, url, digest, resources() if found is None else found)


def test_the_script_writes_the_formula_or_fails_in_one_line(tmp_path):
    lock = tmp_path / "uv.lock"
    lock.write_text(LOCK)
    out = tmp_path / "tap" / "Formula" / "ctf-flightdeck.rb"
    base = [sys.executable, "-I", str(SCRIPT), "--lock", str(lock), "--url", URL]
    done = subprocess.run([*base, "--sha256", SHA, "--output", str(out)], capture_output=True, text=True)
    assert (done.returncode, done.stdout, done.stderr) == (0, "", "")
    formula = out.read_text()
    assert formula.count("  resource ") == 5 and f'url "{URL}"\n  sha256 "{SHA}"' in formula
    assert "{{" not in formula

    bad = subprocess.run([*base, "--sha256", "nope", "--output", str(tmp_path / "never.rb")], capture_output=True, text=True)
    assert bad.returncode == 1 and bad.stdout == ""
    assert bad.stderr == "render_formula: the release's sha256 must be 64 lowercase hex digits, not 'nope'\n"
    assert not (tmp_path / "never.rb").exists()

    absent = subprocess.run([*base[:3], "--lock", str(tmp_path / "no.lock"), "--url", URL, "--sha256", SHA], capture_output=True, text=True)
    assert absent.returncode == 1 and absent.stderr.startswith("render_formula: ") and "no.lock" in absent.stderr


def test_the_repositorys_own_template_and_lock_render():
    """The real template with the real uv.lock: the formula a release would get."""
    lock = tomllib.loads((REPO / "uv.lock").read_text())
    found = render_formula.locked_resources(lock)
    names = [r.name for r in found]
    for needed in ("anthropic", "httpx", "textual", "typer", "pydantic-core"):
        assert needed in names
    for never in ("ctf-flightdeck", "pytest", "cactus-compute", "colorama"):  # the project, dev, an extra, Windows
        assert never not in names
    formula = render_formula.render(render_formula.TEMPLATE.read_text(), URL, SHA, found)
    assert formula.count("\n  resource ") == len(found) and "{{" not in formula
    assert "class CtfFlightdeck < Formula\n  include Language::Python::Virtualenv\n" in formula
    assert "  def install\n    virtualenv_install_with_resources\n  end\n" in formula
    assert formula.index("depends_on") < formula.index("resource ") < formula.index("def install") < formula.index("test do")
    for command in ("flightdeck", "ctfdeck", "ctf-flightdeck"):
        assert f'assert_equal "{command} #{{version}}", shell_output("#{{bin}}/{command} --version").strip' in formula
