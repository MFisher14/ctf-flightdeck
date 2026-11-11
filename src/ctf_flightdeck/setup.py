"""First-run help: `flightdeck init` writes a config, `flightdeck doctor` checks a setup.

Both exist so a new player gets from install to a running console without reading the
architecture (the v0.1.0 requirement). Neither ever asks for, reads out or stores the API
key itself: the config names the environment variable that holds it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import __version__

PROVIDERS = {
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "local": ("http://127.0.0.1:11434/v1", ""),  # Ollama's OpenAI-compatible endpoint; no key
    "mlx": ("http://127.0.0.1:8080/v1", ""),  # an MLX server on this Mac (mlx_lm.server's default port); no key
}
LOCAL_PROVIDERS = ("local", "mlx")  # nothing to spend: no dollar cap
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


@dataclass(frozen=True)
class Answers:
    """What `init` needs; asked interactively or given as options."""

    base_url: str
    key_env: str  # "" for a local server with no key
    models: tuple[str, ...]  # weakest first
    runtime: str  # docker | host
    max_lanes: int = 4
    token_cap: int | None = 400_000
    dollar_cap: float | None = 2.0


def render(answers: Answers) -> str:
    """The config file for `answers`, with comments a player can follow."""
    models = ", ".join(f'"{m}"' for m in answers.models)
    token_cap = str(answers.token_cap) if answers.token_cap else "false"
    dollar_cap = f"{answers.dollar_cap:g}" if answers.dollar_cap else "false"
    return (
        "# flightdeck config, written by `flightdeck init`. Check it with `flightdeck doctor`.\n"
        "\n"
        "[api]\n"
        f'base_url = "{answers.base_url}"\n'
        f'key_env = "{answers.key_env}"   # the environment variable holding your key (never the key)\n'
        "\n"
        "[models]\n"
        f"ladder = [{models}]   # weakest first; escalation moves right\n"
        "\n"
        "[lanes]\n"
        f"max_lanes = {answers.max_lanes}\n"
        f'runtime = "{answers.runtime}"\n'
        + (f'image = "{_lane_image()}"   # build it with `flightdeck image build`\n' if answers.runtime == "docker" else "")
        +
        f"token_cap = {token_cap}\n"
        f"dollar_cap = {dollar_cap}\n"
        'submit = "confirm"   # you approve every flag before it is submitted\n'
    )


def _lane_image() -> str:
    from .lane import IMAGE

    return IMAGE


def write_config(answers: Answers, path: Path, *, force: bool = False) -> Path:
    """Validate the config by loading it, then write it. Refuses to overwrite unless force."""
    from .config import load_config

    text = render(answers)
    with tempfile.TemporaryDirectory() as tmp:
        trial = Path(tmp) / "config.toml"
        trial.write_text(text, encoding="utf-8")
        load_config(trial)  # ConfigError says what is wrong before anything is written
    if path.exists() and not force:
        raise FileExistsError(f"{path} exists; use --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str  # what was found
    fix: str = ""  # what to do when not ok
    essential: bool = True  # a failing essential check makes doctor exit 1


def doctor(config_path: Path | None = None, *, environ: Mapping[str, str] = os.environ) -> list[Check]:
    """Every check, in order. Never prints or returns the API key."""
    from .config import ConfigError, default_config_path, load_config

    checks: list[Check] = []
    version_ok = sys.version_info >= (3, 12)
    checks.append(Check("python", version_ok, f"Python {sys.version.split()[0]}, flightdeck {__version__}",
                        "flightdeck needs Python 3.12 or newer"))
    path = (config_path or default_config_path()).expanduser()
    config = None
    if not path.exists():
        checks.append(Check("config", False, f"no config at {path}", "run `flightdeck init` to write one"))
    else:
        try:
            config = load_config(path)
        except ConfigError as exc:
            checks.append(Check("config", False, str(exc), "fix it, or run `flightdeck init --force` to write a new one"))
        else:
            checks.append(Check("config", True, f"{path}: {len(config.models)} model(s), runtime {config.lanes.runtime}"))
    if config is not None:
        name = config.api.key_env
        if not name:
            checks.append(Check("api key", True, "the config's API needs no key"))
        else:
            present = bool(environ.get(name, "").strip())
            checks.append(Check("api key", present, f"{name} is {'set' if present else 'not set'}",
                                f"export {name}=<your key> in the shell you run flightdeck from"))
    if config is not None:
        checks += _local_server_check(config.api.base_url)
    if config is not None and config.l1.pack is not None:
        checks.append(_l1_check(config.l1.pack))
    runtime = config.lanes.runtime if config is not None else "docker"
    checks += _docker_checks(config.lanes.image if config is not None else None, essential=runtime == "docker")
    try:
        columns, lines = os.get_terminal_size()
    except OSError:
        columns = lines = 0
    if columns:
        big = columns >= 100 and lines >= 30
        checks.append(Check("terminal", big, f"{columns}x{lines}",
                            "the console is easiest at 100x30 or more (it works smaller)", essential=False))
    return checks


def _l1_check(pack: Path) -> Check:
    """The [l1] pack loads and holds engines (a run refuses to start otherwise)."""
    from .l1.manifest import ManifestError, discover

    try:
        engines = discover(pack)
    except ManifestError as exc:
        return Check("l1 pack", False, str(exc), "fix the manifest it names, or remove [l1] pack from the config")
    if not engines:
        return Check("l1 pack", False, f"{pack} has no engines (no .manifest.toml files)",
                     "`flightdeck l1 import` writes manifests for a folder of scripts")
    return Check("l1 pack", True, f"{pack}: {len(engines)} engine(s)")


def _local_server_check(base_url: str) -> list[Check]:
    """For an API on this machine (Ollama, an MLX server), check that it answers. A remote
    API is never contacted here."""
    from urllib.parse import urlsplit

    import httpx

    host = urlsplit(base_url).hostname or ""
    if host not in LOCAL_HOSTS:
        return []
    url = base_url.rstrip("/") + "/models"
    try:
        answer = httpx.get(url, timeout=2.0, follow_redirects=False)
    except httpx.HTTPError as exc:
        return [Check("model server", False, f"nothing answers at {base_url} ({type(exc).__name__})",
                      "start your local model server (it must speak the OpenAI API with tool calling)")]
    ok = answer.status_code < 400
    return [Check("model server", ok, f"{url} answered {answer.status_code}",
                  "check the server's address and port in [api] base_url")]


def _docker_checks(image: str | None, *, essential: bool) -> list[Check]:
    from .agent.workspace import docker_unavailable
    from .lane import IMAGE

    reason = docker_unavailable()
    if reason:
        return [Check("docker", False, reason, "start Docker, or use the host runtime (--host)", essential)]
    out = [Check("docker", True, "running")]
    if image is not None:
        docker = shutil.which("docker") or "docker"
        found = subprocess.run([docker, "image", "inspect", image], capture_output=True).returncode == 0
        how = "flightdeck image build" if image == IMAGE else f"docker pull {image}"
        out.append(Check("lane image", found, f"{image} is {'present' if found else 'not on this machine'}", f"run `{how}`", essential))
    return out


def report(checks: Sequence[Check]) -> tuple[str, int]:
    """The checks as lines for the terminal, and the exit status (1 if an essential check failed)."""
    lines = []
    for check in checks:
        mark = "ok  " if check.ok else ("FAIL" if check.essential else "warn")
        lines.append(f"{mark} {check.name}: {check.detail}")
        if not check.ok and check.fix:
            lines.append(f"     fix: {check.fix}")
    failed = any(not c.ok and c.essential for c in checks)
    lines.append("" if failed else "Ready. Try `flightdeck practice`.")
    return "\n".join(lines).rstrip() + "\n", 1 if failed else 0
