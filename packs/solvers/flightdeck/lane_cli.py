"""`solvers`: the pack's engines from a lane's shell.

    solvers fit [DIR]                 the engines that fit the challenge in DIR (default: .), best first
    solvers run ENGINE [ARGS...]      run one engine (ARGS as `solvers doc ENGINE` says; usually a file)
    solvers doc ENGINE                what an engine does and how to call it
    solvers playbook [CATEGORY]       the approach notes for a category (no CATEGORY: the list)
    solvers list [WORD]               every engine id, or those whose id or tags hold WORD

    -f RE, --flag-format RE           the event's flag format (the brief gives it); before the command

A lane's model calls this while it works a challenge; flightdeck's brief says where it is. It
runs the pack's own router and runner with an event profile made for the challenge in DIR: the
flag format's literal prefixes, and as live-service scope only the hosts the challenge's own
`urls` name. Nothing here submits a flag or talks to a platform.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
PACK = HERE.parent
sys.path.insert(0, str(HERE))
import intake_engine as _adapter  # noqa: E402

USAGE = __doc__.split("\n\n")[1]


def _hosts(urls) -> tuple[str, ...]:
    out = []
    for url in urls if isinstance(urls, list) else []:
        host = urlsplit(url).hostname if isinstance(url, str) else None
        if host and re.fullmatch(r"[A-Za-z0-9.-]+", host) and host not in out:
            out.append(host)
    return tuple(out)


def _environment(folder: Path, flag_format: str | None, work: Path) -> dict:
    """The pack's event environment for the challenge in `folder`."""
    data = _adapter.read_challenge(folder)
    prefixes = (_adapter.prefixes_of(flag_format) if flag_format else ()) or _adapter.COMMON_PREFIXES
    events = work / "events"
    (events / _adapter.SLUG).mkdir(parents=True, exist_ok=True)
    (events / _adapter.SLUG / "event.toml").write_text(
        _adapter.profile_toml(prefixes, "flightdeck board", _hosts(data.get("urls"))), encoding="utf-8")
    (work / "work").mkdir(exist_ok=True)
    return {**os.environ, "CTF_EVENTS_DIR": str(events), "CTF_EVENT": _adapter.SLUG, "CTF_WORKDIR": str(work / "work"),
            "CTF_ENGINE_LEDGER": "0", "PYTHONDONTWRITEBYTECODE": "1"}


def _ctf(args: list[str], env: dict) -> int:
    return subprocess.run([sys.executable, "-m", "ctf", *args], cwd=PACK, env=env).returncode


def _manifests():
    sys.path.insert(0, str(PACK))
    from ctf.engines import manifest
    return manifest.discover(PACK)


def _find(name: str):
    ms = _manifests()
    exact = [m for m in ms if m.id == name]
    loose = exact or [m for m in ms if m.id.split(".", 1)[-1] == name or m.module_path.stem == name]
    if len(loose) != 1:
        near = ", ".join(m.id for m in ms if name.lower() in m.id.lower())[:400]
        sys.exit(f"solvers: {'no' if not loose else 'more than one'} engine {name!r}" + (f"; close: {near}" if near else ""))
    return loose[0]


def main(argv: list[str]) -> int:
    args = argv[1:]
    flag_format = os.environ.get(_adapter.FORMAT_ENV) or None
    while args and args[0] in ("-f", "--flag-format"):
        if len(args) < 2:
            sys.exit("solvers: -f needs the flag format")
        flag_format, args = args[1], args[2:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    command, rest = args[0], args[1:]
    if command == "playbook":
        books = PACK / "docs" / "playbooks"
        if not rest:
            print("playbooks: " + ", ".join(sorted(p.stem for p in books.glob("*.md"))))
            return 0
        name = re.sub(r"[^a-z0-9_-]", "", rest[0].lower())
        aliases = {"cry": "crypto", "rev": "reverse", "for": "forensics", "net": "networking", "network": "networking"}
        path = books / f"{aliases.get(name, name)}.md"
        if not path.is_file():
            sys.exit(f"solvers: no playbook {rest[0]!r}; `solvers playbook` lists them")
        print(path.read_text(encoding="utf-8"))
        return 0
    if command == "list":
        word = rest[0].lower() if rest else ""
        for m in _manifests():
            if m.status == "active" and (not word or word in m.id.lower() or any(word in c for c in m.capabilities)):
                print(f"{m.id}  [{', '.join(m.capabilities[:6])}]")
        return 0
    if command == "doc":
        if not rest:
            sys.exit("solvers: doc needs an engine")
        m = _find(rest[0])
        page = PACK / "docs" / "toolkits" / f"{m.module_path.stem}.md"
        print(f"{m.id}: {m.module_path.relative_to(PACK)}  [{', '.join(m.capabilities)}]  needs: {', '.join(m.needs_tools) or 'nothing'}")
        if page.is_file():
            print(page.read_text(encoding="utf-8")[:6000])
        else:
            import ast
            doc = ast.get_docstring(ast.parse(m.module_path.read_text(encoding="utf-8"))) or "(no description)"
            print(doc[:4000])
        print(f"\nrun it: solvers run {m.id} ARGS   (its own help: solvers run {m.id} --help)")
        return 0
    with tempfile.TemporaryDirectory(prefix="fd-solvers-") as tmp:
        if command == "fit":
            folder = Path(rest[0] if rest else ".").resolve()
            data = _adapter.read_challenge(folder)
            env = _environment(folder, flag_format, Path(tmp))
            text = " ".join(str(data.get(k) or "") for k in ("name", "description"))
            return _ctf(["engines", "route", "--files", str(folder), str(data.get("category") or "misc"), text], env)
        if command == "run":
            if not rest:
                sys.exit("solvers: run needs an engine")
            m = _find(rest[0])
            env = _environment(Path.cwd(), flag_format, Path(tmp))
            fixed = [str(Path(a).resolve()) if a and not a.startswith("-") and Path(a).exists() else a for a in rest[1:]]
            return _ctf(["run", "--no-ledger", m.id, *fixed], env)
    sys.exit(f"solvers: unknown command {command!r}\n{USAGE}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
