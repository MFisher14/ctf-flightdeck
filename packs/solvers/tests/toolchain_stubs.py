"""Test helpers for the B-188 toolchain tests: a stub docker and a synthetic checkout.

The stub docker is a Python script carrying the stub marker (ctf.toolchain.images.STUB_MARKER), so the
CTF_TESTING guard lets it run. It answers from a JSON state file and logs every call (JSON lines):

    images      {tag: labels-dict-or-null}: `image inspect` prints the labels; a tag not here is
                "No such image" (exit 1)
    down        true: every call fails like a stopped daemon
    build_rc    exit code of `build` (it logs the staged context's file names and the staged pin files)
    run_fail    a command word: `run` exits 3 when the command contains it
"""
from __future__ import annotations

import json
import os
import sys
import textwrap
from pathlib import Path

from ctf.toolchain import images

STUB = textwrap.dedent('''\
    #!{python} -I
    # {marker}
    import json, os, sys
    state = json.load(open(os.environ["STUB_STATE"]))
    args = sys.argv[1:]
    entry = {{"argv": args}}
    rc = 0
    if state.get("down"):
        print("Cannot connect to the Docker daemon", file=sys.stderr)
        rc = 1
    elif args[:2] == ["image", "inspect"]:
        tag = args[-1]
        if tag in state.get("images", {{}}):
            print(json.dumps(state["images"][tag]))
        else:
            print("Error response from daemon: No such image: " + tag, file=sys.stderr)
            rc = 1
    elif args[:1] == ["build"]:
        ctx = args[-1]
        names = sorted(os.listdir(ctx))
        entry["context_files"] = names
        entry["staged"] = {{n: open(os.path.join(ctx, n)).read() for n in names if n.startswith("toolchain-")}}
        print("built")
        rc = state.get("build_rc", 0)
    elif args[:1] == ["run"]:
        fail = state.get("run_fail")
        print("ran " + " ".join(args))
        rc = 3 if fail and fail in args else 0
    with open(os.environ["STUB_LOG"], "a") as fh:
        fh.write(json.dumps(entry) + "\\n")
    sys.exit(rc)
    ''')


def docker_stub(tmp: Path, state: dict, *, marker: bool = True) -> dict:
    """A bin folder with a stub docker; returns the environ to pass (PATH, STUB_STATE, STUB_LOG)."""
    bindir = tmp / "stubbin"
    bindir.mkdir(parents=True, exist_ok=True)
    exe = bindir / "docker"
    exe.write_text(STUB.format(python=sys.executable, marker=images.STUB_MARKER if marker else "plain"))
    exe.chmod(0o755)
    st = tmp / "stub-state.json"
    st.write_text(json.dumps(state))
    log = tmp / "stub-log.jsonl"
    return {"PATH": str(bindir), "STUB_STATE": str(st), "STUB_LOG": str(log), "CTF_TESTING": "1",
            "HOME": str(tmp)}


def set_state(environ: dict, state: dict) -> None:
    Path(environ["STUB_STATE"]).write_text(json.dumps(state))


def calls(environ: dict) -> list[dict]:
    p = Path(environ["STUB_LOG"])
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]


REQUIREMENTS = "capstone==5.0.9\nlief==1.0.0\nrequests==2.34.2  # a comment\n"


def checkout(tmp: Path, manifest: str, files: dict[str, str] | None = None,
             requirements: str = REQUIREMENTS) -> Path:
    """A synthetic checkout: tools/images.toml from `manifest`, requirements.in, and `files`."""
    root = tmp / "root"
    (root / "tools").mkdir(parents=True, exist_ok=True)
    (root / "tools" / "images.toml").write_text(textwrap.dedent(manifest))
    (root / "requirements.in").write_text(requirements)
    for rel, text in (files or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return root


def write(p: Path, text: str, mode: int | None = None) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text))
    if mode is not None:
        os.chmod(p, mode)
    return p
