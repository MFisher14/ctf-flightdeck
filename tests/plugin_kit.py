"""Synthetic plugins for the tests: a folder in tmp_path with a plugin.toml and an adapter that
answers from a file beside it and records every call. Never a real platform's adapter, and
nothing here uses the network.

The adapter reads replies.json: for each op, what to do when it is called (one directive, or
a list of them, one per call with the last repeated). A directive is a dict:

    answer   the JSON object to print on stdout
    raw      text to print on stdout as it is, in place of an answer
    bytes    print this many bytes of filler on stdout, in place of an answer
    write    {relative path: text}: files to put in the pull's files folder first
    stderr   text for stderr; "{token}" in it becomes the token the adapter was given
    exit     the exit status (default 0)
    sleep    seconds to wait before answering
    child    true: start a child process that sleeps a minute, and record its pid

Each call appends a line to calls.jsonl: the request, the whole environment, the working
directory, the arguments, the adapter's pid and its child's.
"""

from __future__ import annotations

import json
from pathlib import Path

TOKEN = "fake-plugin-token-for-tests-4417"  # not a real token, and not shaped like one

ADAPTER = r'''
import json, os, subprocess, sys, time

here = os.path.dirname(os.path.abspath(__file__))
request = json.load(sys.stdin)
log = os.path.join(here, "calls.jsonl")
before = [json.loads(line) for line in open(log)] if os.path.exists(log) else []
nth = sum(1 for call in before if call["request"].get("op") == request.get("op"))
with open(os.path.join(here, "replies.json")) as f:
    reply = json.load(f)[request["op"]]
if isinstance(reply, list):
    reply = reply[min(nth, len(reply) - 1)]
child = None
if reply.get("child"):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]).pid
with open(log, "a") as out:
    out.write(json.dumps({"request": request, "env": dict(os.environ), "cwd": os.getcwd(), "argv": sys.argv,
                          "pid": os.getpid(), "child": child}) + "\n")
for rel, text in reply.get("write", {}).items():
    target = os.path.join(request["files"], rel)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w") as f:
        f.write(text)
if "stderr" in reply:
    sys.stderr.write(reply["stderr"].replace("{token}", os.environ.get("FLIGHTDECK_PLUGIN_TOKEN", "")))
    sys.stderr.flush()
if "sleep" in reply:
    time.sleep(reply["sleep"])
if "bytes" in reply:
    sys.stdout.write("x" * reply["bytes"])
elif "raw" in reply:
    sys.stdout.write(reply["raw"])
elif "answer" in reply:
    json.dump(reply["answer"], sys.stdout)
sys.stdout.flush()
sys.exit(reply.get("exit", 0))
'''

MANIFEST = 'name = "{name}"\napi = 1\ncommand = ["{{python}}", "adapter.py"]\nversion = "0.3.1"\ndescription = "Acme events"\n'


def make_plugin(folder: Path, replies: dict | None = None, *, name: str = "acme", toml: str | None = None) -> Path:
    """A plugin folder: plugin.toml (`toml`, else a valid one for `name`), the recording
    adapter and its replies."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "plugin.toml").write_text(MANIFEST.format(name=name) if toml is None else toml)
    (folder / "adapter.py").write_text(ADAPTER)
    set_replies(folder, replies or {})
    return folder


def set_replies(folder: Path, replies: dict) -> None:
    (folder / "replies.json").write_text(json.dumps(replies))


def calls(folder: Path) -> list[dict]:
    """Every call the adapter got so far, in order."""
    path = folder / "calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def challenge(ref: str, name: str, **fields) -> dict:
    """One challenge as a pull's answer lists it."""
    return {"ref": ref, "name": name, "category": "misc", "points": 100, "description": "a synthetic challenge", **fields}
