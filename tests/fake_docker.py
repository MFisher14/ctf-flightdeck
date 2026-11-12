"""A fake `docker` for the coding-agent lanes' tests in Docker: no container, no image, no
network. Never the real docker.

It plays a lane's container on this machine. `docker run` records the container: its bind
mount of the workspace at /work, and a folder of its own that stands for the rest of its
filesystem (`fs`: tmp/ open to all with the sticky bit, root/, and the image's CLIs in
usr/local/bin/, links to tests/fake_agent_cli.py's wrappers). `docker exec` runs the command
on this machine with the container's paths made this machine's: /work and below the
workspace, any other absolute path (an argument, an -e value, -w) the same path under `fs`,
so what the CLI keeps outside /work lands under `fs` and never in the workspace, as in a
container. -e NAME takes the value from its own environment, as docker does, and the command
gets nothing else of it (a PATH of the system's folders, a HOME of root/). exec becomes the
command (same pid): the pid the lane's wrapper says is the CLI's is a pid on this machine,
and so is what `docker exec ... sh -c <signal script> sh SIG PID TREE` signals (the script
reads /proc, which macOS has not). `docker rm -f` forgets the container and kills what its
execs left running.

An L1 engine's container (l1/container.py) is played the same way: its read-only mounts
(`-v <path>:<path>:ro`: the pack, flightdeck's l1 package) are this machine's folders at
their own paths, and a command given by a path in one of this machine's system folders
(what the container's program lookup answered: its PATH is SYSTEM_PATH) is this machine's.

How it runs: tests/test_external.py writes bin/docker, a small Python script that sets
FAKE_DOCKER_STATE (its folder) and execs `python -I fake_docker.py <docker's arguments>`.
Every call is appended to calls.jsonl there (its arguments: no secret's value is ever one).
clis.json there names the image's CLIs ({"claude": path, ...}).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys

STATE = os.environ.get("FAKE_DOCKER_STATE", "")
SIGNALS = {"STOP": signal.SIGSTOP, "CONT": signal.SIGCONT, "INT": signal.SIGINT, "TERM": signal.SIGTERM,
           "KILL": signal.SIGKILL}
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def fail(message: str, status: int = 1) -> None:
    sys.stderr.write(message + "\n")
    sys.exit(status)


def record(args: list[str]) -> None:
    with open(os.path.join(STATE, "calls.jsonl"), "a", encoding="utf-8") as out:
        out.write(json.dumps({"argv": args}) + "\n")


def folder(name: str) -> str:
    return os.path.join(STATE, "containers", name)


def info(name: str) -> dict | None:
    try:
        with open(os.path.join(folder(name), "info.json"), encoding="utf-8") as f:
            return json.load(f)
    except OSError:
        return None


def run(args: list[str]) -> None:
    name, root, i = "", "", 0
    mounts: dict[str, str] = {}
    while i < len(args):
        arg = args[i]
        if arg == "--name":
            name = args[i + 1]
            i += 2
            continue
        if arg == "-v":
            source, _, target = args[i + 1].partition(":")
            if target == "/work":
                root = source
            elif target.endswith(":ro"):
                mounts[target[:-len(":ro")]] = source
            i += 2
            continue
        i += 1
    if not name or not root:
        fail("fake docker: run needs --name and a -v <folder>:/work")
    if info(name) is not None:
        fail(f'docker: Error response from daemon: Conflict. The container name "/{name}" is already in use', 125)
    fs = os.path.join(folder(name), "fs")
    for sub, mode in (("tmp", 0o1777), ("root", 0o700), ("usr/local/bin", 0o755)):
        os.makedirs(os.path.join(fs, sub), exist_ok=True)
        os.chmod(os.path.join(fs, sub), mode)
    with open(os.path.join(STATE, "clis.json"), encoding="utf-8") as f:
        for cli, path in json.load(f).items():
            os.symlink(path, os.path.join(fs, "usr/local/bin", cli))
    with open(os.path.join(folder(name), "info.json"), "w", encoding="utf-8") as f:
        json.dump({"root": root, "fs": fs, "pids": [], "mounts": mounts}, f)
    print(f"fake-{name}")


def here(path: str, box: dict) -> str:
    """A path in the container, on this machine."""
    if path == "/work" or path.startswith("/work/"):
        return box["root"] + path[len("/work"):]
    for target, source in box.get("mounts", {}).items():  # a read-only mount: this machine's folder
        if path == target or path.startswith(target + "/"):
            return source + path[len(target):]
    if path.startswith("/"):
        return box["fs"] + path
    return path


def tree(pid: int) -> list[int]:
    out = subprocess.run(["ps", "-A", "-o", "pid=", "-o", "ppid="], capture_output=True, text=True, check=False).stdout
    children: dict[int, list[int]] = {}
    for line in out.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].isdigit() and fields[1].isdigit():
            children.setdefault(int(fields[1]), []).append(int(fields[0]))
    found, todo = [pid], [pid]
    while todo:
        for child in children.get(todo.pop(), []):
            if child not in found:
                found.append(child)
                todo.append(child)
    return found


def execute(args: list[str]) -> None:
    env = {"PATH": SYSTEM_PATH}
    workdir = "/"
    i = 0
    while i < len(args) and args[i].startswith("-"):
        arg = args[i]
        if arg in ("-e", "--env"):
            item = args[i + 1]
            key, eq, value = item.partition("=")
            if eq:
                env[key] = value
            elif key in os.environ:
                env[key] = os.environ[key]
            i += 2
        elif arg in ("-w", "--workdir", "-u", "--user"):
            if arg in ("-w", "--workdir"):
                workdir = args[i + 1]
            i += 2
        else:
            i += 1  # -i, -t, -it, -d
    name, command = args[i], args[i + 1:]
    box = info(name)
    if box is None:
        fail(f"Error response from daemon: No such container: {name}")
    if command[:2] == ["bash", "-c"] and command[2].startswith("command -v "):
        print("/usr/bin/" + command[2].removeprefix("command -v "))  # the image has bash, timeout, python3
        return
    if command[:2] == ["sh", "-c"] and command[2] == 'command -v "$1"':
        cli = command[4]
        if os.path.lexists(os.path.join(box["fs"], "usr/local/bin", cli)):
            print(f"/usr/local/bin/{cli}")
            return
        sys.exit(1)
    if (len(command) == 7 and command[:2] == ["sh", "-c"] and command[4] in SIGNALS and command[5].isdigit()
            and command[6] in ("0", "1")):  # the lane's signal script: the pid is this machine's
        pid = int(command[5])
        for target in (tree(pid) if command[6] == "1" else [pid]):
            try:
                os.kill(target, SIGNALS[command[4]])
            except (ProcessLookupError, PermissionError):
                pass
        return
    env.setdefault("HOME", "/root")
    env = {key: here(value, box) if value.startswith("/") else value for key, value in env.items() if key != "PATH"} | {"PATH": SYSTEM_PATH}
    argv = [here(arg, box) if arg.startswith("/") else arg for arg in command]
    if os.path.dirname(command[0]) in SYSTEM_PATH.split(":"):  # the image's system programs are this machine's
        argv[0] = command[0]
    box["pids"].append(os.getpid())
    with open(os.path.join(folder(name), "info.json"), "w", encoding="utf-8") as f:
        json.dump(box, f)
    os.chdir(here(workdir, box))
    os.execvpe(argv[0], argv, env)


def remove(args: list[str]) -> None:
    name = args[-1]
    box = info(name)
    if box is None:
        fail(f"Error response from daemon: No such container: {name}")
    for pid in box["pids"]:
        command = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True, check=False).stdout
        if "fake_agent_cli" in command:
            for target in tree(pid):
                try:
                    os.kill(target, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
    os.rename(os.path.join(folder(name), "info.json"), os.path.join(folder(name), "removed.json"))


def main() -> None:
    args = sys.argv[1:]
    record(args)
    if not args:
        fail("fake docker: no command")
    what, rest = args[0], args[1:]
    if what == "version":
        print("99.0.0-fake")
    elif what == "image" and rest[:1] == ["inspect"]:
        print("sha256:fake")
    elif what == "container" and rest[:1] == ["inspect"]:
        box = info(rest[-1])
        if box is None:
            fail(f"Error: No such container: {rest[-1]}")
        print("true" if "State.Running" in " ".join(rest) else f"fake-{rest[-1]}")
    elif what == "run":
        run(rest)
    elif what == "exec":
        execute(rest)
    elif what == "rm":
        remove(rest)
    elif what == "network":
        return
    else:
        fail(f"fake docker: unexpected call: {' '.join(args)}", 2)


if __name__ == "__main__":
    main()
