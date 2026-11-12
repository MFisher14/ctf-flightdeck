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

A fenced lane's network (agent/egress.py) is played too, strictly enough to catch a wrong
order: `docker network create` records a network (networks.json: its members, its aliases,
whether it is internal, its labels), a container can only start on or be connected to a
network that exists, the `docker run` of an egress proxy (--entrypoint python3) records the
proxy with its configuration and runs nothing, `docker logs` says such a proxy is ready, and
`docker network rm` refuses a network that still has a container on it, as docker does.

How it runs: tests/test_external.py writes bin/docker, a small Python script that sets
FAKE_DOCKER_STATE (its folder) and execs `python -I fake_docker.py <docker's arguments>`.
Every call is appended to calls.jsonl there (its arguments: no secret's value is ever one).
clis.json there names the image's CLIs ({"claude": path, ...}).
"""

from __future__ import annotations

import fcntl
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


def networks() -> dict[str, dict]:
    """{a network's name: {"members": [containers on it], "aliases": {alias: container}}}."""
    try:
        with open(os.path.join(STATE, "networks.json"), encoding="utf-8") as f:
            return json.load(f)
    except OSError:
        return {}


def save_networks(nets: dict[str, dict]) -> None:
    with open(os.path.join(STATE, "networks.json"), "w", encoding="utf-8") as f:
        json.dump(nets, f)


def join(net: str, container: str, alias: str = "") -> None:
    """Put a container on a network: only one that exists (none, bridge and host always do)."""
    if net in ("none", "bridge", "host"):
        return
    nets = networks()
    if net not in nets:
        fail(f"docker: Error response from daemon: network {net} not found", 125)
    if container not in nets[net]["members"]:
        nets[net]["members"].append(container)
    if alias:
        nets[net]["aliases"][alias] = container
    save_networks(nets)


def network(args: list[str]) -> None:
    """`docker network create|inspect|connect|disconnect|rm`, as a fenced lane uses them
    (agent/egress.py): a network must exist to be joined, and be empty to be removed."""
    what, rest = (args[0], args[1:]) if args else ("", [])
    nets = networks()
    if what == "create":
        name = rest[-1]
        if name in nets:
            fail(f"Error response from daemon: network with name {name} already exists")
        nets[name] = {"members": [], "aliases": {}, "internal": "--internal" in rest,
                      "labels": [rest[i + 1] for i, arg in enumerate(rest) if arg == "--label"]}
        save_networks(nets)
        print(f"fake-net-{name}")
    elif what == "inspect":
        if rest[-1] not in nets:
            fail(f"Error response from daemon: network {rest[-1]} not found")
        print('[{"Subnet":"172.30.0.0/16"}]')
    elif what == "connect":
        net, container = rest[-2], rest[-1]
        if info(container) is None:
            fail(f"Error response from daemon: No such container: {container}")
        join(net, container, rest[rest.index("--alias") + 1] if "--alias" in rest else "")
    elif what == "disconnect":
        if info(rest[-1]) is None:
            fail(f"Error response from daemon: No such container: {rest[-1]}")
    elif what == "rm":
        name = rest[-1]
        if name not in nets:
            fail(f"Error response from daemon: network {name} not found")
        if nets[name]["members"]:
            fail(f"Error response from daemon: error while removing network: network {name} has active endpoints")
        del nets[name]
        save_networks(nets)
        print(name)
    else:
        fail(f"fake docker: unexpected call: network {' '.join(args)}", 2)


def run(args: list[str]) -> None:
    name, root, net, i = "", "", "bridge", 0
    while i < len(args):
        arg = args[i]
        if arg == "--name":
            name = args[i + 1]
            i += 2
            continue
        if arg == "--network":
            net = args[i + 1]
            i += 2
            continue
        if arg == "-v":
            source, _, target = args[i + 1].partition(":")
            if target == "/work":
                root = source
            i += 2
            continue
        i += 1
    proxy = "--entrypoint" in args and args[args.index("--entrypoint") + 1] == "python3"  # a fence's egress proxy
    if not name or not (root or proxy):
        fail("fake docker: run needs --name and a -v <folder>:/work")
    if info(name) is not None:
        fail(f'docker: Error response from daemon: Conflict. The container name "/{name}" is already in use', 125)
    join(net, name)
    if proxy:  # nothing runs: its configuration is kept, and `docker logs` says it is ready
        os.makedirs(folder(name), exist_ok=True)
        with open(os.path.join(folder(name), "info.json"), "w", encoding="utf-8") as f:
            json.dump({"proxy": json.loads(args[-1]), "network": net, "pids": []}, f)
        print(f"fake-{name}")
        return
    fs = os.path.join(folder(name), "fs")
    for sub, mode in (("tmp", 0o1777), ("root", 0o700), ("usr/local/bin", 0o755)):
        os.makedirs(os.path.join(fs, sub), exist_ok=True)
        os.chmod(os.path.join(fs, sub), mode)
    with open(os.path.join(STATE, "clis.json"), encoding="utf-8") as f:
        for cli, path in json.load(f).items():
            os.symlink(path, os.path.join(fs, "usr/local/bin", cli))
    with open(os.path.join(folder(name), "info.json"), "w", encoding="utf-8") as f:
        json.dump({"root": root, "fs": fs, "pids": []}, f)
    print(f"fake-{name}")


def here(path: str, box: dict) -> str:
    """A path in the container, on this machine."""
    if path == "/work" or path.startswith("/work/"):
        return box["root"] + path[len("/work"):]
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
    nets = networks()
    for net in nets.values():  # off every network it was on
        net["members"] = [member for member in net["members"] if member != name]
        net["aliases"] = {alias: member for alias, member in net["aliases"].items() if member != name}
    save_networks(nets)


def main() -> None:
    args = sys.argv[1:]
    record(args)
    if not args:
        fail("fake docker: no command")
    what, rest = args[0], args[1:]
    if what in ("network", "run", "rm"):  # one at a time: lanes start side by side, and networks.json is one file
        lock = open(os.path.join(STATE, "lock"), "w")  # noqa: SIM115 (held until this process ends)
        fcntl.flock(lock, fcntl.LOCK_EX)
    if what == "logs":
        box = info(rest[-1])
        if box is None:
            fail(f"Error response from daemon: No such container: {rest[-1]}")
        print("flightdeck-egress ready" if "proxy" in box else "")
    elif what == "version":
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
        network(rest)
    else:
        fail(f"fake docker: unexpected call: {' '.join(args)}", 2)


if __name__ == "__main__":
    main()
