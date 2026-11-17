"""NYU CTF Bench as a flightdeck board (issue #50): one split of the benchmark's own checkout
turned into a board folder, and its challenge services started and stopped.

    uv run python scripts/nyuctf_board.py convert CHECKOUT development OUT
    uv run python scripts/nyuctf_board.py up OUT        # docker run each service, on 127.0.0.1
    flightdeck play OUT/board --autopilot --budget-dollars 25
    uv run python scripts/nyuctf_board.py down OUT

The benchmark is GPL-2.0 and is never copied into this repository: this script reads a
checkout you cloned yourself (https://github.com/NYU-LLM-CTF/NYU_CTF_Bench) and writes OUT
outside it. Only numbers from a run are published (docs/BENCHMARK.md).

What `convert` writes:

- OUT/board/ID/challenge.json and the handout files the benchmark's `challenge.json` lists
  (nothing else: not the source, not the Dockerfile, not the flag);
- OUT/board/answers.sha256.json: each flag's SHA-256, so the run scores itself and
  `flightdeck score` scores it again;
- OUT/board/board.json: the event's name; no flag format (the benchmark's flags have several
  shapes, and a lane submits one that is not `word{...}` itself);
- OUT/services.json: for each challenge with a server, its image, the port inside the
  container, the port on 127.0.0.1 it is published on (each its own, from --port-base), and
  its environment. The challenge's `urls` is `http://localhost:PORT` for web and
  `tcp://localhost:PORT` for the rest: a Docker lane reaches it as `instance-localhost:PORT`
  through its fence (GUIDE.md, Docker or host).

A compose file that mounts the Docker socket into the challenge is started without it: a
challenge never gets the host's Docker. Each such change is printed, and kept in
services.json under `notes`.

Challenge content is data: nothing here runs, evaluates or follows any of it (AGENTS.md rule
5). `up` runs the benchmark's own images, inside Docker, as the maintainer allowed for this
benchmark (DECISIONS D25).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

SPLITS = ("development", "test")
POINTS = 500
"""Every challenge's points on the board. The benchmark scores each challenge alike (solved of
N), and leaves points out of many; autopilot's effort budget grows with points (15 turns and
60k tokens per 100), so one value for all gives every lane the same room: 75 turns and 300k
tokens before the effort alert, under the per-lane dollar cap."""
ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
CONTAINER_PREFIX = "nyuctf-"


class ConvertError(Exception):
    """The checkout is not what this script reads; the message says where."""


@dataclass
class Service:
    id: str
    image: str
    container_port: int
    host_port: int
    env: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def challenge_id(key: str) -> str:
    """The benchmark's key ("2013f-cry-stfu") as a board id: lower case, and any character a
    board id does not take as `-`."""
    text = re.sub(r"[^a-z0-9_.-]+", "-", key.lower()).strip("-_.")[:64]
    if not ID.fullmatch(text):
        raise ConvertError(f"the key {key!r} makes no board id")
    return text


def compose_service(text: str, where: str) -> tuple[str, int | None, list[str], list[str]]:
    """(image, the port inside the container (None: the file publishes none, and the
    challenge's `internal_port` says it), environment, notes) of a compose file's one service. Read by lines: the benchmark's compose files are all one service with an image
    (checked, so a file that is not is an error that names it, never half read)."""
    head = text.split("\nnetworks:")[0]
    services = re.findall(r"^  ([A-Za-z0-9_-]+):\s*$", head, re.M)
    images = re.findall(r"^\s+image:\s*(\S+)\s*$", head, re.M)
    if len(services) != 1 or len(images) != 1 or re.search(r"^\s+build:", head, re.M):
        raise ConvertError(f"{where}: not one service with an image ({len(services)} services, {len(images)} images)")
    ports = re.findall(r"^\s+-\s*[\"']?(?:[\d.]+:)?(\d+):(\d+)(?:/tcp)?[\"']?\s*$", head, re.M)
    if len(ports) > 1:
        raise ConvertError(f"{where}: more than one published port ({len(ports)})")
    env: list[str] = []
    notes: list[str] = []
    block = re.search(r"^    environment:\s*\n((?:      - .*\n?)+)", head, re.M)
    if block:
        env = [line.strip()[2:] for line in block.group(1).splitlines() if line.strip()]
    for volume in re.findall(r"^      - (\S+:\S+)\s*$", head.split("volumes:")[1], re.M) if "volumes:" in head else []:
        if "docker.sock" in volume:
            notes.append("started without the Docker socket the compose file mounts: a challenge never gets the host's Docker")
        else:
            raise ConvertError(f"{where}: a volume this script does not start ({volume})")
    return images[0], int(ports[0][1]) if ports else None, env, notes


def convert(checkout: Path, split: str, out: Path, *, port_base: int = 20000) -> list[Service]:
    """Write the board and services.json for `split` of `checkout` into `out` (made; it must
    not hold a board already). The services, in the board's order."""
    if split not in SPLITS:
        raise ConvertError(f"the split is one of {', '.join(SPLITS)}")
    index = checkout / f"{split}_dataset.json"
    try:
        entries = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConvertError(f"cannot read {index}: {exc}") from None
    board = out / "board"
    if board.exists():
        raise ConvertError(f"{board} is there already: convert into a new folder")
    board.mkdir(parents=True)
    answers: dict[str, str] = {}
    services: list[Service] = []
    root = checkout.resolve()
    for key, entry in sorted(entries.items()):
        folder = (checkout / entry["path"]).resolve()
        if not folder.is_relative_to(root):
            raise ConvertError(f"{key}: its path leaves the checkout")
        meta = json.loads((folder / "challenge.json").read_text(encoding="utf-8"))
        cid = challenge_id(key)
        target = board / cid
        target.mkdir()
        files = []
        for name in meta.get("files", []):
            source = (folder / name).resolve()
            if not source.is_relative_to(folder) or not source.is_file() or (folder / name).is_symlink():
                raise ConvertError(f"{key}: the handout {name!r} is not a file inside its folder")
            shutil.copy2(source, target / Path(name).name)
            files.append(Path(name).name)
        challenge = {"name": meta["name"], "category": meta["category"], "points": POINTS,
                     "description": meta.get("description", ""), "files": files, "id": cid}
        compose = sorted(folder.glob("docker-compose.y*ml"))
        if compose:
            image, inner, env, notes = compose_service(compose[0].read_text(encoding="utf-8"), f"{key}: {compose[0].name}")
            inner = inner or meta.get("internal_port")
            if not isinstance(inner, int) or isinstance(inner, bool) or not 0 < inner < 65536:
                raise ConvertError(f"{key}: no port for its server, in {compose[0].name} or as internal_port")
            port = port_base + len(services)
            services.append(Service(cid, image, inner, port, env, notes))
            scheme = "http" if meta["category"].lower() == "web" else "tcp"
            challenge["urls"] = [f"{scheme}://localhost:{port}"]
            for note in notes:
                print(f"{cid}: {note}", file=sys.stderr)
        (target / "challenge.json").write_text(json.dumps(challenge, indent=2) + "\n", encoding="utf-8")
        answers[cid] = hashlib.sha256(str(meta["flag"]).encode("utf-8")).hexdigest()
    (board / "answers.sha256.json").write_text(json.dumps(answers, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (board / "board.json").write_text(json.dumps({"event": f"NYU CTF Bench ({split})"}) + "\n", encoding="utf-8")
    (out / "services.json").write_text(json.dumps([asdict(s) for s in services], indent=2) + "\n", encoding="utf-8")
    return services


def run_args(service: Service) -> list[str]:
    """The `docker run` that starts one service: detached, removed when stopped, published on
    127.0.0.1 only, with its environment and nothing else."""
    args = ["docker", "run", "-d", "--rm", "--name", CONTAINER_PREFIX + service.id,
            "-p", f"127.0.0.1:{service.host_port}:{service.container_port}"]
    for pair in service.env:
        args += ["-e", pair]
    return [*args, service.image]


def load_services(out: Path) -> list[Service]:
    return [Service(**entry) for entry in json.loads((out / "services.json").read_text(encoding="utf-8"))]


def up(out: Path) -> int:
    failed = 0
    for service in load_services(out):
        done = subprocess.run(run_args(service), capture_output=True, text=True)
        if done.returncode != 0:
            failed += 1
            print(f"{service.id}: did not start: {done.stderr.strip().splitlines()[-1] if done.stderr.strip() else done.returncode}",
                  file=sys.stderr)
        else:
            print(f"{service.id}: 127.0.0.1:{service.host_port}")
    return 1 if failed else 0


def down(out: Path) -> int:
    for service in load_services(out):
        subprocess.run(["docker", "rm", "-f", CONTAINER_PREFIX + service.id], capture_output=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("convert", help="write OUT/board and OUT/services.json from a checkout's split")
    make.add_argument("checkout", type=Path)
    make.add_argument("split", choices=SPLITS)
    make.add_argument("out", type=Path)
    make.add_argument("--port-base", type=int, default=20000)
    for name in ("up", "down"):
        sub.add_parser(name, help=f"{name}: the services of OUT/services.json").add_argument("out", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "convert":
            services = convert(args.checkout, args.split, args.out, port_base=args.port_base)
            print(f"board: {args.out / 'board'} ({len(services)} with a server)")
            return 0
        return up(args.out) if args.command == "up" else down(args.out)
    except ConvertError as exc:
        print(f"nyuctf_board: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
