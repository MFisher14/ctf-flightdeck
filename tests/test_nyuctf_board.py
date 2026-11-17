"""scripts/nyuctf_board.py: NYU CTF Bench's checkout as a board (issue #50).

Every checkout here is synthetic, made under tmp_path in the benchmark's layout: no file of
the benchmark is in this repository, and nothing here pulls or runs an image.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from ctf_flightdeck.platform.manual import load_board

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "nyuctf_board.py"
spec = importlib.util.spec_from_file_location("nyuctf_board", SCRIPT)
nyu = importlib.util.module_from_spec(spec)
sys.modules["nyuctf_board"] = nyu  # its dataclasses look their module up by name
spec.loader.exec_module(nyu)

COMPOSE = """version: '3'
services:
  server:
    image: example/2099q-web-made-up
    ports:
      - 8000:80
{extra}    networks:
      ctfnet:
        aliases:
          - web.chal.example

networks:
  ctfnet:
    external: true
"""


def a_checkout(tmp_path: Path, *, compose: str | None = COMPOSE.format(extra=""), files=("handout.bin",), meta: dict | None = None) -> Path:
    root = tmp_path / "bench"
    entries = {}
    for key, path, category in (("2099q-web-made-up", "development/2099/Quals/web/made up", "web"),
                                ("2099f-cry-also-made", "development/2099/Finals/crypto/also made", "crypto")):
        folder = root / path
        folder.mkdir(parents=True)
        for name in files:
            (folder / name).write_bytes(b"synthetic")
        (folder / "solver.py").write_text("not a handout\n")
        (folder / "Dockerfile").write_text("FROM scratch\n")
        data = {"name": key.split("-", 2)[2], "category": category, "description": "an invented challenge",
                "files": list(files), "flag": f"flag{{{key}}}", "box": "", **(meta or {})}
        if category == "web" and compose is not None:
            (folder / "docker-compose.yml").write_text(compose)
        else:
            data.pop("points", None)  # the benchmark leaves points out of some
        if category == "web":
            data["points"] = 300
        (folder / "challenge.json").write_text(json.dumps(data))
        entries[key] = {"category": category, "path": path}
    (root / "development_dataset.json").write_text(json.dumps(entries))
    return root


def test_convert_writes_a_board_flightdeck_loads_with_the_handouts_and_the_answers_and_no_flag(tmp_path):
    out = tmp_path / "out"
    services = nyu.convert(a_checkout(tmp_path), "development", out, port_base=21000)
    board = load_board(out / "board")
    assert sorted(c.challenge.id for c in board.challenges) == ["2099f-cry-also-made", "2099q-web-made-up"]
    assert [c.urls for c in board.challenges if c.urls] == [("http://localhost:21000",)]
    web = json.loads((out / "board" / "2099q-web-made-up" / "challenge.json").read_text())
    assert web == {"name": "made-up", "category": "web", "points": 300, "description": "an invented challenge",
                   "files": ["handout.bin"], "id": "2099q-web-made-up", "urls": ["http://localhost:21000"]}
    crypto = json.loads((out / "board" / "2099f-cry-also-made" / "challenge.json").read_text())
    assert crypto["points"] == 0 and "urls" not in crypto
    # the handout and nothing else: no solver, no Dockerfile, no flag anywhere in the board
    assert sorted(p.name for p in (out / "board" / "2099q-web-made-up").iterdir()) == ["challenge.json", "handout.bin"]
    every = "".join(p.read_text(errors="replace") for p in (out / "board").rglob("*") if p.is_file())
    assert "flag{" not in every
    answers = json.loads((out / "board" / "answers.sha256.json").read_text())
    assert answers["2099q-web-made-up"] == hashlib.sha256(b"flag{2099q-web-made-up}").hexdigest()
    assert json.loads((out / "board" / "board.json").read_text()) == {"event": "NYU CTF Bench (development)"}
    assert [(s.id, s.image, s.container_port, s.host_port) for s in services] == [("2099q-web-made-up", "example/2099q-web-made-up", 80, 21000)]
    assert json.loads((out / "services.json").read_text())[0]["host_port"] == 21000


def test_a_service_starts_on_127_0_0_1_only_with_its_environment_and_without_the_docker_socket(tmp_path):
    extra = "    environment:\n      - DB_PASS='x'\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
    services = nyu.convert(a_checkout(tmp_path, compose=COMPOSE.format(extra=extra)), "development", tmp_path / "out")
    (service,) = services
    assert service.env == ["DB_PASS='x'"] and service.notes and "Docker socket" in service.notes[0]
    args = nyu.run_args(service)
    assert args == ["docker", "run", "-d", "--rm", "--name", "nyuctf-2099q-web-made-up", "-p", "127.0.0.1:20000:80",
                    "-e", "DB_PASS='x'", "example/2099q-web-made-up"]
    assert not any("docker.sock" in arg or arg in ("-v", "--volume", "--privileged") for arg in args)


def test_a_compose_file_with_no_published_port_takes_the_challenges_internal_port(tmp_path):
    compose = COMPOSE.format(extra="").replace("    ports:\n      - 8000:80\n", "")
    (service,) = nyu.convert(a_checkout(tmp_path, compose=compose, meta={"internal_port": 4242}), "development", tmp_path / "out")
    assert service.container_port == 4242
    with pytest.raises(nyu.ConvertError, match="no port for its server"):
        nyu.convert(a_checkout(tmp_path / "again", compose=compose), "development", tmp_path / "out2")


@pytest.mark.parametrize("extra, why", [
    ("    volumes:\n      - ./data:/data\n", "a volume this script does not start"),
    ("    build: .\n", "not one service with an image"),
], ids=["a volume", "a build"])
def test_a_compose_file_this_script_cannot_start_as_written_is_an_error_that_names_it(tmp_path, extra, why):
    with pytest.raises(nyu.ConvertError, match=why):
        nyu.convert(a_checkout(tmp_path, compose=COMPOSE.format(extra=extra)), "development", tmp_path / "out")


def test_a_handout_outside_its_folder_and_an_existing_board_are_refused(tmp_path):
    with pytest.raises(nyu.ConvertError, match="is not a file inside its folder"):
        nyu.convert(a_checkout(tmp_path, files=("../../../../development_dataset.json",)), "development", tmp_path / "out")
    out = tmp_path / "out2"
    nyu.convert(a_checkout(tmp_path / "b"), "development", out)
    with pytest.raises(nyu.ConvertError, match="is there already"):
        nyu.convert(a_checkout(tmp_path / "c"), "development", out)


@pytest.mark.parametrize("key, made", [("2013f-cry-stfu", "2013f-cry-stfu"), ("2016q-web-I Got Id", "2016q-web-i-got-id"),
                                       ("2017q-for-it's a trap", "2017q-for-it-s-a-trap")])
def test_a_benchmark_key_becomes_a_board_id(key, made):
    assert nyu.challenge_id(key) == made
