"""Where a lane batch keeps its state: <paths.lanes_root()>/<batch>/ (B-179).

    <batch>/backlog.json           the parsed backlog the batch was run with
    <batch>/events.jsonl           one line per lane start / finish (append-only)
    <batch>/prompts/<id>.md        the self-contained prompt for one lane
    <batch>/prompts/PACK.md        every prompt, for pasting into a ready Codex agent by hand
    <batch>/lanes/<id>/wt/         the lane's git checkout (own .git, branch lane/<batch>/<id>)
    <batch>/lanes/<id>/result.json the lane's machine-readable result (written by the lane)
    <batch>/lanes/<id>/status.json the runner's record (state, exit code, times)
    <batch>/lanes/<id>/codex.log   codex stdout+stderr
    <batch>/lanes/<id>/last_message.md   codex's final message (codex exec -o)
    <batch>/integration.json       the last integrate report
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .. import paths


@dataclass(frozen=True)
class BatchDirs:
    root: Path

    @property
    def prompts(self) -> Path:
        return self.root / "prompts"

    @property
    def events(self) -> Path:
        return self.root / "events.jsonl"

    @property
    def integration(self) -> Path:
        return self.root / "integration.json"

    def lane_dir(self, lane_id: str) -> Path:
        return self.root / "lanes" / lane_id

    def checkout(self, lane_id: str) -> Path:
        return self.lane_dir(lane_id) / "wt"

    def result(self, lane_id: str) -> Path:
        return self.lane_dir(lane_id) / "result.json"

    def status(self, lane_id: str) -> Path:
        return self.lane_dir(lane_id) / "status.json"

    def log(self, lane_id: str) -> Path:
        return self.lane_dir(lane_id) / "codex.log"

    def last_message(self, lane_id: str) -> Path:
        return self.lane_dir(lane_id) / "last_message.md"

    def prompt(self, lane_id: str) -> Path:
        return self.prompts / f"{lane_id}.md"


def batch_dirs(batch: str, lanes_dir: Path | str | None = None) -> BatchDirs:
    base = Path(lanes_dir).expanduser().resolve() if lanes_dir else paths.lanes_root()
    repo = paths.repo_root().resolve()
    root = base / batch
    if root == repo or repo in root.parents:
        raise ValueError(f"lane state {root} would sit inside the repo {repo}; set CTF_LANES_DIR "
                         "or --lanes-dir outside the checkout")
    return BatchDirs(root)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def event(dirs: BatchDirs, kind: str, **fields) -> dict:
    rec = {"ts": time.time(), "event": kind, **fields}
    dirs.root.mkdir(parents=True, exist_ok=True)
    with open(dirs.events, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec
