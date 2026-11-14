"""Synthetic look-ahead matrices for the B-174 tests: everything is written inside the test's tmp_path.

The probe reader (READER) is a lane reader stand-in. It reads its behaviour from the specimen's
[ctx] table: `mode` answer (default) | raise | hang | exit | nondict | net | env; `answers` a table of
fixed answers by id. Any id ending in `total_size` is answered with the sum of the delivered member
sizes (so a correct answer proves the reader got the real files); every other id is None.
"""
from __future__ import annotations

import base64
import json
import zlib
from pathlib import Path

READER = '''
import os, socket, time

def solve_set(questions, files, ctx):
    mode = ctx.get("mode", "answer")
    if mode == "raise":
        raise RuntimeError("reader broke")
    if mode == "hang":
        ctx["partial"]["partial_id"] = "p"
        while True:
            time.sleep(0.02)
    if mode == "exit":
        os._exit(7)
    if mode == "nondict":
        return ["not", "a", "dict"]
    if mode == "net":
        s = socket.create_connection(("127.0.0.1", int(ctx["port"])), timeout=2)
        s.sendall(b"hello")
        return {}
    fixed = dict(ctx.get("answers", {}))
    if mode == "env":
        fixed["secret_seen"] = os.environ.get("FAKE_TOKEN")
        fixed["ledger_env"] = os.environ.get("CTF_ENGINE_LEDGER")
    out = {}
    for q in questions:
        qid = q.get("id")
        if qid in fixed:
            out[qid] = fixed[qid]
        elif qid.endswith("total_size"):
            out[qid] = sum(len(v) for v in files.values())
        else:
            out[qid] = None
    return out
'''


def q(qid: str, kind: str = "exact_text", text: str = "", **extra) -> dict:
    d = {"id": qid, "question": text or f"What is {qid}?", "answer_format": {"kind": kind}}
    d.update(extra)
    return d


def toml_value(v) -> str:
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{json.dumps(k)} = {toml_value(x)}" for k, x in v.items()) + " }"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    return json.dumps(v)


def write_reader(tmp: Path, name: str = "probe_reader.py", text: str = READER) -> Path:
    p = tmp / "readers" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def matrix(tmp: Path, lanes: dict, *, skipped=(), waived=(), name: str = "matrix") -> Path:
    """lanes: {lane: {"reader": path, ...lane keys; "threshold": [dicts]}}."""
    m = tmp / name
    m.mkdir(parents=True, exist_ok=True)
    lines = []
    for lane, cfg in lanes.items():
        lines.append(f"[lane.{lane}]")
        for k, v in cfg.items():
            if k != "threshold":
                lines.append(f"{k} = {toml_value(str(v) if isinstance(v, Path) else v)}")
        for t in cfg.get("threshold", []):
            lines.append(f"[[lane.{lane}.threshold]]")
            lines += [f"{k} = {toml_value(v)}" for k, v in t.items()]
    for s in skipped:
        lines.append("[[skipped]]")
        lines += [f"{k} = {toml_value(v)}" for k, v in s.items()]
    for w in waived:
        lines.append("[[waived_threshold]]")
        lines += [f"{k} = {toml_value(v)}" for k, v in w.items()]
    (m / "matrix.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return m


def specimen(m: Path, lane: str, name: str, questions, files: dict | None = None, *, encoding=("raw",),
             encodings=None, key=None, skip: str = "", ctx=None, raw_toml: str | None = None) -> Path:
    d = m / lane / name
    (d / "files").mkdir(parents=True, exist_ok=True)
    for member, data in (files if files is not None else {"a.txt": b"hello"}).items():
        p = d / "files" / member
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    (d / "questions.json").write_text(json.dumps(list(questions)), encoding="utf-8")
    if key is not None:
        (d / "key.json").write_text(json.dumps(key), encoding="utf-8")
    if raw_toml is not None:
        (d / "specimen.toml").write_text(raw_toml, encoding="utf-8")
        return d
    lines = []
    if skip:
        lines.append(f"skip = {json.dumps(skip)}")
    if encoding is not None and not skip:
        lines.append(f"encoding = {toml_value(list(encoding))}")
    if encodings:
        lines.append("[encodings]")
        lines += [f"{json.dumps(k)} = {toml_value(list(v))}" for k, v in encodings.items()]
    if ctx:
        lines.append("[ctx]")
        lines += [f"{json.dumps(k)} = {toml_value(v)}" for k, v in ctx.items()]
    (d / "specimen.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return d


def b64_zlib(payload: bytes) -> bytes:
    return base64.b64encode(zlib.compress(payload))
