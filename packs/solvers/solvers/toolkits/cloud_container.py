#!/usr/bin/env python3
"""Toolkit `cloud_container`: AWS, GCP, Azure and Kubernetes audit logs, container images
(`docker save` and OCI layouts, read in memory), Dockerfiles, Compose files, Kubernetes manifests
and Terraform state. The code is solvers/common/cloud_container.py; this file is its toolkit face,
so tools/run.py, tools/verify.py and tools/lane_match.py can load it like any other toolkit:

  .venv/bin/python solvers/toolkits/cloud_container.py <file | folder>... [--json] [--find PATH]
                                                       [--ask "question text"]

  signals(questions, files) -> float      0..1, cheap
  solve_set(questions, files, ctx) -> {qid: plain | labels.pick(...) | None}
  load(files), read_image, find_path, deleted_files, tf_leaves, suspects, ...

Quick reference: docs/toolkits/cloud_container.md.
"""
import importlib.util
import sys
from pathlib import Path

_IMPL = Path(__file__).resolve().parent.parent / "common" / "cloud_container.py"
_NAME = "cloud_container_impl"
if _NAME in sys.modules:
    _mod = sys.modules[_NAME]
else:
    _spec = importlib.util.spec_from_file_location(_NAME, _IMPL)
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules[_NAME] = _mod
    _spec.loader.exec_module(_mod)

globals().update({k: v for k, v in vars(_mod).items() if not k.startswith("__")})
KEY = _mod.KEY
solve_set = _mod.solve_set
signals = _mod.signals

if __name__ == "__main__":
    sys.exit(_mod.main(sys.argv[1:]))
