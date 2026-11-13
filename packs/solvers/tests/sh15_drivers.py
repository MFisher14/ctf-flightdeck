"""SH-15: child-process driver for the stego_review Part B daemon-probe-timeout proof (not a test module).

    python tests/sh15_drivers.py <fake_docker> <probe_timeout> <box>      prints one JSON object

Imports tools/sandbox.py in a fresh interpreter, points it at FAKE_DOCKER (a stand-in docker CLI whose
`image inspect` sleeps past the stock probe timeout) and at BOX as the sandbox folder (a path under the
calling test's tmp_path: nothing is made outside it, so nothing is left behind), sets
sandbox.PROBE_TIMEOUT to PROBE_TIMEOUT, and runs the image probe once (sandbox.present, the call that
fails B0 under load). It prints one JSON line:
{"outcome": "up", "present": true} when the probe answered inside the timeout, or
{"outcome": "down", "reason": "<SandboxDown text>"} when it did not. No real Docker is contacted: the
only CLI used is FAKE_DOCKER, so this runs where Docker is not used.
"""
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def main() -> int:
    fake_docker, probe_timeout, box = sys.argv[1], float(sys.argv[2]), Path(sys.argv[3]).resolve()
    os.environ["CTF_DOCKER"] = fake_docker
    os.environ["CTF_SANDBOX_DIR"] = str(box)
    os.environ["CTF_SANDBOX_NAME"] = f"sh15-probe-{os.getpid()}"
    os.environ.pop("CTF_SANDBOX_IMAGE", None)
    os.environ.pop("CTF_TOKEN", None)
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(REPO / "tools"), str(REPO)]

    import sandbox   # noqa: E402

    sandbox.PROBE_TIMEOUT = probe_timeout        # the whole point: Part B raises it the same way
    gen = sandbox.GENS[0]                         # csctf-sandbox:2, the image Part B uses
    try:
        present = sandbox.present(gen)
        print(json.dumps({"outcome": "up", "present": bool(present)}))
    except sandbox.SandboxDown as e:
        print(json.dumps({"outcome": "down", "reason": str(e)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
