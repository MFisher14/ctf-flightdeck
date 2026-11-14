"""Synthetic checkouts for the adaptation-loop tests (B-036). Everything is written by the test: a probe
engine, its manifest, a one-lane openers/layer1.toml and a minimal tests/gate.toml, in a fresh git repo
whose `ctf/` is a link to this checkout's. No real challenge file, no network.

The probe engine (`toolkits.adapt_probe`) prints `ANSWER: <first 16 hex of sha256(input)>`, so its key
holds on one fixture and not on another. Its behaviour is steered by environment variables, which reach
the engine because openers.engine_env keeps every variable that is not secret-named:

    ADAPT_PROBE_SLEEP=S          sleep S seconds before answering
    ADAPT_PROBE_EXIT=N           exit N after answering
    ADAPT_PROBE_ALWAYS=TEXT      also print TEXT (a key that holds on every input)
    ADAPT_PROBE_ONCE=PATH        first run (PATH absent): create PATH, then do ADAPT_PROBE_ONCE_DO
    ADAPT_PROBE_ONCE_DO=wrong|hang   ... print a wrong answer, or sleep 60 s (a cap cut)
    ADAPT_PROBE_CONNECT=PORT     before answering, open a TCP connection to 127.0.0.1:PORT and print
                                 CONNECTED; on an OSError (the guard's refusal) print REFUSED <error>
                                 and exit 9
    ADAPT_PROBE_SHOW=NAME[,...]  also print `ENV <NAME>=<value or <unset>>` per name, `INPUT <argv[1]>`
                                 and `CWD <cwd>`: what the engine's process can see
    ADAPT_PROBE_LITTER=1         first print `WORKDIR_HAS <sorted entries of $CTF_WORKDIR, comma-joined>`,
                                 then leave a file in $CTF_WORKDIR (state a later run must not see)
"""
from __future__ import annotations

import hashlib
import subprocess
import textwrap
from pathlib import Path

from ctf.openers import fixtures

REPO = Path(__file__).resolve().parents[1]
GIT = ["git", "-c", "user.email=adapt@test.invalid", "-c", "user.name=adapt-test", "-c", "commit.gpgsign=false",
       "-c", "core.hooksPath=/dev/null", "-c", "init.defaultBranch=main"]
ENGINE = "toolkits.adapt_probe"
PROBE_VARS = ("ADAPT_PROBE_SLEEP", "ADAPT_PROBE_EXIT", "ADAPT_PROBE_ALWAYS", "ADAPT_PROBE_ONCE", "ADAPT_PROBE_ONCE_DO",
              "ADAPT_PROBE_CONNECT", "ADAPT_PROBE_SHOW", "ADAPT_PROBE_LITTER")
BASE_FIXTURE = "warmups_base64_slug"
CASE_FIXTURE = "warmups_hex_slug"
CONTROL_FIXTURE = "warmups_no_slug"

PROBE = '''\
import hashlib, os, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import adapt_probe_lib

data = Path(sys.argv[1]).read_bytes()
if os.environ.get("ADAPT_PROBE_LITTER"):
    wd = Path(os.environ["CTF_WORKDIR"])
    print("WORKDIR_HAS " + ",".join(sorted(p.name for p in wd.iterdir())), flush=True)
    (wd / f"litter-{os.getpid()}").write_text("left by an earlier run")
once = os.environ.get("ADAPT_PROBE_ONCE")
if once and not os.path.exists(once):
    Path(once).write_text("x")
    if os.environ.get("ADAPT_PROBE_ONCE_DO") == "hang":
        time.sleep(60)
    print("ANSWER: wrong")
    sys.exit(0)
port = os.environ.get("ADAPT_PROBE_CONNECT")
if port:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=5) as s:
            s.sendall(b"probe\\n")
    except OSError as e:
        print(f"REFUSED {e}")
        sys.exit(9)
    print("CONNECTED")
for name in filter(None, os.environ.get("ADAPT_PROBE_SHOW", "").split(",")):
    print(f"ENV {name}={os.environ.get(name, '<unset>')}")
if os.environ.get("ADAPT_PROBE_SHOW"):
    print(f"INPUT {sys.argv[1]}")
    print(f"CWD {os.getcwd()}")
time.sleep(float(os.environ.get("ADAPT_PROBE_SLEEP", "0")))
print(adapt_probe_lib.PREFIX + hashlib.sha256(data).hexdigest()[:16])
if os.environ.get("ADAPT_PROBE_ALWAYS"):
    print(os.environ["ADAPT_PROBE_ALWAYS"])
sys.exit(int(os.environ.get("ADAPT_PROBE_EXIT", "0")))
'''

LIB = 'PREFIX = "ANSWER: "\n'

GATE_TOML = """\
version = 1
tests = ["tests/test_*.py"]
roots = ["", "solvers/common"]
global = ["tests/gate.toml"]
inert = ["docs/**"]

[wall]
base_seconds = 60
max_scale = 4.0
"""


def git(root: Path, *args: str) -> str:
    r = subprocess.run([*GIT, "-C", str(root), *args], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr}")
    return r.stdout


def answer_for(data: bytes) -> str:
    return "ANSWER: " + hashlib.sha256(data).hexdigest()[:16]


def fixture_answer(kind: str, tmp: Path) -> str:
    return answer_for(fixtures.build(kind, tmp / f"fx-{kind}").read_bytes())


def write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def make_repo(tmp: Path, *, opener: str | None = None, extra_case: bool = True) -> Path:
    """A checkout with the probe engine and a `probe` lane opener (base + one more case + a control).
    `opener` replaces the whole [[opener]] block."""
    root = tmp / "repo"
    root.mkdir(parents=True)
    (root / "ctf").symlink_to(REPO / "ctf", target_is_directory=True)
    write(root, "solvers/toolkits/adapt_probe.py", PROBE)
    write(root, "solvers/toolkits/adapt_probe.manifest.toml",
          f'id = "{ENGINE}"\nlane = "toolkits"\nentry = "cli:python solvers/toolkits/adapt_probe.py"\n'
          'capabilities = ["analysis", "cli"]\ncost_class = "cheap"\n')
    write(root, "solvers/common/adapt_probe_lib.py", LIB)
    write(root, "tests/gate.toml", GATE_TOML)
    if opener is None:
        base = fixture_answer(BASE_FIXTURE, tmp)
        opener = textwrap.dedent(f"""\
            [[opener]]
            lane = "probe"
            category = "Probe"
            engine = "{ENGINE}"
            label = "probe opener"
            fixture = "{BASE_FIXTURE}"
            expect = ["{base}"]
            controls = ["{CONTROL_FIXTURE}"]
            """)
        if extra_case:
            opener += textwrap.dedent(f"""\

                [[opener.case]]
                mode = "time_trial"
                fixture = "{CASE_FIXTURE}"
                expect = ["{fixture_answer(CASE_FIXTURE, tmp)}"]
                """)
    write(root, "openers/layer1.toml", opener)
    git(root, "init", "-q")
    return root
