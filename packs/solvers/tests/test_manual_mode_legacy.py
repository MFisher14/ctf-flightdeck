"""R-02: manual mode is code-enforced on the carried CTFd path, not only behind get_adapter.

Under a manual event (the shipped spooky profile: platform kind manual, ai_on_platform forbidden) the
built-in `ctf` commands (submit, pull, list, status and the rest), `python -m ctf.submit send`,
ctf.submit.guarded_submit, ctf.dynamic.solve_dynamic and ctf.fastlane's rules-page GET refuse before
any connection is attempted. That is proved at two boundaries: no requests.Session is ever built (the
session class is replaced by a recorder), and no socket call happens (socket.getaddrinfo,
socket.create_connection and socket.socket.connect are tripwires, in-process and, for the real
`python -m ctf` entry point, through a sitecustomize in a subprocess).

Under csctf (a CTFd event that allows automation) the same commands reach the client's session and
make the expected CTFd API calls against a recorded fake: nothing here touches the network.

B-006 moved `ctf submit`, `python -m ctf.submit send` and ctf.dynamic onto the submit gate
(ctf.platform.get_adapter): their manual-mode refusal is still checked here, and their send is shown
reaching the CTFd adapter's session for an automation event.
"""
from __future__ import annotations

import datetime
import json
import os
import socket
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import pytest

import ctf.cli as cli
from ctf import client as C
from ctf import dynamic as D
from ctf import env as ENV
from ctf import event as E
from ctf import fastlane as FL
from ctf import submit as S
from ctf import workspace as W
from ctf.platform import NotAllowed, NotSupported
from ctf.platform import legacy as L

REPO = Path(__file__).resolve().parent.parent
BASE = "https://board.r02-legacy.test"
API = BASE + "/api/v1"
DUMMY_AUTH = "r02-dummy-value-not-a-credential"
EVENT_VARS = ("CTF_EVENT", "CTF_TOKEN", "CTF_COOKIE", "CTF_PLATFORM_URL", "CTF_WORKDIR")


def _profile(slug: str, *, kind: str = "ctfd", submit_mode: str = "auto",
             ai: str = "allowed") -> E.EventProfile:
    platform = {"kind": kind}
    if kind != "manual":
        platform["base_url"] = BASE
    return E.parse({
        "slug": slug, "name": slug,
        "dates": {"start": datetime.date(2026, 1, 1), "end": datetime.date(2026, 12, 31)},
        "platform": platform, "flag": {"prefixes": ["R02TEST"]},
        "rules": {"submit_mode": submit_mode, "flag_sharing": "allowed", "ai_on_platform": ai},
    }, src="tests/test_manual_mode_legacy.py")


AUTO = _profile("r02-auto")
SUBMIT_MANUAL = _profile("r02-submit-manual", submit_mode="manual")
AI_FORBIDDEN = _profile("r02-ai-forbidden", submit_mode="manual", ai="forbidden")
GM = _profile("r02-gm", kind="gamemaster")


def csctf_flag(body: str) -> str:
    return E.load("csctf").flag.prefixes[0] + "{" + body + "}"


# ------------------------------------------------------------------------------- boundaries
class _Resp:
    def __init__(self, method: str, url: str, body=None, content: bytes = b"", status: int = 200):
        self.status_code = status
        self.url = url
        self.request = types.SimpleNamespace(method=method)
        self.headers: dict = {}
        self._body = body
        self.content = json.dumps(body).encode() if body is not None else content
        self.text = self.content.decode("utf-8", "replace")

    def json(self):
        if self._body is None:
            raise ValueError("not JSON")
        return self._body

    def iter_content(self, size=65536):
        yield self.content

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Cookies(dict):
    def set(self, name, value):
        self[name] = value


def _routes(flag: str) -> dict:
    chal = {"id": 7, "name": "Warm Up", "category": "Misc", "value": 100, "solved_by_me": False}
    return {
        ("GET", API + "/challenges"): {"success": True, "data": [chal]},
        ("GET", API + "/teams/me/solves"): {"success": True, "data": []},
        ("GET", API + "/teams/me"): {"success": True, "data": {"id": 1, "name": "r02 team", "score": 0,
                                                                "place": 9}},
        ("GET", API + "/users/me"): {"success": True, "data": {"id": 3, "name": "r02 user", "team_id": 1}},
        ("GET", API + "/challenges/7"): {"success": True, "data": dict(
            chal, description="plain words", files=["/files/abc/note.txt"])},
        ("GET", BASE + "/files/abc/note.txt"): b"synthetic note\n",
        ("POST", API + "/challenges/attempt", json.dumps({"challenge_id": 7, "submission": flag})):
            {"success": True, "data": {"status": "correct", "message": "Correct"}},
    }


class Boundary:
    """Replaces requests.Session inside ctf.client with a recorder and arms socket tripwires."""

    def __init__(self, monkeypatch, routes: dict | None = None):
        self.sessions: list = []
        self.socket_calls: list[str] = []
        boundary = self
        table = routes or {}

        class RecordingSession:
            def __init__(self):
                self.headers: dict = {}
                self.cookies = _Cookies()
                self.calls: list[tuple] = []
                boundary.sessions.append(self)

            def _answer(self, method, url, json_body=None):
                self.calls.append((method, url, json_body))
                key = (method, url) if json_body is None else (method, url, json.dumps(json_body))
                if key not in table:
                    raise AssertionError(f"no fake route for {key}")
                v = table[key]
                return _Resp(method, url, content=v) if isinstance(v, bytes) else _Resp(method, url, body=v)

            def get(self, url, timeout=None, stream=False, **kw):
                return self._answer("GET", url)

            def post(self, url, json=None, timeout=None, **kw):
                return self._answer("POST", url, json)

            def head(self, url, timeout=None, **kw):
                return self._answer("HEAD", url)

            def request(self, method, url, json=None, timeout=None, **kw):
                return self._answer(method.upper(), url, json)

        def trip(what):
            def fn(*a, **k):
                boundary.socket_calls.append(what)
                raise OSError(f"R-02 test tripwire: {what} attempted")
            return fn

        monkeypatch.setattr(C.requests, "Session", RecordingSession)
        monkeypatch.setattr(socket, "getaddrinfo", trip("getaddrinfo"))
        monkeypatch.setattr(socket, "create_connection", trip("create_connection"))
        monkeypatch.setattr(socket.socket, "connect", trip("connect"))

    def calls(self) -> list[tuple]:
        return [c for s in self.sessions for c in s.calls]


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    for name in EVENT_VARS:
        monkeypatch.delenv(name, raising=False)
        for legacy in ENV.legacy_names(name):
            monkeypatch.delenv(legacy, raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    monkeypatch.setenv(C.SUBMIT_STATE_ENV, str(tmp_path / "pace"))
    return tmp_path


def _use_event(monkeypatch, slug: str) -> None:
    monkeypatch.setenv("CTF_EVENT", slug)
    monkeypatch.setenv("CTF_TOKEN", DUMMY_AUTH)
    monkeypatch.setenv("CTF_PLATFORM_URL", BASE)


# ------------------------------------------------------------------------------- the rule itself
def test_refusal_follows_the_profile_rules():
    spooky = E.load("spooky")
    for submit in (False, True):
        err = L.refusal(spooky, "x", submit=submit)
        assert type(err) is NotAllowed and "manual" in str(err)
        err = L.refusal(AI_FORBIDDEN, "x", submit=submit)
        assert type(err) is NotAllowed and "ai_on_platform = forbidden" in str(err)
        assert L.refusal(AUTO, "x", submit=submit) is None
        assert L.refusal(E.load("csctf"), "x", submit=submit) is None
    # submit_mode manual on a CTFd event: reads may run, a send may not
    assert L.refusal(SUBMIT_MANUAL, "x") is None
    err = L.refusal(SUBMIT_MANUAL, "send", submit=True)
    assert type(err) is NotAllowed and "submit_mode manual" in str(err) and str(err).startswith("send:")
    # the carried client speaks CTFd only: another platform is NotSupported, not a manual refusal
    err = L.refusal(GM, "x")
    assert type(err) is NotSupported and "gamemaster" in str(err)


def test_a_forbidden_gamemaster_event_is_refused_as_manual_first():
    gm_forbidden = _profile("r02-gm-forbidden", kind="gamemaster", submit_mode="manual", ai="forbidden")
    assert type(L.refusal(gm_forbidden, "x")) is NotAllowed


def test_resolve_fails_closed_without_a_profile(clean_env, monkeypatch):
    assert len(E.available()) > 1        # several shipped profiles, CTF_EVENT unset: ambiguous
    with pytest.raises(L.NoProfile, match="no event profile.*CTF_EVENT"):
        L.require("CTFd client")
    assert issubclass(L.NoProfile, NotAllowed)
    monkeypatch.setenv("CTF_EVENT", "spooky")
    with pytest.raises(NotAllowed, match="'spooky' is manual"):
        L.require("CTFd client")
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert L.require("CTFd client").slug == "csctf"
    assert L.require("CTFd client", profile=AUTO) is AUTO    # an explicit profile wins over CTF_EVENT
    with pytest.raises(TypeError):
        L.require("CTFd client", profile={"slug": "csctf"})


# ------------------------------------------------------------------------------- the CTFd client
def test_client_refuses_a_manual_event_before_any_session(clean_env, monkeypatch):
    b = Boundary(monkeypatch)
    _use_event(monkeypatch, "spooky")
    with pytest.raises(NotAllowed, match="spooky"):
        C.connect()
    with pytest.raises(NotAllowed, match="ai_on_platform"):
        C.CTFd(profile=AI_FORBIDDEN)
    with pytest.raises(NotSupported, match="gamemaster"):
        C.CTFd(profile=GM)
    assert b.sessions == [] and b.socket_calls == []


def test_client_is_built_for_an_automation_event(clean_env, monkeypatch):
    b = Boundary(monkeypatch)
    _use_event(monkeypatch, "csctf")
    c = C.connect()
    assert c.profile.slug == "csctf" and len(b.sessions) == 1
    assert C.CTFd(profile=AUTO).profile is AUTO and len(b.sessions) == 2


def test_client_submit_refuses_submit_mode_manual_before_the_queue(clean_env, monkeypatch):
    b = Boundary(monkeypatch)
    c = C.CTFd(profile=SUBMIT_MANUAL)              # reads are allowed on this event
    with pytest.raises(NotAllowed, match="submit_mode manual"):
        c.submit(7, "R02TEST{x}")
    assert b.calls() == []
    assert not (clean_env / "pace").exists(), "a refused submit must not take a pacing slot"


# ------------------------------------------------------------------------------- the CLI, in process
REFUSE_ARGV = [["submit", "7", "spooky{r02_value}"], ["pull", "7"], ["pull", "all"], ["list"],
               ["status"], ["me"], ["check", "7"], ["triage", "7"], ["wait", "--timeout", "1"]]


@pytest.mark.parametrize("argv", REFUSE_ARGV, ids=lambda a: " ".join(a))
def test_cli_refuses_under_spooky_before_any_connection(clean_env, monkeypatch, capsys, argv):
    b = Boundary(monkeypatch)
    _use_event(monkeypatch, "spooky")
    assert cli.main(argv) == cli.REFUSED_EXIT == 4
    err = capsys.readouterr().err
    assert f"ctf {argv[0]}: refused:" in err and "'spooky' is manual" in err
    assert b.sessions == [], "a session was built under a manual event"
    assert b.socket_calls == [], f"socket calls under a manual event: {b.socket_calls}"
    assert not (clean_env / "work").exists(), "a refused command must not create workspace state"


def test_cli_refuses_without_a_profile(clean_env, monkeypatch, capsys):
    b = Boundary(monkeypatch)
    assert cli.main(["list"]) == 4
    assert "no event profile" in capsys.readouterr().err
    assert b.sessions == []


def test_cli_refuses_a_gamemaster_event(clean_env, monkeypatch, capsys):
    b = Boundary(monkeypatch)
    _use_event(monkeypatch, "huntress")
    assert cli.main(["list"]) == 4
    assert "speaks only CTFd" in capsys.readouterr().err
    assert b.sessions == []


def test_cli_submit_on_a_submit_manual_event_refuses_before_the_challenge_read(clean_env, monkeypatch,
                                                                                capsys):
    b = Boundary(monkeypatch, _routes("R02TEST{x}"))
    monkeypatch.setenv("CTF_TOKEN", DUMMY_AUTH)
    monkeypatch.setenv("CTF_PLATFORM_URL", BASE)
    monkeypatch.setattr(E, "current", lambda root=None: SUBMIT_MANUAL)
    assert cli.main(["submit", "7", "R02TEST{x}"]) == 4
    assert "submit_mode manual" in capsys.readouterr().err
    assert b.calls() == [], "the challenge must not even be read for a refused submit"
    assert cli.main(["list"]) == 0                 # reads still run on this event
    assert ("GET", API + "/challenges", None) in b.calls()


def test_cli_list_and_status_reach_the_client_under_csctf(clean_env, monkeypatch, capsys):
    b = Boundary(monkeypatch, _routes(csctf_flag("unused")))
    _use_event(monkeypatch, "csctf")
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "Warm Up" in out and "== Misc ==" in out
    assert ("GET", API + "/challenges", None) in b.calls()
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "challenges visible: 1" in out and "r02 team" in out
    assert ("GET", API + "/teams/me", None) in b.calls()
    assert b.socket_calls == []


def test_cli_pull_reaches_the_client_under_csctf(clean_env, monkeypatch, capsys):
    b = Boundary(monkeypatch, _routes(csctf_flag("unused")))
    _use_event(monkeypatch, "csctf")
    assert cli.main(["pull", "7"]) == 0
    assert ("GET", API + "/challenges/7", None) in b.calls()
    assert ("GET", BASE + "/files/abc/note.txt", None) in b.calls()
    # the download lands once in files/ (the B-013 sweep's scratch copy under unpacked/ is not a download)
    files = sorted(p for p in (clean_env / "work").rglob("note.txt") if p.parent.name == "files")
    assert len(files) == 1 and files[0].read_bytes() == b"synthetic note\n"
    assert "pulled 7 ->" in capsys.readouterr().out


def test_cli_submit_reaches_the_ctfd_adapter_through_the_gate(clean_env, monkeypatch, capsys):
    # B-006: one POST through get_adapter's gate and queue; no challenge or solves read first.
    flag = "R02TEST{r02_value}"
    b = Boundary(monkeypatch, _routes(flag))
    _use_event(monkeypatch, "csctf")
    monkeypatch.setattr(E, "current", lambda root=None: AUTO)    # a CTFd event on BASE
    assert cli.main(["submit", "7", flag, "--note", "r02 test"]) == 0
    assert "correct" in capsys.readouterr().out
    assert b.calls() == [("POST", API + "/challenges/attempt", {"challenge_id": 7, "submission": flag})]
    assert b.socket_calls == []


def test_cli_submit_refuses_without_a_profile(clean_env, monkeypatch, capsys):
    b = Boundary(monkeypatch)
    assert cli.main(["submit", "7", "R02TEST{x}"]) == 4
    assert "no event profile" in capsys.readouterr().err
    assert b.sessions == [] and not (clean_env / "work").exists()


# ------------------------------------------------------------------------------- python -m ctf.submit
def test_ctf_submit_module_refuses_under_spooky(clean_env, monkeypatch, capsys):
    b = Boundary(monkeypatch)
    _use_event(monkeypatch, "spooky")
    assert S.main(["send", "7", "spooky{r02_value}"]) == S.REFUSED_EXIT == 4
    assert "'spooky' is manual" in capsys.readouterr().err
    assert b.sessions == [] and b.socket_calls == []


def test_ctf_submit_module_reaches_the_ctfd_adapter_through_the_gate(clean_env, monkeypatch, capsys):
    flag = "R02TEST{r02_mod}"
    b = Boundary(monkeypatch, _routes(flag))
    _use_event(monkeypatch, "csctf")
    monkeypatch.setattr(E, "current", lambda root=None: AUTO)
    assert S.main(["send", "7", flag]) == 0
    assert b.calls() == [("POST", API + "/challenges/attempt", {"challenge_id": 7, "submission": flag})]


# ------------------------------------------------------------------------------- guarded_submit
class _FakeClient:
    def __init__(self, profile=None):
        if profile is not None:
            self.profile = profile
        self.cfg = types.SimpleNamespace(looks_like_flag=lambda f: True, submit_wrong_limit=3)
        self.sent: list = []

    def submit(self, cid, flag):
        self.sent.append((cid, flag))
        return C.Submission("correct", "ok")


@pytest.fixture
def chal(tmp_path) -> W.Challenge:
    d = tmp_path / "chal" / "7-warm-up"
    d.mkdir(parents=True)
    return W.Challenge(cid=7, name="Warm Up", category="misc", dir=d)


@pytest.mark.parametrize("profile", [E.load("spooky"), AI_FORBIDDEN, SUBMIT_MANUAL],
                         ids=["spooky", "ai-forbidden", "submit-manual"])
def test_guarded_submit_refuses_a_manual_client_before_any_state(chal, profile):
    fake = _FakeClient(profile)
    with pytest.raises(NotAllowed):
        S.guarded_submit(fake, chal, "R02TEST{x}", provenance="r02")
    assert fake.sent == []
    assert not chal.notes_path.exists() and not chal.load_tried().get("attempts")


def test_guarded_submit_without_a_client_profile_uses_the_current_event(clean_env, monkeypatch, chal):
    fake = _FakeClient()                            # duck-typed client with no .profile
    monkeypatch.setenv("CTF_EVENT", "spooky")
    with pytest.raises(NotAllowed, match="spooky"):
        S.guarded_submit(fake, chal, "R02TEST{x}", provenance="r02")
    assert fake.sent == []
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert S.guarded_submit(fake, chal, "R02TEST{x}", provenance="r02").status == "correct"
    assert fake.sent == [(7, "R02TEST{x}")]


def test_guarded_submit_sends_for_an_automation_event(chal):
    fake = _FakeClient(AUTO)
    assert S.guarded_submit(fake, chal, "R02TEST{x}", provenance="r02").correct
    assert fake.sent == [(7, "R02TEST{x}")]


# ------------------------------------------------------------------------------- ctf.dynamic
_DATE = "Wed, 05 Nov 2025 13:00:10 GMT"     # 10 s into a rotation window


def test_solve_dynamic_refuses_before_the_clock_probe_and_the_fetch(clean_env, monkeypatch):
    from ctf.platform import SubmitGate, ctfd, get_adapter
    b = Boundary(monkeypatch)
    monkeypatch.setenv("CTF_TOKEN", DUMMY_AUTH)
    fetched: list = []
    # spooky through get_adapter (the manual adapter); a submit_mode-manual CTFd event around the
    # real CTFd adapter, whose session is the recorder
    for gate in (get_adapter(E.load("spooky")), SubmitGate(ctfd.make_adapter(SUBMIT_MANUAL), SUBMIT_MANUAL)):
        with pytest.raises(NotAllowed):
            D.solve_dynamic(gate, "7", lambda: fetched.append(1) or "R02TEST{x}", attempts=2,
                            clock=lambda: 10.0, sleep=lambda s: None)
    assert fetched == [] and b.calls() == [] and b.socket_calls == []


def test_solve_dynamic_runs_for_an_automation_event(clean_env, monkeypatch):
    import email.utils
    from ctf.platform import get_adapter
    routes = _routes("R02TEST{x}")
    routes[("HEAD", BASE + "/")] = {}
    b = Boundary(monkeypatch, routes)
    _use_event(monkeypatch, "csctf")
    gate = get_adapter(AUTO)
    [session] = b.sessions
    plain = session._answer

    def answer(method, url, json_body=None):
        r = plain(method, url, json_body)
        if method == "HEAD":
            r.headers["Date"] = _DATE
        return r
    session._answer = answer
    server = email.utils.parsedate_to_datetime(_DATE).timestamp()
    res = D.solve_dynamic(gate, "7", lambda: "R02TEST{x}", attempts=2, clock=lambda: server,
                          sleep=lambda s: None)
    assert res.accepted
    assert [c[:2] for c in b.calls()] == [("HEAD", BASE + "/"), ("POST", API + "/challenges/attempt")]


# ------------------------------------------------------------------------------- ctf.fastlane
_SANITY = {"id": 1, "name": "Read the rules", "category": "sanity", "description": "read the rules page"}


def _urlopen_recorder(monkeypatch, body: bytes):
    opened: list[str] = []

    class _R:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, n=-1):
            return body

    def fake_urlopen(req, timeout=None):
        opened.append(req.full_url)
        return _R()
    monkeypatch.setattr(FL.urllib.request, "urlopen", fake_urlopen)
    return opened


def test_fastlane_does_not_fetch_the_rules_page_of_a_manual_event(clean_env, monkeypatch):
    _use_event(monkeypatch, "spooky")
    opened = _urlopen_recorder(monkeypatch, b"spooky{should_not_be_read}")
    r = FL.try_solve(_SANITY, None, online=True)
    assert opened == []
    assert r is not None and r["flag"] is None
    assert "not fetched" in r["how"] and "'spooky' is manual" in r["how"]
    assert r["instruction"] and "/rules" in r["instruction"]


def test_fastlane_fetches_the_rules_page_for_an_automation_event(clean_env, monkeypatch):
    _use_event(monkeypatch, "csctf")
    flag = csctf_flag("rules_page")
    opened = _urlopen_recorder(monkeypatch, f"<p>{flag}</p>".encode())
    r = FL.try_solve(_SANITY, None, online=True)
    assert opened == [BASE + "/rules"]
    assert r["flag"] == flag


# ------------------------------------------------------------------------------- python -m ctf (real entry)
_TRIPWIRE = textwrap.dedent("""
    import os, socket
    _LOG = os.environ["R02_TRIPWIRE_LOG"]

    def _note(what):
        with open(_LOG, "a", encoding="utf-8") as fh:
            fh.write(what + "\\n")

    def _trip(what):
        def fn(*a, **k):
            _note(what)
            raise OSError("R-02 tripwire: " + what + " attempted")
        return fn

    socket.getaddrinfo = _trip("getaddrinfo")
    socket.create_connection = _trip("create_connection")
    socket.socket.connect = _trip("connect")
    import requests
    _orig_init = requests.Session.__init__

    def _session_init(self, *a, **k):
        _note("session")
        _orig_init(self, *a, **k)

    requests.Session.__init__ = _session_init
""")


def _run_ctf(tmp_path: Path, event: str, argv: list[str]) -> tuple[subprocess.CompletedProcess, list[str]]:
    hook = tmp_path / "hook"
    hook.mkdir(exist_ok=True)
    (hook / "sitecustomize.py").write_text(_TRIPWIRE, encoding="utf-8")
    log = tmp_path / f"trip-{event}-{argv[0]}.log"
    env = {k: v for k, v in os.environ.items()
           if not any(k == n or k in ENV.legacy_names(n) for n in EVENT_VARS)}
    env.update(PYTHONPATH=os.pathsep.join([str(hook), str(REPO)]), R02_TRIPWIRE_LOG=str(log),
               CTF_EVENT=event, CTF_TOKEN=DUMMY_AUTH, CTF_PLATFORM_URL=BASE,
               CTF_WORKDIR=str(tmp_path / "work"), PYTHONDONTWRITEBYTECODE="1")
    env[C.SUBMIT_STATE_ENV] = str(tmp_path / "pace")
    proc = subprocess.run([sys.executable, "-m", "ctf", *argv], cwd=str(tmp_path), env=env,
                          capture_output=True, text=True, timeout=120)
    hits = log.read_text(encoding="utf-8").split() if log.exists() else []
    return proc, hits


@pytest.mark.parametrize("argv", [["submit", "7", "spooky{r02_value}"], ["pull", "7"], ["list"], ["status"]],
                         ids=lambda a: a[0])
def test_python_m_ctf_refuses_under_spooky_with_no_socket_or_session(tmp_path, argv):
    proc, hits = _run_ctf(tmp_path, "spooky", argv)
    assert proc.returncode == 4, proc.stderr
    assert "refused:" in proc.stderr and "'spooky' is manual" in proc.stderr
    assert hits == [], f"connection attempted under a manual event: {hits}"


def test_python_m_ctf_tripwire_fires_under_csctf(tmp_path):
    # The control: the same entry under a CTFd event builds a session and tries to connect, so the
    # tripwire above is live (it raises before any packet leaves).
    proc, hits = _run_ctf(tmp_path, "csctf", ["list"])
    assert proc.returncode != 0 and proc.returncode != 4, proc.stderr
    assert "session" in hits and any(h in hits for h in ("getaddrinfo", "create_connection", "connect")), \
        (hits, proc.stderr[-400:])
