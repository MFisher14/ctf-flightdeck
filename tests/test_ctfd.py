"""The CTFd adapter, over real HTTP to the fake CTFd (tests/fake_ctfd.py).

Nothing is mocked: each test starts a FakeCTFd on 127.0.0.1 with invented challenges,
scripts what it needs, and reads back what the adapter sent and wrote. No real CTFd is
contacted. pytest has no async support here, so each call runs on a fresh event loop with
asyncio.run(). Backoffs are a millisecond so retries stay fast; the tests about waiting use
waits that are short but long enough to measure.
"""

from __future__ import annotations

import asyncio
import email.utils
import fcntl
import json
import os
import socket
import stat
import time
from pathlib import Path

import httpx
import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, ChallengeStatus, DeckConfig, EventKind, PendingKind
from ctf_flightdeck.platform.ctfd import (
    MAX_REDIRECTS,
    STATE_FILE,
    Attempt,
    CTFdClient,
    CTFdError,
    CTFdVerifier,
    Pull,
    PullIncomplete,
    PullStopped,
    load_ids,
    origins_in,
    pull,
    pull_board,
    slugify,
)
from ctf_flightdeck.platform.manual import load_board
from fake_ctfd import FLAG_FORMAT, HANG_UP, TOKEN, FakeChallenge, FakeCTFd, Reply, make_tls, sample


def client(fake: FakeCTFd, *, token: str = TOKEN, **options) -> CTFdClient:
    options.setdefault("backoff", 0.001)
    options.setdefault("max_retries", 2)
    options.setdefault("timeout", 5.0)
    return CTFdClient(fake.base_url, token, **options)


def call(fake: FakeCTFd, use, **options):
    """`await use(client)` with a fresh client on a fresh event loop."""

    async def run():
        async with client(fake, **options) as c:
            return await use(c)

    return asyncio.run(run())


def pulled(fake: FakeCTFd, dest: Path, *, event: str = "Fake CTF", flag_format: str | None = FLAG_FORMAT, **options) -> Pull:
    return call(fake, lambda c: pull(c, dest, event=event, flag_format=flag_format), **options)


def failure(fake: FakeCTFd, use, **options) -> CTFdError:
    with pytest.raises(CTFdError) as caught:
        call(fake, use, **options)
    return caught.value


def closed_port() -> int:
    """A port on 127.0.0.1 that nothing listens on."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def unreachable(**options) -> CTFdError:
    """The error from listing challenges at a CTFd that is not there."""

    async def run():
        async with CTFdClient(f"http://127.0.0.1:{closed_port()}", TOKEN, backoff=0.001, **options) as c:
            await c.challenges()

    with pytest.raises(CTFdError) as caught:
        asyncio.run(run())
    return caught.value


def assert_hides_token(error: BaseException, token: str = TOKEN) -> None:
    assert token not in str(error)
    assert token not in repr(error)
    assert all(token not in str(arg) for arg in error.args)
    # no httpx error in the chain: its request holds the Authorization header
    assert error.__cause__ is None and error.__context__ is None


# ---------------------------------------------------------------------- requests and the token


def test_every_request_carries_the_token_and_says_it_is_json(tmp_path):
    # CTFd reads the token only from a request that says it is JSON, GETs and downloads included
    with FakeCTFd(sample()) as fake:
        pulled(fake, tmp_path / "board")
        call(fake, lambda c: c.attempt(1, "test{hello}"))
        call(fake, lambda c: c.solved_ids())
        assert {r.route.split("/")[1] for r in fake.requests} == {"api", "files"}
        for request in fake.requests:
            assert request.headers["authorization"] == f"Token {TOKEN}"
            assert request.headers["content-type"] == "application/json"
        assert all(r.headers["user-agent"].startswith("ctf-flightdeck/") for r in fake.requests)


def test_a_refused_token_is_an_error_naming_the_endpoint_and_status():
    with FakeCTFd(sample()) as fake:
        error = failure(fake, lambda c: c.challenges(), token="not-the-right-token")
    assert error.status == 401 and error.endpoint == "GET /api/v1/challenges"
    assert "refused the API token" in str(error) and "Your access token is invalid" in str(error)
    assert "GET /api/v1/challenges" in str(error) and not error.retryable
    assert_hides_token(error, "not-the-right-token")


def test_a_403_says_the_token_was_refused_or_not_allowed_now_and_shows_ctfds_words():
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", Reply(403, {"message": "Fake CTF has not started yet"}))
        error = failure(fake, lambda c: c.challenges())
    assert error.status == 403
    assert "the token was refused, or this account may not do this now" in str(error)
    assert "Fake CTF has not started yet" in str(error)


def test_the_token_is_never_in_an_error_a_repr_or_an_exception_chain(tmp_path):
    echo = {"message": f"bad header: Token {TOKEN}"}  # a server that echoes what it got
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", Reply(400, echo))
        errors = [failure(fake, lambda c: c.challenges())]
        fake.script("GET", "/api/v1/challenges", *[Reply(503, echo)] * 3)
        errors.append(failure(fake, lambda c: c.challenges()))
        fake.script("GET", "/api/v1/challenges", Reply(200, {"success": False, "errors": {"token": [TOKEN]}}))
        errors.append(failure(fake, lambda c: c.challenges()))
        fake.script("POST", "/api/v1/challenges/attempt", Reply(502, echo))
        errors.append(failure(fake, lambda c: c.attempt(1, "test{x}")))
        errors.append(unreachable(max_retries=1))
        assert TOKEN not in repr(client(fake))
        assert TOKEN not in repr(CTFdVerifier(fake.base_url, TOKEN, {"warmup": 1}))
    for error in errors:
        assert_hides_token(error)
    assert "[token]" in str(errors[0]) and "[token]" in str(errors[2])


def test_a_token_a_header_cannot_carry_is_refused_without_being_shown():
    for bad in ("", "two words", "line\nbreak", "café"):
        with pytest.raises(ValueError) as caught:
            CTFdClient("https://ctf.example.org", bad)
        assert "token" in str(caught.value)
        if bad:
            assert bad not in str(caught.value)


def test_the_url_must_be_http_with_no_credentials_query_or_fragment():
    for bad in ("ftp://ctf.example.org", "ctf.example.org", "https://player:hunter2pw@ctf.example.org",
                "https://ctf.example.org/?x=1", "https://ctf.example.org/#top", "https://"):
        with pytest.raises(ValueError) as caught:
            CTFdClient(bad, TOKEN)
        assert "hunter2pw" not in str(caught.value)
    assert CTFdClient("https://CTF.example.org/sub/", TOKEN).base_url == "https://ctf.example.org/sub"


# ---------------------------------------------------------------------- listing, pages, answers


def test_challenges_follows_every_page_in_ctfds_order():
    board = sample() + [FakeChallenge(5, "Second Warmup", value=50)]
    with FakeCTFd(board, page_size=2) as fake:
        listed = call(fake, lambda c: c.challenges())
        pages = [r.path for r in fake.to("/api/v1/challenges")]
    assert [item["id"] for item in listed] == [1, 5, 2, 3, 4]  # value, then id
    assert pages == ["/api/v1/challenges", "/api/v1/challenges?page=2", "/api/v1/challenges?page=3"]


def test_a_next_page_that_goes_back_is_an_error_not_a_loop():
    looping = {"success": True, "data": [], "meta": {"pagination": {"page": 1, "next": 1}}}
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", Reply(200, looping))
        error = failure(fake, lambda c: c.challenges())
        assert len(fake.to("/api/v1/challenges")) == 1
    assert "next page" in str(error)


def test_success_false_is_an_error_with_ctfds_words():
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges/2", Reply(200, {"success": False, "errors": {"id": ["No such thing"]}}))
        error = failure(fake, lambda c: c.challenge(2))
    assert error.endpoint == "GET /api/v1/challenges/2"
    assert "success: false" in str(error) and "id: No such thing" in str(error)


def test_an_answer_that_is_not_json_says_so():
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", Reply(200, "<html><body>Log in</body></html>"))
        error = failure(fake, lambda c: c.challenges())
    assert "not JSON" in str(error) and "the CTFd's address" in str(error)


def test_server_text_in_an_error_is_made_safe_and_short():
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", Reply(400, {"message": "\x1b[31mred\x1b[0m\n" + "x" * 5000}))
        error = failure(fake, lambda c: c.challenges())
    assert "\x1b" not in str(error) and "\n" not in str(error)
    assert "^[[31mred" in str(error) and len(str(error)) < 600


def test_an_api_redirect_is_never_followed():
    with FakeCTFd(sample()) as fake, FakeCTFd(sample()) as elsewhere:
        target = f"{elsewhere.base_url}/api/v1/challenges"
        fake.script("GET", "/api/v1/challenges", Reply(302, None, {"Location": target}))
        error = failure(fake, lambda c: c.challenges())
        assert elsewhere.requests == []  # the token never went there
    assert error.status == 302 and "never follows a redirect" in str(error)
    assert elsewhere.base_url in str(error)  # its origin only


# ---------------------------------------------------------------------- retries


def test_429_and_5xx_are_retried_and_then_the_answer_is_used():
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", Reply(503, "busy"), Reply(429, {"code": 429, "message": "slow down"}))
        listed = call(fake, lambda c: c.challenges())
        assert len(fake.to("/api/v1/challenges")) == 3
    assert len(listed) == 4


def test_retry_after_is_honoured():
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", Reply(429, {"message": "slow"}, {"Retry-After": "0.4"}))
        call(fake, lambda c: c.challenges(), backoff=0.001)
        first, second = fake.to("/api/v1/challenges")
    assert second.at - first.at >= 0.35


def test_retry_after_as_an_http_date_is_honoured():
    past = email.utils.formatdate(time.time() - 60, usegmt=True)
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", Reply(503, "busy", {"Retry-After": past}))
        started = time.monotonic()
        call(fake, lambda c: c.challenges(), backoff=3.0, max_wait=10.0)  # the date says: now, not 3 s
    assert time.monotonic() - started < 2.0


def test_retry_after_is_capped_by_max_wait():
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", Reply(429, {"message": "slow"}, {"Retry-After": "3600"}))
        started = time.monotonic()
        call(fake, lambda c: c.challenges(), max_wait=0.2)
        first, second = fake.to("/api/v1/challenges")
    assert 0.15 <= second.at - first.at and time.monotonic() - started < 5.0


def test_retries_give_up_with_the_status_and_the_number_of_tries():
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", *[Reply(500, {"message": "broken"})] * 5)
        error = failure(fake, lambda c: c.challenges(), max_retries=2)
        assert len(fake.to("/api/v1/challenges")) == 3
    assert error.status == 500 and error.retryable
    assert "HTTP 500" in str(error) and "gave up after 3 tries" in str(error) and "broken" in str(error)


def test_a_dropped_connection_is_retried():
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges", HANG_UP)
        assert len(call(fake, lambda c: c.challenges())) == 4
        assert len(fake.to("/api/v1/challenges")) == 2


def test_no_answer_at_all_is_an_error_saying_so():
    error = unreachable(max_retries=1)
    assert error.status is None and error.retryable
    assert "no answer from CTFd" in str(error) and "gave up after 2 tries" in str(error)


# ---------------------------------------------------------------------- downloads


def test_a_download_writes_the_file_without_an_execute_bit(tmp_path):
    with FakeCTFd(sample()) as fake:
        path = call(fake, lambda c: c.download(fake.file_url(4, "echo.bin"), tmp_path))
    assert path == tmp_path / "echo.bin"
    assert path.read_bytes() == b"not a real program\n"
    assert not path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_a_file_name_that_is_a_path_is_refused_and_nothing_escapes(tmp_path):
    dest = tmp_path / "a" / "b"
    dest.mkdir(parents=True)
    hostile = ["/files/0123456789abcdef/..%2F..%2Fx", "/files/0123456789abcdef/..%5C..%5Cx",
               "/files/0123456789abcdef/%2E%2E", "/files/0123456789abcdef/", "/files/0123456789abcdef/a%00b",
               "/files/0123456789abcdef/%1B%5B2J"]
    with FakeCTFd(sample()) as fake:
        for url in hostile:
            error = failure(fake, lambda c, url=url: c.download(url, dest))
            assert "refuses to write it" in str(error) and "\x1b" not in str(error)
        assert fake.requests == []  # refused before anything was asked for
    assert sorted(tmp_path.rglob("*")) == [tmp_path / "a", dest]  # nothing written anywhere


def test_a_file_url_to_another_host_is_refused_without_a_request(tmp_path):
    with FakeCTFd(sample()) as fake, FakeCTFd(sample()) as elsewhere:
        other = elsewhere.file_url(1, "hello.txt")
        port = elsewhere.base_url.rsplit(":", 1)[1]
        for url in (elsewhere.base_url + other, f"//127.0.0.1:{port}{other}", "https://cdn.example.org/files/x/hello.txt",
                    "ftp://127.0.0.1/hello.txt"):
            error = failure(fake, lambda c, url=url: c.download(url, tmp_path))
            assert "is on another host" in str(error) and "token=" not in str(error)
        assert elsewhere.requests == [] and fake.requests == []
    assert list(tmp_path.iterdir()) == []


def test_a_download_redirected_to_another_host_over_plain_http_is_refused(tmp_path):
    with FakeCTFd(sample()) as fake, FakeCTFd(sample()) as elsewhere:
        url = fake.file_url(1, "hello.txt")
        signed = f"{elsewhere.base_url}{url.split('?')[0]}?X-Amz-Signature=s3cr3t-signature"
        fake.script("GET", url.split("?")[0], Reply(302, None, {"Location": signed}))
        error = failure(fake, lambda c: c.download(url, tmp_path))
        assert elsewhere.requests == []
    assert "another host" in str(error) and "only over https" in str(error) and elsewhere.base_url in str(error)
    assert "s3cr3t-signature" not in str(error) and list(tmp_path.iterdir()) == []


@pytest.fixture(scope="session")
def tls_files(tmp_path_factory):
    try:
        return make_tls(tmp_path_factory.mktemp("tls"))
    except FileNotFoundError:
        pytest.skip("not run: the openssl command is not installed, and this test needs it to make a test certificate")


@pytest.fixture
def tls(tls_files, monkeypatch):
    """The test certificates, with httpx trusting their authority (SSL_CERT_FILE) in this test."""
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_files.ca))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    return tls_files


def redirect_to_storage(fake: FakeCTFd, storage: FakeCTFd, number: int, name: str, *, serve: bool = True) -> str:
    """Script CTFd on S3: the file's URL answers with a redirect to a signed URL on the storage's host
    (and a session cookie, as CTFd may set one), and the storage serves the file there."""
    path = fake.file_url(number, name).split("?")[0]
    signed = f"{storage.base_url}/bucket{path}?X-Amz-Signature=s3cr3t-signature&X-Amz-Expires=3600"
    fake.script("GET", path, Reply(302, None, {"Location": signed, "Set-Cookie": "session=ctfd-session; Path=/"}))
    if serve:
        storage.script("GET", f"/bucket{path}", Reply(200, fake.challenges[number].files[name]))
    return f"/bucket{path}"


def test_a_file_ctfd_sends_to_object_storage_is_fetched_there_without_the_token_or_a_cookie(tmp_path, tls):
    with FakeCTFd(sample()) as fake, FakeCTFd([], tls=tls) as storage:
        for number, name in ((1, "hello.txt"), (2, "out.txt"), (4, "echo.bin")):
            redirect_to_storage(fake, storage, number, name)
        result = pulled(fake, tmp_path / "board")
        fetched = list(storage.requests)
    assert result.problems == () and len(result.board.challenges) == 4
    assert (tmp_path / "board" / "baby-rsa" / "out.txt").read_bytes() == b"n = 3233\ne = 3\nc = 2201\n"
    assert sorted(r.route.rsplit("/", 1)[1] for r in fetched) == ["echo.bin", "hello.txt", "out.txt"]
    for request in fetched:  # the 127.0.0.1 cookie would go to any port; the token and JSON header are CTFd's
        assert {"authorization", "cookie", "content-type"}.isdisjoint(request.headers)
        assert request.headers["user-agent"].startswith("ctf-flightdeck/") and "X-Amz-Signature=" in request.path


def test_a_file_host_that_refuses_the_download_is_named_and_its_signed_url_is_not(tmp_path, tls):
    with FakeCTFd(sample()) as fake, FakeCTFd([], tls=tls) as storage:
        where = redirect_to_storage(fake, storage, 1, "hello.txt", serve=False)
        storage.script("GET", where, Reply(403, "<Error><Code>AccessDenied</Code></Error>"))
        error = failure(fake, lambda c: c.download(fake.file_url(1, "hello.txt"), tmp_path))
    assert f"the file host {storage.base_url}" in str(error) and "HTTP 403" in str(error)
    assert "token was refused" not in str(error) and "s3cr3t-signature" not in str(error)
    assert error.endpoint.startswith("GET /files/") and list(tmp_path.iterdir()) == []


def test_a_download_redirect_on_the_same_origin_is_followed(tmp_path):
    with FakeCTFd(sample()) as fake:
        real = fake.file_url(1, "hello.txt")
        moved = "/files/0000000000000000/hello.txt"
        fake.script("GET", moved, Reply(301, None, {"Location": real}))
        path = call(fake, lambda c: c.download(moved, tmp_path))
    assert path.read_bytes() == b"hello\n" and path.name == "hello.txt"


def test_an_https_ctfd_never_sends_the_token_in_clear_to_its_own_host_and_port(tmp_path):
    with FakeCTFd(sample()) as fake:  # it answers plain http on 127.0.0.1:<port>
        port = fake.base_url.rsplit(":", 1)[1]
        plain = f"http://127.0.0.1:{port}" + fake.file_url(1, "hello.txt")

        async def run():
            async with CTFdClient(f"https://127.0.0.1:{port}", TOKEN, backoff=0.001, max_retries=0) as c:
                return await c.download(plain, tmp_path)  # the CTFd as given is https; the file entry says http

        with pytest.raises(CTFdError) as caught:
            asyncio.run(run())
        assert fake.requests == []  # nothing went out, the token least of all
    assert f"is on another host (http://127.0.0.1:{port})" in str(caught.value) and list(tmp_path.iterdir()) == []


def test_an_https_ctfd_redirecting_a_download_to_plain_http_on_its_own_host_is_not_followed(tmp_path, tls):
    with FakeCTFd(sample(), tls=tls) as fake:
        url = fake.file_url(1, "hello.txt")
        downgraded = fake.base_url.replace("https://", "http://") + url  # the same host and port
        fake.script("GET", url.split("?")[0], Reply(302, None, {"Location": downgraded}))
        error = failure(fake, lambda c: c.download(url, tmp_path))
        assert len(fake.requests) == 1  # the redirect, and nothing after it
    assert "another host" in str(error) and "only over https" in str(error) and list(tmp_path.iterdir()) == []


def test_a_redirect_loop_on_ctfds_own_origin_is_cut_off(tmp_path):
    with FakeCTFd(sample()) as fake:
        url = fake.file_url(1, "hello.txt")
        fake.script("GET", url.split("?")[0], *[Reply(302, None, {"Location": url})] * 50)
        error = failure(fake, lambda c: c.download(url, tmp_path), max_retries=0)
        asked = len(fake.to(url.split("?")[0]))
    assert f"more than {MAX_REDIRECTS} times" in str(error) and asked == MAX_REDIRECTS + 1
    assert list(tmp_path.iterdir()) == []


def test_a_file_over_the_size_cap_is_refused_and_leaves_nothing(tmp_path):
    with FakeCTFd(sample()) as fake:
        error = failure(fake, lambda c: c.download(fake.file_url(2, "out.txt"), tmp_path), max_file_bytes=8)
    assert "over 8 bytes" in str(error) and list(tmp_path.iterdir()) == []


def test_a_file_over_the_cap_without_a_length_is_cut_off_and_leaves_nothing(tmp_path):
    with FakeCTFd(sample()) as fake:
        url = fake.file_url(1, "hello.txt")
        fake.script("GET", url.split("?")[0], Reply(200, b"y" * 65536, until_close=True))
        error = failure(fake, lambda c: c.download(url, tmp_path), max_file_bytes=100)
        fake.script("GET", url.split("?")[0], Reply(200, b"z" * 100, until_close=True))
        path = call(fake, lambda c: c.download(url, tmp_path), max_file_bytes=100)
    assert "over 100 bytes" in str(error)
    assert list(tmp_path.iterdir()) == [path] and path.read_bytes() == b"z" * 100  # at the cap is fine


def test_a_download_never_overwrites_and_never_writes_challenge_json(tmp_path):
    board = [FakeChallenge(9, "Files", files={"hello.txt": b"one", "challenge.json": b"{}", "archive.tar.gz": b"z"})]
    (tmp_path / "hello.txt").write_text("the player's own")
    with FakeCTFd(board) as fake:
        names = [call(fake, lambda c, n=n: c.download(fake.file_url(9, n), tmp_path)).name for n in board[0].files]
        again = call(fake, lambda c: c.download(fake.file_url(9, "archive.tar.gz"), tmp_path)).name
    assert names == ["hello-2.txt", "challenge-2.json", "archive.tar.gz"] and again == "archive-2.tar.gz"
    assert (tmp_path / "hello.txt").read_text() == "the player's own" and not (tmp_path / "challenge.json").exists()


def test_a_handout_named_like_challenge_json_in_another_case_gets_a_name_of_its_own(tmp_path):
    # on a case-insensitive file system (macOS, WSL's drvfs) "Challenge.json" IS challenge.json, which the pull
    # writes over it; here every file system gets the same names
    handout = b'{"api": "the challenge\'s own schema"}\n'
    board = [FakeChallenge(1, "Json Thing", category="Web", files={"Challenge.json": handout}),
             FakeChallenge(2, "Others", files={"CHALLENGE.JSON": b"upper", "challenge.jſon": b"long s"})]
    with FakeCTFd(board) as fake:
        result = pulled(fake, tmp_path / "board")
        direct = []
        for n, name in enumerate(("CHALLENGE.JSON", "challenge.jſon")):  # a folder each: what else is taken differs
            (tmp_path / f"direct-{n}").mkdir()
            direct.append(call(fake, lambda c, name=name, n=n: c.download(fake.file_url(2, name), tmp_path / f"direct-{n}")).name)
    found = {item.challenge.id: item for item in result.board.challenges}
    thing = found["json-thing"]
    assert result.problems == () and thing.challenge.files == ("Challenge-2.json",)
    assert (thing.handout / "Challenge-2.json").read_bytes() == handout
    assert json.loads((thing.handout / "challenge.json").read_text())["name"] == "Json Thing"
    assert direct == ["CHALLENGE-2.JSON", "challenge-2.jſon"]


def test_a_failed_download_names_the_file_but_never_its_file_token(tmp_path):
    with FakeCTFd(sample()) as fake:
        url = fake.file_url(1, "hello.txt")
        file_token = url.split("token=")[1]
        fake.script("GET", url.split("?")[0], *[Reply(500, {"message": f"no {url}"})] * 3)
        error = failure(fake, lambda c: c.download(url, tmp_path))
    assert "hello.txt" in str(error) and "HTTP 500" in str(error)
    assert file_token not in str(error) and "[file token]" in str(error)


# ---------------------------------------------------------------------- attempts


def test_an_attempt_sends_the_ctfd_id_and_the_flag():
    with FakeCTFd(sample()) as fake:
        call(fake, lambda c: c.attempt(2, "test{rsa}"))
        (sent,) = fake.to("/api/v1/challenges/attempt")
    assert sent.method == "POST" and sent.json == {"challenge_id": 2, "submission": "test{rsa}"}


def test_attempt_statuses_come_back_as_ctfd_gives_them():
    board = sample() + [FakeChallenge(6, "Two Tries", max_attempts=2, flag="test{two}"),
                        FakeChallenge(7, "Two Parts", flag="test{both}", partial=("test{half}",))]
    with FakeCTFd(board) as fake:
        def statuses(*tries):
            return [call(fake, lambda c, t=t: c.attempt(*t)) for t in tries]

        got = statuses((1, "test{nope}"), (1, "test{hello}"), (1, "test{hello}"), (6, "test{a}"), (6, "test{b}"),
                       (6, "test{two}"), (7, "test{half}"))
        fake.paused = True
        got += statuses((2, "test{rsa}"))
    # out of tries, CTFd answers "incorrect" with HTTP 403 before it checks the flag: here the right one
    assert [a.status for a in got] == ["incorrect", "correct", "already_solved", "incorrect", "incorrect", "locked_out",
                                       "partial", "paused"]
    assert got[3].message == "Incorrect. You have 1 try remaining." and got[4].message == "Incorrect. You have 0 tries remaining."
    assert got[5] == Attempt("locked_out", "You have 0 tries remaining") and 6 not in fake.solved
    assert got[7] == Attempt("paused", "Fake CTF is paused")


def test_a_ratelimited_attempt_is_returned_as_such_and_never_retried():
    limited = {"success": True, "data": {"status": "ratelimited", "message": "You're submitting flags too fast."}}
    locked = {"success": True, "data": {"status": "ratelimited", "message": "Another submission is being processed."}}
    with FakeCTFd(sample()) as fake:
        fake.script("POST", "/api/v1/challenges/attempt", Reply(429, limited), Reply(403, locked),
                    Reply(429, "<html>proxy says slow down</html>", {"Retry-After": "30"}))
        got = [call(fake, lambda c: c.attempt(1, "test{hello}")) for _ in range(3)]
        assert len(fake.to("/api/v1/challenges/attempt")) == 3  # one request each
    assert [a.status for a in got] == ["ratelimited"] * 3
    assert got[0].message == "You're submitting flags too fast." and "retry after 30" in got[2].message


def test_a_failed_attempt_is_never_retried_and_says_the_outcome_is_unknown():
    with FakeCTFd(sample()) as fake:
        fake.script("POST", "/api/v1/challenges/attempt", Reply(502, "bad gateway"), Reply(502, "bad gateway"))
        error = failure(fake, lambda c: c.attempt(1, "test{hello}"), max_retries=3)
        assert len(fake.to("/api/v1/challenges/attempt")) == 1
    assert error.status == 502 and "may have reached CTFd" in str(error)


def test_a_submit_cut_off_after_it_was_sent_says_the_flag_may_have_reached_ctfd():
    # CTFd got the flag (and may have counted the try), then the connection dropped: never "not submitted"
    with FakeCTFd(sample()) as fake:
        fake.script("POST", "/api/v1/challenges/attempt", HANG_UP, HANG_UP)
        error = failure(fake, lambda c: c.attempt(1, "test{hello}"))
        with CTFdVerifier(fake.base_url, TOKEN, {"warmup": 1}) as verify:
            assert verify("warmup", "test{hello}") is None
        assert len(fake.to("/api/v1/challenges/attempt")) == 2  # both arrived, once each
    for said in (str(error), verify.last_error):
        assert "no answer from CTFd" in said and "may have reached CTFd" in said and "not submitted" not in said


def test_an_attempt_status_flightdeck_does_not_know_is_an_error():
    weird = {"success": True, "data": {"status": "maybe", "message": "who knows"}}
    unauthenticated = {"success": True, "data": {"status": "authentication_required"}}
    with FakeCTFd(sample()) as fake:
        fake.script("POST", "/api/v1/challenges/attempt", Reply(200, weird), Reply(403, unauthenticated))
        first = failure(fake, lambda c: c.attempt(1, "test{a}"))
        second = failure(fake, lambda c: c.attempt(1, "test{a}"))
    assert '"maybe"' in str(first) and "does not know" in str(first)
    assert "did not take the token" in str(second) and "not submitted" in str(second)


# ---------------------------------------------------------------------- solves


def test_solved_ids_in_team_mode_counts_a_teammates_solve():
    with FakeCTFd(sample()) as fake:
        fake.solved, fake.user_solved = {1, 2}, {1}  # 2 was a teammate's
        assert call(fake, lambda c: c.solved_ids()) == {1, 2}
        assert fake.to("/api/v1/users/me/solves") == []


def test_solved_ids_in_users_mode_asks_the_users_endpoint():
    with FakeCTFd(sample(), team_mode=False) as fake:
        fake.solved = {3}
        assert call(fake, lambda c: c.solved_ids()) == {3}
        assert [r.route for r in fake.requests] == ["/api/v1/teams/me/solves", "/api/v1/users/me/solves"]


def test_solved_ids_for_a_player_not_on_a_team_yet_is_empty():
    with FakeCTFd(sample()) as fake:
        fake.no_team, fake.solved = True, {1}
        assert call(fake, lambda c: c.solved_ids()) == set()


def test_solved_ids_with_a_refused_token_does_not_fall_back():
    with FakeCTFd(sample()) as fake:
        error = failure(fake, lambda c: c.solved_ids(), token="not-the-right-token")
        assert len(fake.requests) == 1
    assert error.status == 401


# ---------------------------------------------------------------------- pulling a board


def test_a_pull_writes_a_folder_board_that_loads(tmp_path):
    dest = tmp_path / "board"
    lines: list[str] = []
    with FakeCTFd(sample()) as fake:
        result = call(fake, lambda c: pull(c, dest, event="Fake CTF", flag_format=FLAG_FORMAT, progress=lines.append))
    board = load_board(dest)
    assert board == result.board and board.event == "Fake CTF" and board.flag_format == FLAG_FORMAT
    found = {item.challenge.id: item for item in board.challenges}
    assert set(found) == {"warmup", "baby-rsa", "login-portal", "echo-service"}
    rsa = found["baby-rsa"].challenge
    assert (rsa.name, rsa.category, rsa.points, rsa.solves, rsa.description, rsa.files) == (
        "Baby RSA", "cry", 100, 40, "e is small.", ("out.txt",))
    assert (dest / "baby-rsa" / "out.txt").read_bytes() == b"n = 3233\ne = 3\nc = 2201\n"
    assert found["echo-service"].challenge.category == "pwn" and found["warmup"].challenge.files == ("hello.txt",)
    assert result.added == ("warmup", "baby-rsa", "login-portal", "echo-service")  # CTFd id order
    assert dict(result.ids) == {"warmup": 1, "baby-rsa": 2, "login-portal": 3, "echo-service": 4} == load_ids(dest)
    assert result.problems == () and result.hidden == 0
    assert lines[1] == 'added baby-rsa: "Baby RSA" (Crypto, 100 points, 1 file)'
    assert json.loads((dest / "board.json").read_text()) == {"event": "Fake CTF", "flag_format": FLAG_FORMAT}


def test_connection_info_gives_the_live_origins_and_joins_the_description(tmp_path):
    with FakeCTFd(sample()) as fake:
        board = pulled(fake, tmp_path / "board").board
    found = {item.challenge.id: item for item in board.challenges}
    web, pwn = found["login-portal"], found["echo-service"]
    assert web.urls == ("http://web.example.org:8080",) and web.challenge.live
    assert web.challenge.description == "Log in as admin.\n\nConnection info: http://web.example.org:8080/login"
    assert pwn.urls == () and not pwn.challenge.live  # nc is not a URL: no origin, but the lane still reads it
    assert pwn.challenge.description == "It echoes.\n\nConnection info: nc pwn.example.org 1337"
    assert found["warmup"].urls == () and found["warmup"].challenge.description == "Say hello."


def test_a_challenge_with_capped_tries_says_so_in_its_description(tmp_path):
    board = [FakeChallenge(1, "Capped", description="Guess well.", max_attempts=3), FakeChallenge(2, "One Shot", max_attempts=1),
             FakeChallenge(3, "Free", description="Any number of tries."), FakeChallenge(4, "Unsaid", max_attempts=None)]
    with FakeCTFd(board) as fake:
        found = {item.challenge.id: item.challenge for item in pulled(fake, tmp_path / "board").board.challenges}
    assert found["capped"].description == (
        "Guess well.\n\nNote from flightdeck: CTFd allows 3 attempts at this challenge's flag, then checks no more.")
    assert found["one-shot"].description == (
        "Note from flightdeck: CTFd allows 1 attempt at this challenge's flag, then checks no more.")
    assert found["free"].description == "Any number of tries." and found["unsaid"].description == ""


def test_connection_info_that_points_at_ctfd_itself_never_makes_ctfd_a_lanes_instance(tmp_path):
    # an instancer page served by a CTFd plugin: the lane must not get the platform as its target
    with FakeCTFd([]) as fake:
        on_https = fake.base_url.replace("http://", "https://")  # the same host and port, the other scheme
        fake.add(FakeChallenge(1, "Note Keeper", connection_info=f"Start your instance at {fake.base_url}/plugins/i/1"),
                 FakeChallenge(2, "Same Host", connection_info=f"http://127.0.0.1:31337/ or {on_https}/x"))
        found = {item.challenge.id: item for item in pulled(fake, tmp_path / "board").board.challenges}
    keeper, same = found["note-keeper"], found["same-host"]
    assert keeper.urls == () and not keeper.challenge.live
    assert keeper.challenge.description == (
        f"Connection info: Start your instance at {fake.base_url}/plugins/i/1\n\nNote from flightdeck: the connection "
        f"info points at CTFd itself ({fake.base_url}), which lanes never get as an instance.")
    assert same.urls == ("http://127.0.0.1:31337",)  # another port on CTFd's host is an instance like any other
    assert f"points at CTFd itself ({on_https})" in same.challenge.description


def test_ctfds_own_host_on_the_other_default_port_is_ctfd_too():
    from ctf_flightdeck.platform.ctfd import _on_ctfd  # CTFd on port 80 or 443 cannot be faked here

    ctfd = httpx.URL("https://ctf.example.org/")
    assert _on_ctfd("https://ctf.example.org", ctfd) and _on_ctfd("http://ctf.example.org", ctfd)
    assert _on_ctfd("https://ctf.example.org:443", ctfd) and _on_ctfd("http://CTF.example.org:80", ctfd)
    assert not _on_ctfd("http://ctf.example.org:8080", ctfd) and not _on_ctfd("https://chal.ctf.example.org", ctfd)
    odd = httpx.URL("http://10.0.0.1:8000/ctf/")
    assert _on_ctfd("https://10.0.0.1:8000", odd) and not _on_ctfd("http://10.0.0.1", odd)


def test_a_connection_url_the_board_would_refuse_is_left_in_the_text_not_in_the_urls(tmp_path):
    disguised = ("http://127.1:8080/", "http://2130706433/", "http://1.2.3.4.5/", "http://0x7f.1/", "http://10.0.0.256/")
    assert origins_in(" ".join(disguised)) == ()  # each a loopback address in disguise, or no address at all
    board = [FakeChallenge(1, "Short Form", connection_info="Instance: http://127.1:8080/ (or nc 127.0.0.1 9001)")]
    with FakeCTFd(board) as fake:
        result = pulled(fake, tmp_path / "board")
    (item,) = result.board.challenges
    assert result.problems == () and item.urls == ()
    assert item.challenge.description == "Connection info: Instance: http://127.1:8080/ (or nc 127.0.0.1 9001)"


def test_a_description_too_long_for_challenge_json_is_cut_short_and_kept_whole_in_a_file(tmp_path):
    inline = "![diagram](data:image/png;base64," + "A" * 1_100_000 + ")"  # an image pasted into the description
    wide = "暗号" * 100_000  # 200,000 characters, six bytes each in challenge.json
    board = [FakeChallenge(1, "Big Image", description=inline, connection_info="nc chal.example.org 1337",
                           files={"description.md": b"the challenge's own file"}),
             FakeChallenge(2, "Wide Text", description=wide), FakeChallenge(3, "Small", description="x" * 150_000)]
    lines: list[str] = []
    with FakeCTFd(board) as fake:
        result = call(fake, lambda c: pull(c, tmp_path / "board", event="Fake CTF", flag_format=None, progress=lines.append))
    assert result.problems == () and len(result.board.challenges) == 3
    found = {item.challenge.id: item for item in result.board.challenges}
    big, wide_one, small = found["big-image"], found["wide-text"], found["small"]
    assert big.challenge.files == ("description.md", "description-2.md")
    assert (big.handout / "description.md").read_bytes() == b"the challenge's own file"
    assert (big.handout / "description-2.md").read_text(encoding="utf-8") == (
        inline + "\n\nConnection info: nc chal.example.org 1337")
    shown = big.challenge.description
    assert shown.startswith("![diagram](data:image/png;base64,AAAA") and len(shown) < 120_000
    assert shown.endswith("\n\nNote from flightdeck: this description is too long for the board, so it is cut short; "
                          "the whole of it is in the file description-2.md.\n\nConnection info: nc chal.example.org 1337")
    assert (wide_one.handout / "description.md").read_text(encoding="utf-8") == wide
    assert wide_one.challenge.description.startswith(wide[:1000]) and len(wide_one.challenge.description) < 20_000
    assert small.challenge.description == "x" * 150_000 and small.challenge.files == ()  # long, but it fits: whole
    assert lines[0] == ('added big-image: "Big Image" (misc, 100 points, 2 files; its description is cut short, '
                        "the whole of it is in description-2.md)")


def test_origins_are_taken_from_urls_in_the_connection_info():
    assert origins_in(None) == () and origins_in("") == () and origins_in("nc chal.example.org 31337") == ()
    assert origins_in("http://web.example.org:8080") == ("http://web.example.org:8080",)
    assert origins_in("HTTPS://Web.Example.ORG/login?next=/admin#x") == ("https://web.example.org",)
    assert origins_in("Visit http://a.example.org. Or https://b.example.org:8443/x, or (http://c.example.org)") == (
        "http://a.example.org", "https://b.example.org:8443", "http://c.example.org")
    assert origins_in("http://a.example.org/1 http://a.example.org/2") == ("http://a.example.org",)
    assert origins_in("http://guest:guest@web.example.org/") == ("http://web.example.org",)
    assert origins_in("http://[::1]:8080/ and http://10.0.0.5:5000/") == ("http://[::1]:8080", "http://10.0.0.5:5000")
    assert origins_in("ftp://files.example.org http://bad_port.example.org:99999 http://") == ()


def test_text_from_ctfd_with_a_lone_surrogate_is_made_valid_before_it_is_kept_or_shown(tmp_path):
    # "\ud800" is valid JSON, and nothing can encode it: not print(), a terminal, a log or a file
    board = [FakeChallenge(1, "Bad \ud800 Name", category="Mi\udc00sc", description="De\ud83dsc",
                           connection_info="nc a.example.org 1 \udfff"),
             FakeChallenge(2, "Far \ud800", file_urls=["https://cdn.example.org/far.zip"])]
    incorrect = {"success": True, "data": {"status": "incorrect", "message": "No \ud800 way"}}
    with FakeCTFd(board) as fake:
        result = pulled(fake, tmp_path / "board")
        fake.script("POST", "/api/v1/challenges/attempt", Reply(200, incorrect))
        attempt = call(fake, lambda c: c.attempt(1, "test{x}"))
        fake.script("GET", "/api/v1/challenges", Reply(403, {"message": "closed \ud800 now"}))
        error = failure(fake, lambda c: c.challenges())
    (item,) = result.board.challenges
    shown = (item.challenge.name, item.challenge.category, item.challenge.description)
    assert shown == ("Bad � Name", "mi�sc", "De�sc\n\nConnection info: nc a.example.org 1 �")
    (problem,) = result.problems
    assert problem.startswith('challenge 2 ("Far �"): ') and attempt.message == "No � way"
    assert "closed � now" in str(error)
    for text in (*shown, problem, attempt.message, str(error)):
        text.encode("utf-8")  # strict: raises on a lone surrogate


def test_slugs_are_board_ids_and_unique(tmp_path):
    board = [FakeChallenge(3, "Warmup"), FakeChallenge(7, "Warmup", category="Crypto"), FakeChallenge(8, "???"),
             FakeChallenge(9, "Café Crème – Part 1"), FakeChallenge(10, "A" * 100),
             FakeChallenge(11, "board.json")]
    with FakeCTFd(board) as fake:
        result = pulled(fake, tmp_path / "board")
    assert result.added == ("warmup", "warmup-7", "challenge-8", "cafe-creme-part-1", "a" * 40, "board-json")
    assert slugify("  --Hello, World!--  ") == "hello-world" and slugify("暗号") == ""


def test_locked_challenges_are_left_out_counted_and_never_asked_for(tmp_path):
    with FakeCTFd(sample() + [FakeChallenge(5, "Locked One", type="hidden")]) as fake:
        result = pulled(fake, tmp_path / "board")
        assert fake.to("/api/v1/challenges/5") == []
    assert result.hidden == 1 and result.problems == () and len(result.board.challenges) == 4


def test_a_wave_re_pull_keeps_every_folder_and_adds_the_new_ones(tmp_path):
    dest = tmp_path / "board"
    with FakeCTFd(sample()) as fake:
        pulled(fake, dest)
        (dest / "warmup" / "notes.txt").write_text("the player's notes")
        before = (dest / "warmup" / "challenge.json").read_bytes()
        fake.challenges[1].description = "Changed on CTFd after the first pull."
        fake.add(FakeChallenge(5, "Second Wave", category="Forensics", value=150, files={"disk.img": b"\0" * 64}))
        asked = len(fake.requests)
        result = pulled(fake, dest)
        second = [r.route for r in fake.requests[asked:]]
    assert result.added == ("second-wave",) and result.problems == ()  # the folders there are kept, not in the way
    assert second == ["/api/v1/challenges", "/api/v1/challenges/5", second[2]] and second[2].endswith("/disk.img")
    assert (dest / "warmup" / "challenge.json").read_bytes() == before
    assert (dest / "warmup" / "notes.txt").read_text() == "the player's notes"
    assert len(result.board.challenges) == 5 and dict(result.ids)["second-wave"] == 5 and load_ids(dest)["warmup"] == 1


def test_a_re_pull_keeps_board_json_and_may_add_a_flag_format_it_lacked(tmp_path):
    dest = tmp_path / "spring"
    with FakeCTFd(sample()) as fake:
        first = pulled(fake, dest, event=None, flag_format=None)
        kept = pulled(fake, dest, event=None, flag_format=None)
        added = pulled(fake, dest, event=None, flag_format=FLAG_FORMAT)
    assert (first.board.event, first.board.flag_format) == ("spring", None)  # a new board: the folder's name
    assert (kept.board.event, kept.board.flag_format) == ("spring", None)
    assert (added.board.event, added.board.flag_format) == ("spring", FLAG_FORMAT)


def test_a_challenge_that_cannot_be_pulled_is_left_out_and_retried_next_time(tmp_path):
    dest = tmp_path / "board"
    board = sample() + [FakeChallenge(5, "Far Away", file_urls=["https://cdn.example.org/files/x/far.zip"])]
    with FakeCTFd(board) as fake:
        result = pulled(fake, dest)
        assert len(result.board.challenges) == 4 and result.added == ("warmup", "baby-rsa", "login-portal", "echo-service")
        (problem,) = result.problems
        assert problem.startswith('challenge 5 ("Far Away"): ') and "is on another host (https://cdn.example.org)" in problem
        assert not (dest / "far-away").exists() and "far-away" not in load_ids(dest)
        assert not [p for p in dest.iterdir() if p.name.startswith(".ctfd-pull-")]
        fake.challenges[5].file_urls = None
        fake.challenges[5].files = {"far.zip": b"PK fake"}
        again = pulled(fake, dest)
    assert again.added == ("far-away",) and again.problems == ()
    assert (dest / "far-away" / "far.zip").read_bytes() == b"PK fake"


def test_bad_values_from_ctfd_are_problems_not_a_broken_board(tmp_path):
    with FakeCTFd(sample()) as fake:
        detail = {"success": True, "data": {"id": 2, "name": "Baby RSA", "value": "100", "category": "Crypto"}}
        fake.script("GET", "/api/v1/challenges/2", Reply(200, detail))
        fake.script("GET", "/api/v1/challenges/3", Reply(200, {"success": True, "data": {"id": 99, "name": "Other"}}))
        result = pulled(fake, tmp_path / "board")
    assert [p.split(":")[0] for p in result.problems] == ['challenge 2 ("Baby RSA")', 'challenge 3 ("Login Portal")']
    assert "value (points) is not a whole number" in result.problems[0]
    assert "details of another challenge" in result.problems[1]
    assert {item.challenge.id for item in result.board.challenges} == {"warmup", "echo-service"}


def test_pull_board_is_the_whole_board_or_pull_incomplete(tmp_path):
    with FakeCTFd(sample()) as fake:
        board = call(fake, lambda c: pull_board(c, tmp_path / "one", event="Fake CTF", flag_format=None))
        assert len(board.challenges) == 4 and board.flag_format is None
        fake.add(FakeChallenge(5, "Far Away", file_urls=["//cdn.example.org/far.zip"]))
        with pytest.raises(PullIncomplete) as caught:
            call(fake, lambda c: pull_board(c, tmp_path / "two", event="Fake CTF", flag_format=None))
    assert len(caught.value.pull.board.challenges) == 4 and "Far Away" in str(caught.value)
    assert str(caught.value).startswith("1 challenge not pulled: ")


def test_a_challenge_that_keeps_failing_is_left_out_and_the_ones_after_it_are_pulled(tmp_path):
    # a challenge plugin that crashes, or one handout the proxy cannot serve, while CTFd itself answers
    for where in ("details", "file"):
        dest = tmp_path / where
        with FakeCTFd(sample()) as fake:
            route = "/api/v1/challenges/2" if where == "details" else fake.file_url(2, "out.txt").split("?")[0]
            fake.script("GET", route, *[Reply(500, {"message": "Internal Server Error"})] * 20)
            first = pulled(fake, dest, max_retries=1)
            again = pulled(fake, dest, max_retries=1)
            assert [len(fake.to(f"/api/v1/challenges/{n}")) for n in (3, 4)] == [1, 1]  # pulled once, then kept
            assert len(fake.to("/api/v1/challenges")) == 4  # each pull lists, then asks again after the failure
        assert first.added == ("warmup", "login-portal", "echo-service") and again.added == ()
        (problem,) = first.problems
        assert problem.startswith('challenge 2 ("Baby RSA"): ') and "HTTP 500" in problem and again.problems == (problem,)
        assert load_ids(dest) == {"warmup": 1, "login-portal": 3, "echo-service": 4}


def test_a_pull_stops_when_ctfd_stops_answering_and_the_next_one_goes_on(tmp_path):
    dest = tmp_path / "board"
    with FakeCTFd(sample()) as fake:
        fake.challenges[2].file_urls = ["https://cdn.example.org/x/far.zip"]  # a problem before CTFd goes down
        # the list comes through, then CTFd goes down: challenge 3's details fail, and so does the list asked again
        fake.script("GET", "/api/v1/challenges", Reply(200, fake.listing()), *[Reply(503, "down")] * 2)
        fake.script("GET", "/api/v1/challenges/3", *[Reply(503, "down")] * 2)
        with pytest.raises(PullStopped) as caught:
            call(fake, lambda c: pull(c, dest, event="Fake CTF", flag_format=None), max_retries=1)
        error = caught.value
        assert fake.to("/api/v1/challenges/4") == []  # it stopped instead of failing every challenge left
        assert error.retryable and error.endpoint == "GET /api/v1/challenges" and error.added == ("warmup",)
        rsa, web = error.problems  # the problems met so far are kept, the one it stopped at included
        assert rsa.startswith('challenge 2 ("Baby RSA"): ') and web.startswith('challenge 3 ("Login Portal"): ')
        assert rsa in str(error) and web in str(error) and "HTTP 503" in error.reason
        assert "pull again to go on" in error.reason and "1 new challenge written" in error.reason
        assert load_ids(dest) == {"warmup": 1}
        fake.challenges[2].file_urls = None
        result = pulled(fake, dest)
    assert result.added == ("baby-rsa", "login-portal", "echo-service") and len(result.board.challenges) == 4


def test_a_token_refused_partway_stops_the_pull_at_once(tmp_path):
    with FakeCTFd(sample()) as fake:
        fake.script("GET", "/api/v1/challenges/2", Reply(401, {"message": "Your access token is invalid"}))
        with pytest.raises(PullStopped) as caught:
            pulled(fake, tmp_path / "board")
        assert len(fake.to("/api/v1/challenges")) == 1 and fake.to("/api/v1/challenges/3") == []
    assert caught.value.status == 401 and caught.value.added == ("warmup",) and "refused the API token" in str(caught.value)


def test_a_pull_into_a_folder_that_is_not_a_ctfd_board_is_refused(tmp_path):
    dest = tmp_path / "board"
    (dest / "notes").mkdir(parents=True)
    with FakeCTFd(sample()) as fake:
        error = failure(fake, lambda c: pull(c, dest, event="Fake CTF", flag_format=None))
        assert fake.requests == []
    assert "not empty" in str(error) and [p.name for p in dest.iterdir()] == ["notes"]  # left as it was


def test_a_pull_into_a_board_from_another_ctfd_is_refused(tmp_path):
    dest = tmp_path / "board"
    with FakeCTFd(sample()) as first, FakeCTFd(sample()) as second:
        pulled(first, dest)
        before = sorted(p.name for p in dest.iterdir())
        error = failure(second, lambda c: pull(c, dest, event="Other", flag_format=None))
        assert second.requests == []
    assert "was pulled from" in str(error) and first.base_url in str(error)
    assert sorted(p.name for p in dest.iterdir()) == before


def test_a_folder_a_pull_got_nothing_into_can_be_pulled_into_from_another_ctfd(tmp_path):
    dest = tmp_path / "board"
    with FakeCTFd([FakeChallenge(1, "Locked", type="hidden")]) as typo, FakeCTFd(sample()) as right:
        error = failure(typo, lambda c: pull(c, dest, event="Fake CTF", flag_format=None))
        assert "are locked until a prerequisite is solved" in str(error)
        assert len(pulled(right, dest).board.challenges) == 4


def test_an_empty_board_says_why(tmp_path):
    with FakeCTFd([]) as fake:
        error = failure(fake, lambda c: pull(c, tmp_path / "board", event="Fake CTF", flag_format=None))
    assert "lists no challenges for this account yet" in str(error)


def test_two_pulls_into_one_folder_never_run_at_once(tmp_path):
    dest = tmp_path / "board"
    dest.mkdir()
    holder = os.open(dest / ".ctfd-pull.lock", os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        with FakeCTFd(sample()) as fake:
            error = failure(fake, lambda c: pull(c, dest, event="Fake CTF", flag_format=None))
            assert fake.requests == []
    finally:
        os.close(holder)
    assert "another pull into this folder is running" in str(error)


def test_a_pull_leaves_only_the_board_in_dest(tmp_path):
    dest = tmp_path / "board"
    with FakeCTFd(sample() + [FakeChallenge(5, "Far", file_urls=["../../../../etc/x%2F..%2Fy"])]) as fake:
        result = pulled(fake, dest)
    assert sorted(p.name for p in dest.iterdir()) == [
        ".ctfd-pull.lock", "baby-rsa", "board.json", "ctfd.json", "echo-service", "login-portal", "warmup"]
    assert list(tmp_path.iterdir()) == [dest]  # nothing beside it
    assert "refuses to write it" in result.problems[0]


def test_pull_checks_its_arguments_before_any_request(tmp_path):
    with FakeCTFd(sample()) as fake:
        for event, flag_format in (("", None), ("Fake CTF", "(unclosed"), ("Fake CTF", "")):
            with pytest.raises(ValueError):
                call(fake, lambda c, e=event, f=flag_format: pull(c, tmp_path / "board", event=e, flag_format=f))
        (tmp_path / "file").write_text("x")
        assert "not a directory" in str(failure(fake, lambda c: pull(c, tmp_path / "file", event="E", flag_format=None)))
        assert fake.requests == []


def test_load_ids_refuses_a_mapping_that_makes_no_sense(tmp_path):
    for bad in ('{"url": "https://ctf.example.org"}', '{"url": "https://ctf.example.org", "ids": {"a": 1, "b": 1}}',
                '{"url": "https://ctf.example.org", "ids": {"../x": 1}}', '{"url": 1, "ids": {}}', "not json",
                '{"url": "https://ctf.example.org", "ids": {"a": true}}'):
        (tmp_path / STATE_FILE).write_text(bad)
        with pytest.raises(CTFdError) as caught:
            load_ids(tmp_path)
        assert STATE_FILE in str(caught.value)
    (tmp_path / STATE_FILE).unlink()
    with pytest.raises(CTFdError):
        load_ids(tmp_path)


# ---------------------------------------------------------------------- the deck's verifier


def test_the_verifier_answers_true_false_or_none_with_the_reason():
    with FakeCTFd(sample() + [FakeChallenge(7, "Two Parts", flag="test{both}", partial=("test{half}",))]) as fake:
        verify = CTFdVerifier(fake.base_url, TOKEN, {"warmup": 1, "baby-rsa": 2, "two-parts": 7})
        assert verify("warmup", "test{nope}") is False and verify.last_attempt.status == "incorrect"
        assert verify.last_error is None
        assert verify("warmup", "test{hello}") is True and verify.last_error is None
        assert verify("warmup", "test{hello}") is None and verify.last_attempt.status == "already_solved"
        assert verify("two-parts", "test{half}") is None and "only part of the answer" in verify.last_error
        fake.script("POST", "/api/v1/challenges/attempt",
                    Reply(429, {"success": True, "data": {"status": "ratelimited", "message": "Slow down."}}))
        assert verify("baby-rsa", "test{rsa}") is None and "rate-limited" in verify.last_error
        assert "Slow down." in verify.last_error
        fake.paused = True
        assert verify("baby-rsa", "test{rsa}") is None and "CTFd is paused" in verify.last_error
        asked = len(fake.requests)
        assert verify("not-pulled", "test{x}") is None and "was not pulled from CTFd" in verify.last_error
        assert len(fake.requests) == asked  # nothing sent for a challenge with no CTFd id
        verify.close()


def test_the_verifier_never_retries_and_keeps_the_reason():
    with FakeCTFd(sample()) as fake:
        fake.script("POST", "/api/v1/challenges/attempt", Reply(503, "down"), Reply(503, "down"))
        with CTFdVerifier(fake.base_url, TOKEN, {"warmup": 1}) as verify:
            assert verify("warmup", "test{hello}") is None
        assert len(fake.to("/api/v1/challenges/attempt")) == 1
    assert "HTTP 503" in verify.last_error and "may have reached CTFd" in verify.last_error
    assert TOKEN not in verify.last_error


def test_the_verifier_never_blocks_the_console_much_longer_than_its_timeout():
    # httpx's timeouts bound each read; a server that sends a byte now and then never trips them
    incorrect = {"success": True, "data": {"status": "incorrect", "message": "Incorrect"}}
    with FakeCTFd(sample()) as fake, CTFdVerifier(fake.base_url, TOKEN, {"warmup": 1}, timeout=1.0) as verify:
        for stalled in (Reply(200, incorrect, drip=0.2), Reply(200, incorrect, drip=0.2, drip_head=True)):
            fake.script("POST", "/api/v1/challenges/attempt", stalled)  # 14 s for the body; 30 s with the head
            started = time.monotonic()
            assert verify("warmup", "test{hello}") is None
            assert time.monotonic() - started < 2.5
            assert "no complete answer from CTFd" in verify.last_error and "within 1 s" in verify.last_error
            assert "may have reached CTFd" in verify.last_error and verify.last_attempt is None


def test_the_verifier_refuses_an_answer_too_big_to_be_ctfds():
    with FakeCTFd(sample()) as fake, CTFdVerifier(fake.base_url, TOKEN, {"warmup": 1}) as verify:
        fake.script("POST", "/api/v1/challenges/attempt", Reply(200, b"x" * 100_000))
        assert verify("warmup", "test{hello}") is None
    assert "more than 65,536 bytes" in verify.last_error and "may have reached CTFd" in verify.last_error


def test_the_verifier_with_ctfd_unreachable_says_the_flag_was_not_submitted():
    with CTFdVerifier(f"http://127.0.0.1:{closed_port()}", TOKEN, {"warmup": 1}) as verify:
        assert verify("warmup", "test{hello}") is None
    assert "no answer from CTFd" in verify.last_error and "the flag was not submitted" in verify.last_error


def test_the_verifier_works_on_a_running_event_loop():
    # the deck calls verify() synchronously on the console's loop: it must not need one of its own
    with FakeCTFd(sample()) as fake, CTFdVerifier(fake.base_url, TOKEN, {"warmup": 1}) as verify:
        async def on_the_loop() -> bool | None:
            return verify("warmup", "test{hello}")

        assert asyncio.run(on_the_loop()) is True


def test_the_verifier_refuses_ids_that_are_not_ctfd_ids():
    for bad in ({"warmup": "1"}, {"warmup": 0}, {"warmup": True}, {1: 1}):
        with pytest.raises(ValueError):
            CTFdVerifier("https://ctf.example.org", TOKEN, bad)


class Clock:
    def now(self) -> float:
        return 0.0


class Driver:
    """Does no work; records which flags the deck said were wrong."""

    def __init__(self) -> None:
        self.rejected_flags: list[str] = []

    def attach(self, deck): ...
    def start(self, lane, challenge): ...
    def pause(self, lane): ...
    def resume(self, lane): ...
    def hint(self, lane, text): ...
    def redirect(self, lane, text): ...
    def escalate(self, lane, model, summary): ...
    def approved(self, lane, pending): ...
    def declined(self, lane, pending): ...
    def stop(self, lane): ...

    def rejected(self, lane, flag):
        self.rejected_flags.append(flag)


def test_a_pulled_board_plays_on_the_deck_with_the_ctfd_verifier(tmp_path):
    with FakeCTFd(sample()) as fake:
        result = pulled(fake, tmp_path / "board")
        board = result.board
        with CTFdVerifier(fake.base_url, TOKEN, result.ids) as verify:
            driver = Driver()
            config = DeckConfig(event=board.event, flag_format=board.flag_format, models=("m",), submit="confirm")
            deck = Deck(config, driver, Clock(), verify=verify)
            deck.release([item.challenge for item in board.challenges],
                         [QueueEntry("baby-rsa", "m"), QueueEntry("warmup", "m")])
            (lane,) = deck.lanes_on("baby-rsa")
            deck.report(lane.id, TurnReport(action="guess", flag="test{wrong}"))
            deck.apply(iv.Approve(lane.id))
            assert driver.rejected_flags == ["test{wrong}"]
            deck.report(lane.id, TurnReport(action="solve", flag="test{rsa}"))
            assert deck.apply(iv.Approve(lane.id)).ok
            assert deck.challenges["baby-rsa"].status is ChallengeStatus.SOLVED and 2 in fake.solved
            (other,) = deck.lanes_on("warmup")
            fake.paused = True
            deck.report(other.id, TurnReport(action="solve", flag="test{hello}"))
            deck.apply(iv.Approve(other.id))
            assert other.pending.kind is PendingKind.CONFIRM  # CTFd did not judge it: the player confirms
            assert "CTFd is paused" in verify.last_error
    sent = [r.json for r in fake.to("/api/v1/challenges/attempt")]
    assert sent == [{"challenge_id": 2, "submission": "test{wrong}"}, {"challenge_id": 2, "submission": "test{rsa}"},
                    {"challenge_id": 1, "submission": "test{hello}"}]


def one_lane_deck(verify, challenge: Challenge, driver: Driver, **config) -> tuple[Deck, object]:
    """A deck with one lane on `challenge`, submitting through `verify` after the player approves."""
    config.setdefault("submit", "confirm")
    deck = Deck(DeckConfig(event="Fake CTF", flag_format=FLAG_FORMAT, models=("m",), **config), driver, Clock(),
                verify=verify)
    deck.release([challenge], [QueueEntry(challenge.id, "m")])
    (lane,) = deck.lanes_on(challenge.id)
    return deck, lane


def test_a_flag_ctfd_did_not_check_for_want_of_tries_is_not_remembered_as_wrong():
    # Out of tries, CTFd answers {"status": "incorrect"} with HTTP 403 before it looks at the flag.
    with FakeCTFd([FakeChallenge(1, "One Try", category="Crypto", flag="test{right}", max_attempts=1)]) as fake:
        with CTFdVerifier(fake.base_url, TOKEN, {"one-try": 1}) as verify:
            assert verify("one-try", "test{wrong}") is False  # the last real try: CTFd checked it
            assert verify.last_attempt == Attempt("incorrect", "Incorrect. You have 0 tries remaining.")
            driver = Driver()
            deck, lane = one_lane_deck(verify, Challenge(id="one-try", name="One Try", category="cry", points=100), driver)
            deck.report(lane.id, TurnReport(action="solve", flag="test{right}"))
            deck.apply(iv.Approve(lane.id))
            assert verify.last_attempt == Attempt("locked_out", "You have 0 tries remaining")
            assert "did not check the flag" in verify.last_error and "no tries left" in verify.last_error
            assert "You have 0 tries remaining" in verify.last_error
            assert lane.pending is not None and lane.pending.kind is PendingKind.CONFIRM  # the player says how it went
            assert deck.not_flag("one-try", "test{right}") is None and driver.rejected_flags == []
            assert deck.summary(lane).not_flags == ()
        assert len(fake.to("/api/v1/challenges/attempt")) == 2


def test_a_flag_for_a_challenge_already_solved_on_ctfd_is_not_counted_correct():
    # CTFd answers already_solved as soon as the account (the team) has a solve, without checking the flag
    with FakeCTFd(sample()) as fake:
        fake.solved = {2}  # a teammate solved Baby RSA, whose flag is test{rsa}
        with CTFdVerifier(fake.base_url, TOKEN, {"baby-rsa": 2}) as verify:
            events = []
            deck, lane = one_lane_deck(verify, Challenge(id="baby-rsa", name="Baby RSA", category="cry", points=100),
                                       Driver(), team=True)
            deck.subscribe(events.append)
            deck.report(lane.id, TurnReport(action="solve", flag="test{a_wrong_guess}"))
            deck.apply(iv.Approve(lane.id))
            assert verify.last_attempt == Attempt("already_solved", "You already solved this")
            assert "already solved" in verify.last_error and "did not check this flag" in verify.last_error
            assert deck.challenges["baby-rsa"].status is not ChallengeStatus.SOLVED
            assert lane.pending is not None and lane.pending.kind is PendingKind.CONFIRM
            assert [e for e in events if e.kind is EventKind.SUBMIT] == []  # no flag recorded as the solution
