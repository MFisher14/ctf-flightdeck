#!/usr/bin/env python3
"""Player-gated live upload loop for an RFID card validator (B-084).

Forging, decrypting and identifying a card's CRC are offline and live in ``rfid_nfc_depth`` -- they
need no network.  This module is the *only* networked step of the Ultralight C workflow: uploading a
forged card to the challenge's card-validation endpoint and reading back the server's error strings
(which is how a validator's "which byte means admin" and CRC definition are learned -- a few reasoned
uploads, never a flood).  It is deliberately fenced:

  * every request goes through ``solvers.toolkits.web.WebClient``, which is locked to the squad's one
    assigned in-scope target (``ctf.scope``) and can never reach the platform or any other host; any
    other client object (a ``requests.Session``, a raw opener) is refused before the first send, and
    so is a ``WebClient`` subclass or instance that replaces any method on the upload path
    (``post``, ``request``, ``_resolve_url``, ``_in_scope``, ``_check_private``);
  * it refuses to send unless the *active* event profile -- the one ``ctf.scope`` pinned, else
    ``ctf.event.current()``, exactly as ``solvers/web/flow_recorder.py`` reads it -- sets
    ``rules.web_state_changing = true`` (uploading a forged card mutates server-side state). A caller
    cannot pass its own profile. With no profile loaded it fails closed with a named reason;
  * it also needs ``approved=True`` -- the player's explicit go-ahead for this specific probe against
    the assigned instance. Known limitation: this is a caller-set flag, not a recorded approval (no
    shared player-approval record for live writes exists yet);
  * the number of uploads is capped and the loop is paced.

The caller constructs the ``WebClient`` (so the one assigned target URL is never guessed here) and
passes it in.  Nothing in this module starts a session, reads a token, or contacts a scoreboard.
"""
from __future__ import annotations

import json
import sys
import time
import uuid as _uuid
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from ctf import event as _event, scope as _scope  # noqa: E402


class ProbeRefused(RuntimeError):
    """A guard (web_state_changing, player approval, or the upload cap) blocked the probe."""


def build_multipart(fields: dict[str, str] | None,
                    files: Sequence[tuple[str, str, str, bytes]] | None,
                    *, boundary: str | None = None) -> tuple[bytes, str]:
    """Encode a ``multipart/form-data`` body.

    ``fields`` is ``{name: value}``; ``files`` is ``[(name, filename, content_type, bytes), ...]``.
    Returns ``(body, content_type_header)``.
    """
    boundary = boundary or ("----rfidprobe" + _uuid.uuid4().hex)
    marker = boundary.encode("ascii")
    crlf = b"\r\n"
    parts: list[bytes] = []
    for name, value in (fields or {}).items():
        parts += [b"--", marker, crlf,
                  f'Content-Disposition: form-data; name="{name}"'.encode("utf-8"), crlf, crlf,
                  str(value).encode("utf-8"), crlf]
    for name, filename, content_type, content in files or []:
        parts += [b"--", marker, crlf,
                  f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode("utf-8"), crlf,
                  f"Content-Type: {content_type}".encode("ascii"), crlf, crlf,
                  bytes(content), crlf]
    parts += [b"--", marker, b"--", crlf]
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _active_profile() -> Any:
    """The event profile in force: the one ``ctf.scope`` pinned, else ``ctf.event.current()``. Fails
    closed with a named reason when none can be loaded."""
    prof = _scope.pinned()
    if prof is not None:
        return prof
    try:
        return _event.current()
    except Exception as exc:
        raise ProbeRefused(
            f"no event profile loaded ({type(exc).__name__}: {exc}); a live card upload is a "
            "state-changing web action and is refused without one") from exc


def _webclient_classes() -> tuple[type, ...]:
    """The scope-locked ``WebClient`` class of this checkout's ``solvers/toolkits/web.py``, under every
    module name it is loaded as (flat ``web`` on the engine path, or ``solvers.toolkits.web``)."""
    source = (_HERE / "web.py").resolve()

    def _ours(module: Any) -> bool:
        path = getattr(module, "__file__", None)
        return bool(path) and Path(path).resolve() == source

    classes = [module.WebClient for name, module in list(sys.modules.items())
               if name in ("web", "solvers.toolkits.web") and _ours(module)
               and isinstance(getattr(module, "WebClient", None), type)]
    if not classes:
        try:
            from solvers.toolkits import web as _web  # type: ignore
        except ImportError as exc:
            raise ProbeRefused(f"cannot load the scope-locked web toolkit (solvers/toolkits/web.py): {exc}") from exc
        classes.append(_web.WebClient)
    return tuple(classes)


# The WebClient methods a card upload runs through: post -> request -> _resolve_url / _in_scope
# (the scope lock) and _check_private. A subclass or instance that replaces any of them could send the
# card somewhere other than the scope-locked target, so such a client is refused.
_TRANSPORT_METHODS = ("post", "request", "_resolve_url", "_in_scope", "_check_private")


def _check_client(client: Any) -> None:
    classes = _webclient_classes()
    if not isinstance(client, classes):
        raise ProbeRefused(
            f"client {type(client).__name__!r} is not a solvers.toolkits.web.WebClient: a live card "
            "upload goes only through the scope-locked WebClient built for the one assigned instance")
    base = next(cls for cls in classes if isinstance(client, cls))
    instance_attrs = getattr(client, "__dict__", {})
    for name in _TRANSPORT_METHODS:
        if name in instance_attrs or getattr(type(client), name, None) is not getattr(base, name):
            raise ProbeRefused(
                f"client {type(client).__name__!r} overrides WebClient.{name}: a live card upload goes "
                "only through the unmodified scope-locked WebClient transport")


def _check_gates(approved: bool) -> None:
    profile = _active_profile()
    rules = getattr(profile, "rules", None)
    if not bool(getattr(rules, "web_state_changing", False)):
        slug = getattr(profile, "slug", "?")
        raise ProbeRefused(
            f"event {slug!r} sets rules.web_state_changing=false: uploading a forged card is a "
            "state-changing web action and is refused (BUILD-PLAN O-2). Set it true in the event "
            "profile only once the player has authorised live writes to the assigned instance.")
    if approved is not True:
        raise ProbeRefused(
            "a live card upload needs the player's explicit approval; pass approved=True only after "
            "the player has authorised this probe against the assigned instance.")


def _interpret(response: dict[str, Any]) -> dict[str, Any]:
    body = response.get("body") or b""
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
    out: dict[str, Any] = {"status": response.get("status"), "body_text": text[:4096]}
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict):
        out["json"] = data
        for key in ("ok", "error", "message", "flag"):
            if key in data:
                out[key] = data[key]
        out["accepted"] = bool(data.get("ok")) or bool(data.get("flag"))
    else:
        out["accepted"] = False
    return out


def probe_validator(client: Any, path: str, cards: Iterable[bytes], *,
                    approved: bool = False, field: str = "card", filename: str = "card.bin",
                    content_type: str = "application/octet-stream", min_interval: float = 1.0,
                    max_uploads: int = 16, extra_fields: dict[str, str] | None = None,
                    stop_on_accept: bool = True,
                    clock: Callable[[], float] = time.monotonic,
                    sleep: Callable[[float], None] = time.sleep) -> list[dict[str, Any]]:
    """Upload each forged card to ``path`` on ``client`` and return the parsed responses.

    Refuses unless ``client`` is a ``web.WebClient``, the active event profile sets
    ``rules.web_state_changing`` true, and ``approved`` is True.  Uploads
    are capped at ``max_uploads`` and paced to at least ``min_interval`` seconds apart (``clock`` and
    ``sleep`` are injectable so a test can drive and observe the pacing without real waits).  Stops
    early on the first accepted/flagged response when ``stop_on_accept`` is set.
    """
    _check_gates(approved)
    _check_client(client)
    cards = list(cards)
    if not cards:
        raise ProbeRefused("no cards to upload")
    if len(cards) > max_uploads:
        raise ProbeRefused(
            f"{len(cards)} uploads exceeds the max_uploads cap of {max_uploads}; a validator probe "
            "is a few reasoned uploads, not a flood")
    results: list[dict[str, Any]] = []
    last: float | None = None
    for index, card in enumerate(cards):
        if last is not None:
            wait = min_interval - (clock() - last)
            if wait > 0:
                sleep(wait)
        last = clock()
        body, ctype = build_multipart(extra_fields, [(field, filename, content_type, bytes(card))])
        response = client.post(path, data=body, headers={"Content-Type": ctype})
        parsed = _interpret(response)
        parsed["index"] = index
        results.append(parsed)
        if stop_on_accept and parsed.get("accepted"):
            break
    return results
