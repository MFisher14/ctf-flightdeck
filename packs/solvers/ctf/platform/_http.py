"""Small HTTP helpers shared by the CTFd and Game Master adapters (not an adapter kind).

The adapters talk through a requests.Session-like object and only ever call
session.request(method, url, params=..., json=..., headers=..., timeout=..., stream=...), so a test
can hand them a recorded-fixture session instead of the network.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .base import PlatformError

_CTRL = re.compile(r"[\x00-\x20\x7f]")


def origin(url: str) -> tuple[str, str]:
    p = urlsplit(url)
    return p.scheme.lower(), p.netloc.lower()


def json_body(resp: Any, call: str) -> Any:
    try:
        return resp.json()
    except ValueError:
        raise PlatformError(f"{call}: HTTP {resp.status_code} with a non-JSON body "
                            "(not logged in, or a gateway error?)") from None


def retry_after(resp: Any) -> float | None:
    raw = (getattr(resp, "headers", None) or {}).get("Retry-After")
    try:
        return float(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None   # an HTTP-date: the caller backs off on its own pacing


def safe_filename(name: str | None, default: str = "file.bin") -> str:
    """The last path component of a server-given name, URL-decoded, never empty, '.' or '..'."""
    base = unquote(str(name or "")).replace("\\", "/").split("?", 1)[0].rstrip("/").split("/")[-1]
    base = base.strip()
    if base in ("", ".", "..") or "\x00" in base:
        return default
    return base


def unique_path(dest: Path, name: str) -> Path:
    out = dest / name
    n = 1
    while out.exists():
        stem, dot, ext = name.partition(".")
        out = dest / (f"{stem}-{n}{dot}{ext}")
        n += 1
    return out


def write_body(resp: Any, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".part")
    with open(tmp, "wb") as fh:
        for chunk in resp.iter_content(65536):
            if chunk:
                fh.write(chunk)
    tmp.replace(out)


def check_secret(value: str, name: str) -> str:
    """A credential read from the environment, stripped; a value with a space, line break or control
    character is refused without echoing it (requests would quote it in its own error)."""
    v = value.strip()
    if _CTRL.search(v):
        raise PlatformError(f"{name} holds a space, line break or control character; it must hold the "
                            "value only, on one line (the value is not shown)")
    return v
