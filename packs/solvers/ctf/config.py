"""Connection and event settings for CSCTF 2026.

Nothing secret is committed. Settings come from, in order of precedence:

  1. environment variables (CTF_PLATFORM_URL, CTF_TOKEN, CTF_COOKIE, CTF_TEAM_ID), read through ctf.env
     (which still honours the legacy CSCTF_* spellings with a DeprecationWarning)
  2. a local, git-ignored JSON file at .ctf/config.json  (see .ctf/config.example.json)
  3. the defaults below

The flag format and the working folder are NOT settings here: the flag format is the active event
profile's (ctf.flagfmt, events/<slug>/event.toml) and the working folder is ctf.paths.workdir().
The retired overrides ($CTF_FLAG_FORMAT/$CSCTF_FLAG_FORMAT, config.json "flag_format"/"workdir") are
refused loudly instead of being ignored.

The API token is read from $CTF_TOKEN or .ctf/token (a git-ignored file holding just the token).
Create a CTFd access token in the web UI under Settings -> Access Tokens once the event opens, then:

    echo 'ctfd_xxxxxxxx' > .ctf/token      # or: export CTF_TOKEN=ctfd_xxxxxxxx
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from . import env, flagfmt, paths

REPO = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO / ".ctf"
CONFIG_JSON = CONFIG_DIR / "config.json"
TOKEN_FILE = CONFIG_DIR / "token"

# CSCTF 2026 facts (https://2026.ctf-platform.example). Override via .ctf/config.json if any change.
DEFAULT_URL = "https://2026.ctf-platform.example"

# The flag format is the event profile's (ctf.flagfmt). IMPORTANT EXCEPTION: OSINT challenges take a
# freeform answer in a template defined by the brief (e.g. "lat,long to 4 decimals, no spaces"), which
# does NOT look like a flag — submit those with guarded_submit(..., allow_nonstandard=True). Never
# reshape a rejected flag; re-derive from the bytes.
RETIRED_KEYS = {"flag_format": "the flag format is the event profile's [flag] table (events/<slug>/event.toml)",
                "workdir": "the working folder is $CTF_WORKDIR, else ~/ctf-work/<event> (ctf.paths.workdir())"}


class ConfigError(RuntimeError):
    """A retired or invalid setting; the message names it and where its replacement lives."""


def _load_file() -> dict:
    try:
        return json.loads(CONFIG_JSON.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


COOKIE_FILE = CONFIG_DIR / "cookie"


def _read_token() -> str | None:
    tok = env.get("CTF_TOKEN")
    if tok:
        return tok.strip()
    try:
        tok = TOKEN_FILE.read_text(encoding="utf-8").strip()
        return tok or None
    except OSError:
        return None


def _read_cookie() -> str | None:
    """Fallback auth when the CTFd Access-Tokens UI is disabled: the value of the `session` cookie from a
    logged-in browser. Put it in $CTF_COOKIE or .ctf/cookie (git-ignored). The token is preferred —
    it needs no CSRF handling — but the cookie keeps us unblocked on race day if tokens aren't offered."""
    ck = env.get("CTF_COOKIE")
    if ck:
        return ck.strip()
    try:
        ck = COOKIE_FILE.read_text(encoding="utf-8").strip()
        return ck or None
    except OSError:
        return None


@dataclass
class Config:
    base_url: str
    token: str | None
    team_id: int | None
    workdir: Path
    cookie: str | None = None
    # The flag format the guard checks: None = the active event's (ctf.flagfmt.current()). A test or a
    # one-off tool may pin a FlagFormat built by ctf.flagfmt; nothing builds a regex here.
    flags: flagfmt.FlagFormat | None = None
    # Submission guard knobs (CSCTF rules: no brute-forcing or submission flooding).
    submit_interval_min_s: float = 3.0   # minimum seconds between two flag submissions
    submit_wrong_limit: int = 3            # wrong answers on ONE challenge before we stop and ask
    request_timeout_s: float = 20.0
    user_agent: str = "csctf-2026-solver"

    @property
    def flag_format(self) -> flagfmt.FlagFormat:
        return self.flags if self.flags is not None else flagfmt.current()

    def looks_like_flag(self, text: str) -> bool:
        """The whole (stripped) candidate is one flag in the event format."""
        return bool(text) and self.flag_format.is_flag(text)

    def require_auth(self) -> None:
        if not self.token and not self.cookie:
            raise SystemExit(
                "No CSCTF auth. Either create a CTFd access token (your profile -> Settings -> Access "
                "Tokens) into .ctf/token / $CTF_TOKEN, or, if that UI is disabled, put your logged-in "
                "`session` cookie value into .ctf/cookie / $CTF_COOKIE. See ctf/config.py."
            )

    # Backwards-compatible alias.
    def require_token(self) -> str:
        self.require_auth()
        return self.token or ""

    def redacted(self) -> dict:
        return {
            "base_url": self.base_url,
            "auth": ("token" if self.token else ("cookie" if self.cookie else None)),
            "flag_format": self.flag_format.pattern,
            "team_id": self.team_id,
            "workdir": str(self.workdir),
        }


def load() -> Config:
    f = _load_file()
    if env.get("CTF_FLAG_FORMAT"):
        raise ConfigError("CTF_FLAG_FORMAT (or CSCTF_FLAG_FORMAT) is retired: " + RETIRED_KEYS["flag_format"])
    for key, why in RETIRED_KEYS.items():
        if key in f:
            raise ConfigError(f"{CONFIG_JSON}: key {key!r} is retired: {why}")
    base_url = env.get("CTF_PLATFORM_URL") or f.get("base_url") or DEFAULT_URL
    team_env = env.get("CTF_TEAM_ID") or f.get("team_id")
    team_id = int(team_env) if team_env not in (None, "") else None
    cfg = Config(
        base_url=base_url.rstrip("/"),
        token=_read_token(),
        team_id=team_id,
        workdir=paths.workdir(),
        cookie=_read_cookie(),
    )
    for k in ("submit_interval_min_s", "submit_wrong_limit", "request_timeout_s", "user_agent"):
        if k in f:
            setattr(cfg, k, f[k])
    return cfg


if __name__ == "__main__":
    import pprint
    pprint.pp(load().redacted())
