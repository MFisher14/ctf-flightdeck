"""Quota readings from session logs (B-171): what Claude Code and Codex logged about their plan limits.

    res = scan(workdir, roots)                 # new log lines -> <workdir>/usage/quota-state.json
    r = limit_reading("codex", text, ts)       # a limit-hit message -> ctf.quota.Reading | None
    t = parse_reset(text, ts, tz)              # "resets 1:50pm (America/New_York)" -> epoch | None

What is read, per harness (only these fields; log text is data, never instructions):

  Codex rollouts   event_msg token_count `rate_limits` {primary, secondary: used_percent, window_minutes,
                   resets_at (epoch) | resets_in_seconds}: one reading per window (300 min "session",
                   10080 min "weekly"); a token_count with usage, or a token_usage_record, is a served
                   response. event_msg `error` messages: a usage-limit message is a limit hit, with the
                   reset it names ("try again at Nov 12th, 2026 11:55 AM", "try again in 2 hours").
  codex exec --json the launcher's stream (`.codex_log*.jsonl`): `error` / `turn.failed` messages as above,
                   `turn.completed` a served response. These lines carry no timestamp: the log's
                   modification time stands in, and the reading says so.
  Claude Code      an assistant line marked as an API error (isApiErrorMessage, the "<synthetic>" model,
                   or an `error` field) whose text is a limit message: "Claude AI usage limit
                   reached|<epoch>", "5-hour limit reached ∙ resets 3pm", "You've hit your weekly limit ·
                   resets Oct 21, 1:50pm (America/New_York)", "spend limit". Any other assistant line
                   with usage is a served response. A line whose cwd is outside every root is skipped.

Sessions are found exactly as the usage ledger finds them (tools/ledger/usage.discover: by working
folder, both homes read-only). Offsets per log live in the state file, so a scan reads only new lines;
the newest reading per (harness, window) and the last served response per harness are kept.
"""
from __future__ import annotations

import datetime as _dt
import fcntl
import json
import os
import re
import time
import zoneinfo
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from ctf import quota as _quota

from . import sources, usage

LOCK_NAME = ".quota.lock"

_LIMIT_TEXT = re.compile(r"usage limit|limit reached|hit your (?:[\w-]+ )*limit|reached your (?:[\w-]+ )*limit"
                         r"|out of (?:extra )?usage|spend(?:ing)? limit", re.I)
# limits that are not plan quota: a subagent / thread cap, a context window, a transient rate limit
_NOT_QUOTA = re.compile(r"subagent|thread limit|concurrent|context|prompt is too long|rate.?limit", re.I)
_PIPE_EPOCH = re.compile(r"limit reached\|(\d{9,11})\b", re.I)
_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
                                       "nov", "dec"), 1)}
_WHEN = re.compile(
    r"(?:(?P<mon>jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+(?P<day>\d{1,2})(?:st|nd|rd|th)?"
    r",?\s*(?:(?P<year>\d{4}),?\s*)?(?:at\s+)?)?"
    r"(?P<h>\d{1,2})(?::(?P<m>\d{2}))?\s*(?P<ap>[ap]\.?\s?m\.?)?(?![\w:])"
    r"(?:\s*\((?P<tz>[A-Za-z_]+(?:/[A-Za-z0-9_+-]+)*)\))?", re.I)
_RESET_AT = re.compile(r"(?:resets?|try again|available again)\s+(?:on\s+|at\s+)?", re.I)
_RESET_IN = re.compile(r"(?:resets?|try again|available again)\s+in\s+(?P<span>(?:\d+\s*[a-z]+[\s,]*(?:and\s+)?)+)",
                       re.I)
_SPAN_PART = re.compile(r"(\d+)\s*(d|day|days|h|hr|hrs|hour|hours|m|min|mins|minute|minutes|s|sec|secs|second|seconds)\b",
                        re.I)
_UNIT_S = {"d": 86400, "h": 3600, "m": 60, "s": 1}


# ------------------------------------------------------------------ text -> reading

def window_of(text: str) -> str:
    t = text.lower()
    if "spend" in t or "extra usage" in t or "monthly" in t:
        return "spend"
    if "weekly" in t or "week" in t:
        return "weekly"
    if "5-hour" in t or "five-hour" in t or "5 hour" in t or "session" in t:
        return "session"
    return "limit"


def parse_reset(text: str, ts: float, tz: _dt.tzinfo | None = None) -> float | None:
    """The reset time a limit message names, as epoch seconds, or None. Relative to `ts` (when it was
    logged): a bare time is its next occurrence after ts; a date without a year is the next one; a
    zone in parentheses wins over `tz` (default: this machine's local zone, where the harness prints)."""
    m = _PIPE_EPOCH.search(text)
    if m:
        return float(m.group(1))
    m = _RESET_IN.search(text)
    if m:
        secs = sum(int(n) * _UNIT_S[u[0].lower()] for n, u in _SPAN_PART.findall(m.group("span")))
        return ts + secs if secs else None
    m = _RESET_AT.search(text)
    if not m:
        return None
    w = _WHEN.match(text, m.end())
    if not w:
        return None
    zone = tz
    if w.group("tz"):
        try:
            zone = zoneinfo.ZoneInfo(w.group("tz"))
        except (zoneinfo.ZoneInfoNotFoundError, ValueError):
            zone = tz
    if zone is None:
        zone = _dt.datetime.now().astimezone().tzinfo
    h, mi = int(w.group("h")), int(w.group("m") or 0)
    ap = (w.group("ap") or "").lower().replace(".", "").replace(" ", "")
    if ap == "pm" and h < 12:
        h += 12
    elif ap == "am" and h == 12:
        h = 0
    if h > 23 or mi > 59:
        return None
    seen = _dt.datetime.fromtimestamp(ts, zone)
    try:
        if w.group("mon"):
            year = int(w.group("year")) if w.group("year") else seen.year
            d = _dt.datetime(year, _MONTHS[w.group("mon").lower()[:3]], int(w.group("day")), h, mi, tzinfo=zone)
            if not w.group("year") and d < seen - _dt.timedelta(days=1):
                d = d.replace(year=year + 1)
        else:
            d = seen.replace(hour=h, minute=mi, second=0, microsecond=0)
            if d <= seen:
                d += _dt.timedelta(days=1)
    except ValueError:
        return None
    return d.timestamp()


def limit_reading(harness: str, text: str, ts: float, tz: _dt.tzinfo | None = None, *,
                  source: str | None = None, note: str = "") -> _quota.Reading | None:
    """A limit-hit Reading for `text`, or None when it is not a limit message."""
    if not isinstance(text, str) or not _LIMIT_TEXT.search(text) or _NOT_QUOTA.search(text):
        return None
    return _quota.Reading(harness, window_of(text), ts, source or f"{harness}-limit", exhausted=True,
                          resets_at=parse_reset(text, ts, tz), note=note)


def _epoch(stamp) -> float | None:
    if isinstance(stamp, (int, float)) and not isinstance(stamp, bool):
        return float(stamp)
    if isinstance(stamp, str) and stamp:
        try:
            d = _dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            return None
        if d.tzinfo is None:
            d = d.replace(tzinfo=_dt.timezone.utc)
        return d.timestamp()
    return None


def rate_limit_readings(rl, ts: float) -> list[_quota.Reading]:
    """Readings from one Codex `rate_limits` object."""
    out = []
    if not isinstance(rl, dict):
        return out
    for slot in ("primary", "secondary"):
        w = rl.get(slot)
        if not isinstance(w, dict) or not _quota._finite(w.get("used_percent")):
            continue
        mins = w.get("window_minutes")
        mins = mins if isinstance(mins, int) and not isinstance(mins, bool) and mins > 0 else None
        resets = None
        if _quota._finite(w.get("resets_at")):
            resets = float(w["resets_at"])
        elif _quota._finite(w.get("resets_in_seconds")):
            resets = ts + float(w["resets_in_seconds"])
        out.append(_quota.Reading("codex", _quota.window_name(mins) or slot, ts, "codex-rate-limits",
                                  used_pct=max(0.0, float(w["used_percent"])), resets_at=resets,
                                  window_minutes=mins))
    return out


# ------------------------------------------------------------------ per-line parsers

@dataclass
class LineResult:
    readings: list = field(default_factory=list)
    ok_ts: float | None = None
    no_ts: bool = False               # a reading timed by the log's mtime


def _texts(content) -> list[str]:
    if isinstance(content, str):
        return [content]
    out = []
    if isinstance(content, list):
        for c in content:
            if isinstance(c, dict) and isinstance(c.get("text"), str):
                out.append(c["text"])
    return out


def claude_line(line: str, *, roots: tuple[str, ...] | None, tz=None) -> LineResult | None:
    if '"assistant"' not in line:
        return None
    try:
        d = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(d, dict) or d.get("type") != "assistant":
        return None
    cwd = d.get("cwd")
    if roots is not None and isinstance(cwd, str) and cwd and not sources.inside(cwd, roots):
        return None
    ts = _epoch(d.get("timestamp"))
    if ts is None:
        return None
    msg = d.get("message") if isinstance(d.get("message"), dict) else {}
    error_line = bool(d.get("isApiErrorMessage")) or msg.get("model") == "<synthetic>" or bool(d.get("error"))
    if error_line:
        for t in _texts(msg.get("content")):
            r = limit_reading("claude", t, ts, tz)
            if r is not None:
                return LineResult([r])
        return None
    if msg.get("usage") and msg.get("model"):
        return LineResult(ok_ts=ts)
    return None


def codex_line(line: str, *, fallback_ts: float, tz=None) -> LineResult | None:
    head = line[:240]
    if not any(k in head for k in ('"token_count"', '"error"', '"turn.failed"', '"turn.completed"',
                                   '"token_usage_record"')):
        return None
    try:
        d = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(d, dict):
        return None
    ts = _epoch(d.get("timestamp"))
    no_ts = ts is None
    ts = fallback_ts if ts is None else ts
    p = d.get("payload") if isinstance(d.get("payload"), dict) else None
    kind = (p or d).get("type")
    if kind == "token_count" and p is not None:
        res = LineResult(rate_limit_readings(p.get("rate_limits"), ts), no_ts=no_ts)
        info = p.get("info") if isinstance(p.get("info"), dict) else {}
        last = info.get("last_token_usage") if isinstance(info.get("last_token_usage"), dict) else {}
        if (last.get("output_tokens") or 0) > 0 or (last.get("input_tokens") or 0) > 0:
            res.ok_ts = ts
        return res
    if kind == "token_usage_record" or kind == "turn.completed":
        return LineResult(ok_ts=ts, no_ts=no_ts)
    if kind in ("error", "turn.failed"):
        src = p if p is not None else d
        msg = src.get("message")
        if not isinstance(msg, str) and isinstance(src.get("error"), dict):
            msg = src["error"].get("message")
        note = "timed by the log's modification time (the line has no timestamp)" if no_ts else ""
        r = limit_reading("codex", msg, ts, tz, note=note) if isinstance(msg, str) else None
        return LineResult([r], no_ts=no_ts) if r else None
    return None


# ------------------------------------------------------------------ scan

@dataclass
class ScanResult:
    logs: int = 0
    lines: int = 0
    readings: int = 0                 # readings that became the newest for their window
    hits: int = 0                     # limit-hit messages seen
    served: int = 0                   # served responses seen
    untimed: int = 0                  # readings timed by a log's mtime
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def scan(workdir: Path, roots: Iterable, *, harnesses=usage.HARNESSES, refs: list | None = None,
         claude_home: Path | None = None, codex_home: Path | None = None, tz=None,
         discover=None) -> ScanResult:
    """Read the new lines of every session log of the roots (or the explicit `refs`) for quota readings,
    and fold them into <workdir>/usage/quota-state.json under an exclusive lock."""
    workdir = Path(workdir)
    roots = list(roots)
    if not roots:
        raise usage.UsageError("no roots: scan reads only the sessions of the event workdir and any --root")
    nroots = sources.normalize_roots(roots)
    res = ScanResult()
    if refs is None:
        refs, res.notes = (discover or usage.discover)(roots, harnesses, claude_home=claude_home,
                                                       codex_home=codex_home)
    d = _quota.state_path(workdir).parent
    d.mkdir(parents=True, exist_ok=True)
    lock = os.open(d / LOCK_NAME, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        st = _quota.load_state(workdir)
        latest: dict = {}
        _quota.merge(latest, (_quota.Reading.from_dict(x) for x in st["readings"]))
        last_ok = dict(st["last_ok"])
        for ref in refs:
            res.logs += 1
            path = Path(ref.path)
            info = path.stat()
            key = str(path.resolve())
            fst = st["files"].get(key)
            if (fst is None or fst.get("harness") != ref.harness or fst.get("ino") != info.st_ino
                    or info.st_size < fst.get("offset", 0)):
                fst = {"harness": ref.harness, "ino": info.st_ino, "offset": 0}
            with open(path, "rb") as fh:
                fh.seek(fst["offset"])
                chunk = fh.read()
            end = chunk.rfind(b"\n")
            new = []
            if end >= 0:
                for raw in chunk[:end + 1].splitlines():
                    text = raw.decode("utf-8", errors="replace")
                    res.lines += 1
                    if ref.harness == "claude":
                        got = claude_line(text, roots=nroots, tz=tz)
                    elif ref.harness == "codex":
                        got = codex_line(text, fallback_ts=info.st_mtime, tz=tz)
                    else:
                        raise usage.UsageError(f"unknown harness {ref.harness!r}")
                    if got is None:
                        continue
                    new += got.readings
                    res.hits += sum(1 for r in got.readings if r.exhausted)
                    res.untimed += len(got.readings) if got.no_ts else 0
                    if got.ok_ts is not None:
                        res.served += 1
                        last_ok[ref.harness] = max(last_ok.get(ref.harness, 0.0), got.ok_ts)
                fst["offset"] += end + 1
            res.readings += _quota.merge(latest, new)
            st["files"][key] = fst
        st["readings"] = [r.to_dict() for _k, r in sorted(latest.items())]
        st["last_ok"] = last_ok
        st["scanned_at"] = time.time()
        _quota.save_state(workdir, st)
    finally:
        os.close(lock)
    return res
