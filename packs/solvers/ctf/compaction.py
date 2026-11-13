"""Compaction thresholds (B-032): compact Claude agents at 200K tokens of context, Codex at 150K.

    from ctf import compaction
    compaction.threshold("claude")            # 200000, or None when CTF_COMPACT_CLAUDE=off
    compaction.claude_env()                   # {"CLAUDE_CODE_AUTO_COMPACT_WINDOW": "200000"}
    compaction.claude_settings()              # {"autoCompactWindow": 200000}
    compaction.codex_config_args()            # ["-c", "model_auto_compact_token_limit=150000"]
    compaction.audit(path)                    # Audit: where a session's context went, where it compacted
    compaction.check(path)                    # Reading: the latest context against the threshold

Why (analysis tokens/EFFICIENCY-PLAN.md section 3.5): Claude main threads averaged 400K to 440K of
context and peaked near 1M, so every response re-read a huge cached prefix; Claude compacted 29 times
in the whole dataset against 2,459 for Codex. Simulated per file, Claude at 200K and Codex at 150K were
the best net thresholds (below 200K on Claude the extra compactions eat the saving).

How each harness gets its threshold (both names were confirmed in the installed builds: Claude Code
2.1.322 and Codex 0.167.0):

  Claude Code  CLAUDE_CODE_AUTO_COMPACT_WINDOW=<tokens> in the agent's environment (tools/claude_launch,
               tools/pink_launch.sh), or the `autoCompactWindow` setting (pink_launch also passes it as
               --settings JSON). Claude Code compacts when context approaches that window: at the window
               minus its summary buffer, so a little under the threshold. It accepts 100000..1000000.
               Subagents inherit the window. The environment variable beats every settings file.
  Codex        `-c model_auto_compact_token_limit=<tokens>` on every codex command the repo builds
               (ctf.fence_launch.codex_argv, tools/codex_handoff.sh). A `-c` beats ~/.codex/config.toml.

Sessions started by hand (the player's own `claude`, a "ready" Codex agent a brief is pasted into)
do not pass through a launcher: `ctf preflight` warns until the threshold is in the player's shell
or config (the fix line it prints is the human step).

Overrides: CTF_COMPACT_CLAUDE and CTF_COMPACT_CODEX take a token count ("200000", "200k", "1m") or
"off" (leave the harness default alone). An unusable value raises CompactionError; it never falls
back to a default.

Measuring (the rehearsal test the spec asks for before live hard-tail solves): `audit()` reads one
session log (a Claude Code transcript JSONL or a Codex rollout JSONL) and reports per response the
context the model read (Claude: input + cache writes + cache reads; Codex: input_tokens, which
includes cached), the peak, the responses above the threshold, and every compaction with the
context it fired at. `check()` is the restart route for an orchestrator: the latest context against
the threshold (exit 3 from `ctf compaction check` when it is reached), so an agent can be stopped and
restarted from a briefing file. Log content is data: only usage and compaction records are read.
"""
from __future__ import annotations

import json
import os
import re
import statistics
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from . import env as _env

HARNESSES = ("claude", "codex")
DEFAULTS = {"claude": 200_000, "codex": 150_000}
ENV_VARS = {"claude": "CTF_COMPACT_CLAUDE", "codex": "CTF_COMPACT_CODEX"}
# Claude Code's own bounds for autoCompactWindow / CLAUDE_CODE_AUTO_COMPACT_WINDOW (2.1.322 schema).
BOUNDS = {"claude": (100_000, 1_000_000),
          # Codex has no documented floor; below 50K one turn's tool output can trip it every turn.
          "codex": (50_000, 1_000_000)}

CLAUDE_WINDOW_VAR = "CLAUDE_CODE_AUTO_COMPACT_WINDOW"
CLAUDE_SETTING = "autoCompactWindow"
CODEX_CONFIG_KEY = "model_auto_compact_token_limit"
# Environment that would defeat or move the Claude threshold. Truthy = set to anything but 0/false.
CLAUDE_DISABLING_VARS = ("DISABLE_AUTO_COMPACT", "DISABLE_COMPACT")
CLAUDE_PCT_VAR = "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"
# The strings a harness build must contain for the knob to exist (doctor probe; the file is read,
# never run).
KNOB_MARKERS = {"claude": CLAUDE_WINDOW_VAR.encode(), "codex": CODEX_CONFIG_KEY.encode()}
BIN_VARS = {"claude": "CLAUDE_BIN", "codex": "CODEX_BIN"}
SCRIPT_PROBE_LIMIT = 1 << 20     # a file under 1 MiB that starts with #! is a launcher shim
OVERSHOOT_TOLERANCE = 0.10       # audit: a response up to 10% over the threshold still counts as held
CHECK_EXIT_OVER = 3

_TOKENS = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kKmM]?)\s*$")


class CompactionError(ValueError):
    """An unusable threshold, a conflicting harness setting, or an unreadable session log."""


def _harness(h: str) -> str:
    if h not in HARNESSES:
        raise CompactionError(f"unknown harness {h!r} (one of {', '.join(HARNESSES)})")
    return h


def parse_tokens(text: str, *, name: str = "value") -> int | None:
    """'200000' / '200k' / '1m' -> tokens; 'off' -> None. Anything else raises CompactionError."""
    raw = text.strip()
    if raw.lower() == "off":
        return None
    m = _TOKENS.match(raw)
    if not m:
        raise CompactionError(f"{name}={text!r} is not a token count (200000, 200k, 1m) or 'off'")
    mult = {"": 1, "k": 1_000, "m": 1_000_000}[m.group(2).lower()]
    val = float(m.group(1)) * mult
    if val != int(val):
        raise CompactionError(f"{name}={text!r} is not a whole number of tokens")
    return int(val)


def threshold(harness: str, environ: Mapping[str, str] | None = None) -> int | None:
    """The compaction threshold for `harness` in tokens: DEFAULTS, or the CTF_COMPACT_<HARNESS>
    override; None when the override is 'off'. Out of BOUNDS raises CompactionError."""
    h = _harness(harness)
    if h == "claude":
        raw = _env.get("CTF_COMPACT_CLAUDE", environ=environ)
    else:
        raw = _env.get("CTF_COMPACT_CODEX", environ=environ)
    if raw is None:
        return DEFAULTS[h]
    val = parse_tokens(raw, name=ENV_VARS[h])
    if val is None:
        return None
    lo, hi = BOUNDS[h]
    if not lo <= val <= hi:
        raise CompactionError(f"{ENV_VARS[h]}={raw!r} is outside {lo}..{hi} tokens for {h}")
    return val


def _truthy(v: str | None) -> bool:
    return bool(v) and v.strip().lower() not in ("0", "false", "no", "off")


def claude_conflicts(environ: Mapping[str, str] | None = None) -> list[str]:
    """Settings in `environ` that would disable or move the Claude threshold (empty when the
    threshold is off: the harness default is then the player's own business)."""
    e = os.environ if environ is None else environ
    t = threshold("claude", e)
    if t is None:
        return []
    out = [f"{v} is set (auto-compaction off)" for v in CLAUDE_DISABLING_VARS if _truthy(e.get(v))]
    if e.get(CLAUDE_PCT_VAR):
        out.append(f"{CLAUDE_PCT_VAR}={e[CLAUDE_PCT_VAR]} lowers the threshold below the window")
    have = e.get(CLAUDE_WINDOW_VAR)
    if have:
        try:
            same = parse_tokens(have, name=CLAUDE_WINDOW_VAR) == t
        except CompactionError:
            same = False
        if not same:
            out.append(f"{CLAUDE_WINDOW_VAR}={have} differs from the threshold {t} "
                       f"(set {ENV_VARS['claude']} instead)")
    return out


def claude_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment a Claude Code agent is started with: {CLAUDE_CODE_AUTO_COMPACT_WINDOW: N},
    or {} when the threshold is off. A conflicting setting in `environ` raises CompactionError
    naming it (the launcher refuses instead of starting an agent that would not compact)."""
    e = os.environ if environ is None else environ
    t = threshold("claude", e)
    if t is None:
        return {}
    bad = claude_conflicts(e)
    if bad:
        raise CompactionError("refusing to start Claude with a conflicting compaction setting: "
                              + "; ".join(bad))
    return {CLAUDE_WINDOW_VAR: str(t)}


def claude_settings(environ: Mapping[str, str] | None = None) -> dict:
    """Claude Code settings carrying the threshold ({"autoCompactWindow": N}); {} when off."""
    t = threshold("claude", environ)
    return {} if t is None else {CLAUDE_SETTING: t}


def codex_config_args(environ: Mapping[str, str] | None = None) -> list[str]:
    """The codex flags that set the threshold: ["-c", "model_auto_compact_token_limit=N"]; [] when off."""
    t = threshold("codex", environ)
    return [] if t is None else ["-c", f"{CODEX_CONFIG_KEY}={t}"]


# ---------------------------------------------------------------------------------- session logs

@dataclass(frozen=True)
class Compaction:
    index: int                 # responses before it
    trigger: str               # auto | manual | unknown
    pre_tokens: int | None     # the context it fired at (recorded, else the last response's)
    ts: str | None = None


@dataclass
class Session:
    path: Path
    harness: str
    contexts: list[int] = field(default_factory=list)       # per response, in order
    compactions: list[Compaction] = field(default_factory=list)


_CODEX_TYPES = {"session_meta", "turn_context", "event_msg", "response_item", "compacted"}
_CLAUDE_TYPES = {"user", "assistant", "system", "summary", "attachment"}


def detect_harness(path: str | Path, lines: int = 50) -> str:
    """'claude' or 'codex' from the record types of the first `lines` JSON lines."""
    p = Path(path)
    try:
        with open(p, errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= lines:
                    break
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(d, dict):
                    continue
                t = d.get("type")
                if t in _CODEX_TYPES and "payload" in d:
                    return "codex"
                if t in _CLAUDE_TYPES and ("message" in d or "sessionId" in d or "subtype" in d):
                    return "claude"
    except OSError as e:
        raise CompactionError(f"cannot read {p}: {e}") from None
    raise CompactionError(f"{p}: neither a Claude Code transcript nor a Codex rollout "
                          "(pass --harness)")


def _int(v) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def _claude_context(usage: dict) -> int:
    cc = usage.get("cache_creation_input_tokens")
    if not cc:
        nested = usage.get("cache_creation") or {}
        cc = _int(nested.get("ephemeral_5m_input_tokens")) + _int(nested.get("ephemeral_1h_input_tokens"))
    return _int(usage.get("input_tokens")) + _int(cc) + _int(usage.get("cache_read_input_tokens"))


def _read_claude(path: Path) -> Session:
    s = Session(path, "claude")
    seen: dict[str, int] = {}
    with open(path, errors="replace") as fh:
        for line in fh:
            if '"compact_boundary"' not in line and '"usage"' not in line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if not isinstance(d, dict) or d.get("isSidechain") is True:
                continue
            if d.get("type") == "system" and d.get("subtype") == "compact_boundary":
                meta = d.get("compactMetadata") or {}
                pre = meta.get("preTokens")
                pre = pre if isinstance(pre, int) and not isinstance(pre, bool) else (
                    s.contexts[-1] if s.contexts else None)
                s.compactions.append(Compaction(len(s.contexts), str(meta.get("trigger") or "unknown"),
                                                pre, d.get("timestamp")))
                continue
            if d.get("type") != "assistant":
                continue
            msg = d.get("message") or {}
            usage, mid = msg.get("usage"), msg.get("id")
            if not isinstance(usage, dict) or not mid or msg.get("model") == "<synthetic>":
                continue
            if mid in seen:            # one response is several lines (one per content block)
                continue
            seen[mid] = len(s.contexts)
            s.contexts.append(_claude_context(usage))
    return s


def _read_codex(path: Path) -> Session:
    s = Session(path, "codex")
    records: list[int] = []
    fallback: list[int] = []
    rec_ids: set = set()
    fb_keys: set = set()
    compacted: list[tuple] = []
    events: list[tuple] = []
    with open(path, errors="replace") as fh:
        for line in fh:
            head = line[:240]
            if not any(k in head for k in ('"token_usage_record"', '"token_count"', '"compacted"',
                                            '"context_compacted"')):
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if not isinstance(d, dict):
                continue
            p = d.get("payload") if isinstance(d.get("payload"), dict) else {}
            t, pt = d.get("type"), p.get("type")
            if t == "compacted":
                compacted.append((len(records), len(fallback), d.get("timestamp")))
            elif pt == "context_compacted":
                events.append((len(records), len(fallback), d.get("timestamp")))
            elif pt == "token_usage_record" or t == "token_usage_record":
                u, rid = p.get("usage") or {}, p.get("response_id")
                if rid and u and rid not in rec_ids:     # forked threads replay the parent's records
                    rec_ids.add(rid)
                    records.append(_int(u.get("input_tokens")))
            elif pt == "token_count":
                info = p.get("info") or {}
                lu, tu = info.get("last_token_usage") or {}, info.get("total_token_usage") or {}
                if not lu:
                    continue
                key = (tu.get("total_tokens"), lu.get("total_tokens"), lu.get("input_tokens"),
                       lu.get("output_tokens"))
                if key not in fb_keys:
                    fb_keys.add(key)
                    fallback.append(_int(lu.get("input_tokens")))
    s.contexts = records or fallback
    which = 0 if records else 1           # positions are counted in the series that was kept
    # One compaction writes a `compacted` record and usually a context_compacted event: count the
    # records, the events only when a rollout has no records.
    s.compactions = [Compaction(pos[which], "unknown", s.contexts[pos[which] - 1] if pos[which] else None,
                                pos[2]) for pos in (compacted or events)]
    return s


def read_session(path: str | Path, harness: str | None = None) -> Session:
    p = Path(path)
    h = _harness(harness) if harness else detect_harness(p)
    try:
        s = _read_claude(p) if h == "claude" else _read_codex(p)
    except OSError as e:
        raise CompactionError(f"cannot read {p}: {e}") from None
    if not s.contexts:
        raise CompactionError(f"{p}: no {h} usage records: nothing to measure")
    return s


@dataclass(frozen=True)
class Audit:
    path: str
    harness: str
    threshold: int | None
    responses: int
    peak: int
    mean: float
    over: int                   # responses above threshold * (1 + tolerance)
    excess_tokens: int          # sum of context above the threshold, every response
    compactions: tuple[Compaction, ...]
    tolerance: float = OVERSHOOT_TOLERANCE

    @property
    def held(self) -> bool:
        """True when no response went past the threshold plus the tolerance."""
        return self.threshold is not None and self.over == 0

    @property
    def fired_at(self) -> list[int]:
        """Context at each automatic compaction (the calibration a rehearsal is for)."""
        return [c.pre_tokens for c in self.compactions if c.trigger != "manual" and c.pre_tokens is not None]

    def to_dict(self) -> dict:
        return {"path": self.path, "harness": self.harness, "threshold": self.threshold,
                "responses": self.responses, "peak": self.peak, "mean": round(self.mean, 1),
                "over": self.over, "excess_tokens": self.excess_tokens, "held": self.held,
                "tolerance": self.tolerance, "fired_at": self.fired_at,
                "compactions": [{"index": c.index, "trigger": c.trigger, "pre_tokens": c.pre_tokens,
                                 "ts": c.ts} for c in self.compactions]}

    def line(self) -> str:
        t = "off" if self.threshold is None else f"{self.threshold:,}"
        verdict = ("HELD" if self.held else "THRESHOLD OFF" if self.threshold is None
                   else f"EXCEEDED ({self.over} responses over)")
        fired = self.fired_at
        cal = (f"; auto-compacted at {min(fired):,}..{max(fired):,} (median "
               f"{int(statistics.median(fired)):,})" if fired else "")
        return (f"{verdict}  {self.path} [{self.harness}] threshold {t}: {self.responses} responses, "
                f"peak {self.peak:,}, mean {self.mean:,.0f}, {len(self.compactions)} compactions"
                f"{cal}; {self.excess_tokens:,} tokens read above the threshold")


def audit(path: str | Path, harness: str | None = None, *, limit: int | None = None,
          environ: Mapping[str, str] | None = None, tolerance: float = OVERSHOOT_TOLERANCE) -> Audit:
    """Measure one session log against the threshold (`limit`, default: threshold(harness))."""
    if tolerance < 0:
        raise CompactionError(f"tolerance must be >= 0 (got {tolerance})")
    s = read_session(path, harness)
    t = threshold(s.harness, environ) if limit is None else limit
    ctx = s.contexts
    over = 0 if t is None else sum(1 for c in ctx if c > t * (1 + tolerance))
    excess = 0 if t is None else sum(max(0, c - t) for c in ctx)
    return Audit(str(s.path), s.harness, t, len(ctx), max(ctx), sum(ctx) / len(ctx), over, excess,
                 tuple(s.compactions), tolerance)


@dataclass(frozen=True)
class Reading:
    path: str
    harness: str
    context: int
    threshold: int

    @property
    def over(self) -> bool:
        return self.context >= self.threshold

    def line(self) -> str:
        pct = 100.0 * self.context / self.threshold
        state = "AT THRESHOLD: compact, or stop and restart from a briefing" if self.over else "under"
        return f"{self.context:,} of {self.threshold:,} tokens ({pct:.0f}%) [{self.harness}]: {state}"


def check(path: str | Path, harness: str | None = None, *, limit: int | None = None,
          environ: Mapping[str, str] | None = None) -> Reading:
    """The latest response's context against the threshold (the restart route for an orchestrator).
    A compaction after the latest response means the context is no longer known: CompactionError."""
    s = read_session(path, harness)
    t = threshold(s.harness, environ) if limit is None else limit
    if t is None:
        raise CompactionError(f"the {s.harness} threshold is off ({ENV_VARS[s.harness]}=off): "
                              "nothing to check against (pass --limit)")
    if s.compactions and s.compactions[-1].index == len(s.contexts):
        raise CompactionError(f"{s.path}: it compacted after its last response; the new context is "
                              "known after the next response")
    return Reading(str(s.path), s.harness, s.contexts[-1], t)


# ---------------------------------------------------------------------------------- preflight

def _resolve_bin(harness: str, e: Mapping[str, str]) -> tuple[str, str | None]:
    raw = e.get(BIN_VARS[harness]) or harness
    if os.sep in raw:
        p = Path(raw).expanduser()
        return raw, (str(p) if p.is_file() else None)
    for d in e.get("PATH", os.defpath).split(os.pathsep):
        cand = Path(d or ".") / raw
        if cand.is_file() and os.access(cand, os.X_OK):
            return raw, str(cand)
    return raw, None


def knob_in_build(path: str | Path, marker: bytes, chunk: int = 1 << 22) -> bool | None:
    """Whether the file holds `marker` (read in chunks, never run). None when it is a small `#!`
    launcher shim: the real build is elsewhere and this cannot tell."""
    p = Path(path)
    with open(p, "rb") as fh:
        head = fh.read(2)
        fh.seek(0)
        if head == b"#!" and p.stat().st_size < SCRIPT_PROBE_LIMIT:
            if marker in fh.read():
                return True
            return None
        tail = b""
        while True:
            buf = fh.read(chunk)
            if not buf:
                return False
            if marker in tail + buf:
                return True
            tail = buf[-len(marker):]


def codex_config_limit(environ: Mapping[str, str] | None = None) -> tuple[object, Path]:
    """(the Codex config's model_auto_compact_token_limit or None, the config path). Only that key is
    read. Invalid TOML raises CompactionError."""
    from . import paths
    cfg = paths.codex_home(environ) / "config.toml"
    try:
        data = tomllib.loads(cfg.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, cfg
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as err:
        raise CompactionError(f"{cfg} is not readable TOML: {type(err).__name__}") from None
    return data.get(CODEX_CONFIG_KEY), cfg


_RANK = {"ok": 0, "skip": 1, "warn": 2, "fail": 3}


def preflight(environ: Mapping[str, str] | None = None, *, codex: bool = True) -> tuple[str, str, str]:
    """(status, detail, fix) for the doctor's `compaction` check. fail: an unusable threshold, a
    setting that would disable or move the Claude threshold, or an installed build without the knob.
    warn: sessions started by hand do not get the threshold, or a build could not be probed. The Codex
    config is read (one key) only when `codex` is true."""
    e = dict(os.environ if environ is None else environ)
    parts: list[tuple[str, str, str]] = []
    try:
        th = {h: threshold(h, e) for h in HARNESSES}
    except CompactionError as err:
        return "fail", str(err), "fix CTF_COMPACT_CLAUDE / CTF_COMPACT_CODEX (a token count or 'off')"
    for h in HARNESSES:
        if th[h] is None:
            parts.append(("warn", f"{h} threshold off ({ENV_VARS[h]}=off): harness default", ""))
            continue
        raw, found = _resolve_bin(h, e)
        if found is None:
            parts.append(("warn", f"{h} CLI not found ({raw!r}): cannot confirm it knows the knob",
                          f"install it or set {BIN_VARS[h]}"))
            continue
        try:
            has = knob_in_build(found, KNOB_MARKERS[h])
        except OSError as err:
            parts.append(("warn", f"cannot read {found} to look for the knob: {err}", ""))
            continue
        knob = KNOB_MARKERS[h].decode()
        if has is False:
            parts.append(("fail", f"the installed {h} build ({found}) has no {knob}: the {th[h]:,} "
                          "threshold would be ignored",
                          f"update {h}, or watch the context with `python -m ctf compaction check` "
                          "and restart agents from a briefing"))
        elif has is None:
            parts.append(("warn", f"{found} is a launcher script: cannot confirm {knob}", ""))
        else:
            parts.append(("ok", f"{h} at {th[h]:,} ({knob})", ""))
    if th["claude"] is not None:
        bad = claude_conflicts(e)
        if bad:
            parts.append(("fail", "Claude: " + "; ".join(bad), "unset it, or set CTF_COMPACT_CLAUDE"))
        elif e.get(CLAUDE_WINDOW_VAR):
            parts.append(("ok", f"hand-started claude sessions get {CLAUDE_WINDOW_VAR} from this shell", ""))
        else:
            parts.append(("warn", "hand-started claude sessions use the default window (launchers set it)",
                          f"export {CLAUDE_WINDOW_VAR}={th['claude']} in your shell profile, or add "
                          f'"{CLAUDE_SETTING}": {th["claude"]} to your Claude settings'))
    if codex and th["codex"] is not None:
        try:
            have, cfg = codex_config_limit(e)
        except CompactionError as err:
            parts.append(("fail", str(err), "fix the Codex config"))
        else:
            fix = f"add `{CODEX_CONFIG_KEY} = {th['codex']}` to {cfg}"
            if have is None:
                parts.append(("warn", f"{cfg} sets no {CODEX_CONFIG_KEY}: a hand-started Codex agent "
                              "(a pasted brief) does not compact at the threshold", fix))
            elif not isinstance(have, int) or isinstance(have, bool):
                parts.append(("warn", f"{cfg} {CODEX_CONFIG_KEY} = {have!r} is not an integer", fix))
            elif have > th["codex"]:
                parts.append(("warn", f"{cfg} {CODEX_CONFIG_KEY} = {have:,} is above {th['codex']:,} "
                              "(launches override it; hand-started agents do not)", fix))
            else:
                parts.append(("ok", f"{cfg} {CODEX_CONFIG_KEY} = {have:,}", ""))
    status = max((p[0] for p in parts), key=_RANK.__getitem__, default="ok")
    detail = "; ".join(p[1] for p in parts)
    fix = "; ".join(p[2] for p in parts if p[2] and p[0] == status)
    return status, detail, fix


# ---------------------------------------------------------------------------------- shell interface

def main(argv: Iterable[str] | None = None) -> int:
    """`python -m ctf.compaction claude-env | claude-settings | codex-config` for the shell launchers
    (light: imports nothing beyond ctf.env). claude-env prints KEY=VALUE lines, claude-settings a
    JSON object, codex-config the `-c` value; nothing when the threshold is off. Exit 2 on an
    unusable value or a conflicting setting, with the reason on stderr."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0] not in ("claude-env", "claude-settings", "codex-config"):
        print("usage: python -m ctf.compaction claude-env|claude-settings|codex-config", file=sys.stderr)
        return 2
    try:
        if args[0] == "claude-env":
            for k, v in claude_env().items():
                print(f"{k}={v}")
        elif args[0] == "claude-settings":
            s = claude_settings()
            if s:
                print(json.dumps(s, separators=(",", ":")))
        else:
            a = codex_config_args()
            if a:
                print(a[1])
    except CompactionError as err:
        print(f"compaction: {err}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
