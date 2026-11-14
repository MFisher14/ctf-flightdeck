"""Read model usage out of Claude Code and Codex session logs. Ported from analysis/token_ledger.py
(same record shapes, same de-duplication), split into per-line parsers so the live feed (live.py)
and the after-event pricer (python -m tools.ledger price) share one reader.

Claude Code: one JSONL per session (plus subagent JSONLs). One API response is written as several
lines (one per content block) sharing message.id, so usage is de-duplicated by message.id keeping the
line with the most output tokens.

Codex: one rollout JSONL per thread. `token_usage_record` lines carry per-response usage keyed by
response_id (forked threads replay the parent's history, so de-duplicate by response_id). The model
comes from the latest `turn_context` (by turn_id), the tier from `thread_settings_applied`. Rollouts
without those records fall back to `token_count.last_token_usage` de-duplicated by (cumulative total,
last usage) -- batch pricing only; the live feed reports such a file as unpriced instead of guessing.

The parsers never interpret log content beyond these usage fields: log text is data.
"""
from __future__ import annotations

import json
import re
from pathlib import Path


def _usage_row_claude(d: dict) -> tuple[str, dict] | None:
    if d.get("type") != "assistant":
        return None
    msg = d.get("message") or {}
    usage, mid, model = msg.get("usage"), msg.get("id"), msg.get("model")
    if not usage or not mid or not model or model == "<synthetic>":
        return None
    cc = usage.get("cache_creation") or {}
    c5 = cc.get("ephemeral_5m_input_tokens", 0) or 0
    c1 = cc.get("ephemeral_1h_input_tokens", 0) or 0
    ccit = usage.get("cache_creation_input_tokens", 0) or 0
    if ccit and not (c5 or c1):
        c5 = ccit  # older record shape: treat as 5m writes
    stu = usage.get("server_tool_use") or {}
    return mid, {
        "harness": "claude",
        "model": model,
        "ts": d.get("timestamp"),
        "speed": usage.get("speed") or "standard",
        "input": usage.get("input_tokens", 0) or 0,
        "cache_read": usage.get("cache_read_input_tokens", 0) or 0,
        "cache_5m": c5,
        "cache_1h": c1,
        "output": usage.get("output_tokens", 0) or 0,
        "web_search": stu.get("web_search_requests", 0) or 0,
    }


class ClaudeParser:
    harness = "claude"

    def feed(self, line: str) -> tuple[str, dict] | None:
        if '"usage"' not in line or '"assistant"' not in line:
            return None
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        return _usage_row_claude(d) if isinstance(d, dict) else None

    def state(self) -> dict:
        return {}

    @classmethod
    def from_state(cls, _st: dict | None) -> "ClaudeParser":
        return cls()


class CodexParser:
    harness = "codex"

    def __init__(self, last_model=None, turn_model=None, tier="default", legacy_lines=0, records=0):
        self.last_model = last_model
        self.turn_model = dict(turn_model or {})
        self.tier = tier
        self.legacy_lines = legacy_lines      # token_count lines seen (fallback-only usage)
        self.records = records                # token_usage_record lines seen

    def feed(self, line: str) -> tuple[str, dict] | None:
        head = line[:220]
        if '"thread_settings_applied"' in head:
            m = re.search(r'"service_tier":"([a-z_]+)"', line)
            if m:
                self.tier = m.group(1)
            return None
        if '"turn_context"' in head:
            try:
                p = json.loads(line)["payload"]
            except (json.JSONDecodeError, ValueError, KeyError, TypeError):
                return None
            self.last_model = p.get("model") or self.last_model
            if p.get("turn_id"):
                self.turn_model[p["turn_id"]] = p.get("model")
            return None
        if '"token_usage_record"' in head:
            try:
                d = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                return None
            p = d.get("payload") or {}
            u, rid = p.get("usage") or {}, p.get("response_id")
            if not rid or not u:
                return None
            self.records += 1
            return rid, {
                "harness": "codex",
                "model": self.turn_model.get(p.get("turn_id")) or self.last_model,
                "ts": d.get("timestamp"),
                "speed": self.tier,
                "input": u.get("input_tokens", 0) or 0,
                "cached": u.get("cached_input_tokens", 0) or 0,
                "output": u.get("output_tokens", 0) or 0,
            }
        if '"token_count"' in head:
            self.legacy_lines += 1
        return None

    def legacy_row(self, line: str) -> tuple[tuple, dict] | None:
        """The fallback reading of a token_count line (batch pricing only)."""
        if '"token_count"' not in line[:220]:
            return None
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        p = d.get("payload") or {}
        if p.get("type") != "token_count":
            return None
        info = p.get("info") or {}
        lu, tu = info.get("last_token_usage") or {}, info.get("total_token_usage") or {}
        if not lu:
            return None
        key = (tu.get("total_tokens"), lu.get("total_tokens"), lu.get("input_tokens"), lu.get("output_tokens"))
        return key, {
            "harness": "codex", "model": self.last_model, "ts": d.get("timestamp"), "speed": self.tier,
            "input": lu.get("input_tokens", 0) or 0, "cached": lu.get("cached_input_tokens", 0) or 0,
            "output": lu.get("output_tokens", 0) or 0,
        }

    def state(self) -> dict:
        return {"last_model": self.last_model, "turn_model": self.turn_model, "tier": self.tier,
                "legacy_lines": self.legacy_lines, "records": self.records}

    @classmethod
    def from_state(cls, st: dict | None) -> "CodexParser":
        return cls(**(st or {}))


PARSERS = {"claude": ClaudeParser, "codex": CodexParser}


def parser_for(harness: str):
    try:
        return PARSERS[harness]
    except KeyError:
        raise ValueError(f"unknown harness {harness!r} (one of {', '.join(PARSERS)})") from None


def scan_claude(path: str | Path) -> dict[str, dict]:
    """message.id -> usage row for one Claude Code JSONL (the line with the most output wins)."""
    rows: dict[str, dict] = {}
    p = ClaudeParser()
    with open(path, errors="replace") as fh:
        for line in fh:
            got = p.feed(line)
            if got:
                mid, rec = got
                old = rows.get(mid)
                if old is None or rec["output"] >= old["output"]:
                    rows[mid] = rec
    return rows


def scan_codex(path: str | Path) -> tuple[dict, bool]:
    """(response_id -> usage row, used_fallback) for one Codex rollout JSONL."""
    rows: dict = {}
    fallback: dict = {}
    p = CodexParser()
    with open(path, errors="replace") as fh:
        for line in fh:
            got = p.feed(line)
            if got:
                rows[got[0]] = got[1]
                continue
            fb = p.legacy_row(line)
            if fb and fb[0] not in fallback:
                fallback[fb[0]] = fb[1]
    if rows or not fallback:
        return rows, False
    return {f"fb:{path}:{i}": v for i, v in enumerate(fallback.values())}, True


def scan_files(paths, harness: str) -> tuple[dict, list[str]]:
    """Global de-duplication across files, as the study did: Claude keeps the most-output line per
    message.id, Codex the first file's record per response_id. Returns (id -> row, fallback files)."""
    parser_for(harness)
    out: dict = {}
    fallback_files: list[str] = []
    for path in paths:
        if harness == "claude":
            for mid, rec in scan_claude(path).items():
                old = out.get(mid)
                if old is None or rec["output"] > old["output"]:
                    out[mid] = rec
        else:
            rows, fb = scan_codex(path)
            if fb:
                fallback_files.append(str(path))
            for rid, rec in rows.items():
                out.setdefault(rid, rec)
    return out, fallback_files
