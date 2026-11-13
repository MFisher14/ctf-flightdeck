"""Live spend feed: tail an agent's session log(s) and charge the new, priced usage to one challenge's
budget meter (ctf.budget.LedgerMeter).

    from tools.ledger import live
    res = live.feed(meter, "9158", [log_path], harness="claude")   # call it every poll

Only complete lines are read; the byte offset, the per-file parser state and every response id
already charged are kept in a state file (default <workdir>/budget/feed-state.json, under a lock), so
re-running never charges a response twice. A Claude response whose later line reports more output
tokens is charged the difference. The state is saved before the spend is recorded, and all new
spend of one poll goes into one add_spend call, so a BudgetExceeded from the meter loses nothing.

A Codex rollout with only legacy token_count lines (no token_usage_record) cannot be priced
reliably while it grows; it is returned in `unpriced` (never guessed) for the caller to report.
"""
from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import pricing, scan

STATE_NAME = ("budget", "feed-state.json")


@dataclass
class FeedResult:
    usd: float = 0.0
    tokens: int = 0
    responses: int = 0
    unpriced: list[str] = field(default_factory=list)


def default_state_path(workdir: Path) -> Path:
    return Path(workdir).joinpath(*STATE_NAME)


class LiveFeed:
    def __init__(self, state_path: str | Path, prices: dict | None = None):
        self.state_path = Path(state_path)
        self.prices = prices if prices is not None else pricing.load_prices()

    def _load(self) -> dict:
        try:
            st = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"files": {}, "seen": {}}
        except json.JSONDecodeError as e:
            raise ValueError(f"{self.state_path}: corrupt feed state ({e}); move it aside to re-scan "
                             "(already-charged spend would then be charged again)") from None
        st.setdefault("files", {})
        st.setdefault("seen", {})
        return st

    def _save(self, st: dict) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(st, fh)
        os.replace(tmp, self.state_path)

    def poll(self, paths, harness: str) -> FeedResult:
        """Read the new complete lines of each file; return the new priced usage (not yet charged).
        Persists the state before returning."""
        parser_cls = scan.parser_for(harness)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        lock = os.open(str(self.state_path) + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            st = self._load()
            res = FeedResult()
            for path in paths:
                self._poll_one(Path(path), harness, parser_cls, st, res)
            self._save(st)
            return res
        finally:
            os.close(lock)

    def _poll_one(self, path: Path, harness: str, parser_cls, st: dict, res: FeedResult) -> None:
        try:
            info = path.stat()
        except FileNotFoundError:
            raise FileNotFoundError(f"session log not found: {path}") from None
        key = str(path.resolve())
        fst = st["files"].get(key)
        if fst is None or fst.get("harness") != harness or fst.get("ino") != info.st_ino \
                or info.st_size < fst.get("offset", 0):
            fst = {"harness": harness, "ino": info.st_ino, "offset": 0, "parser": {}}
        parser = parser_cls.from_state(fst.get("parser"))
        with open(path, "rb") as fh:
            fh.seek(fst["offset"])
            chunk = fh.read()
        end = chunk.rfind(b"\n")
        if end >= 0:
            for raw in chunk[:end + 1].splitlines():
                got = parser.feed(raw.decode("utf-8", errors="replace"))
                if got:
                    self._charge(harness, got[0], got[1], st["seen"], res)
            fst["offset"] += end + 1
        fst["parser"] = parser.state()
        st["files"][key] = fst
        if harness == "codex" and parser.legacy_lines and not parser.records:
            res.unpriced.append(str(path))

    def _charge(self, harness: str, rid: str, row: dict, seen: dict, res: FeedResult) -> None:
        k = f"{harness}:{rid}"
        old = seen.get(k)
        if old is not None and (harness == "codex" or row.get("output", 0) <= old["output"]):
            return
        usd = pricing.cost(row, self.prices)
        tok = pricing.tokens(row)
        d_usd, d_tok = (usd, tok) if old is None else (usd - old["usd"], tok - old["tok"])
        seen[k] = {"usd": usd, "tok": tok, "output": row.get("output", 0)}
        res.usd += max(0.0, d_usd)
        res.tokens += max(0, d_tok)
        res.responses += 1 if old is None else 0


def feed(meter, challenge_id: str, paths, harness: str, *, state_path: str | Path | None = None,
         prices: dict | None = None) -> FeedResult:
    """Poll the logs and charge the new spend to `challenge_id` on `meter` (one add_spend call).
    The meter's BudgetExceeded propagates after the spend is recorded."""
    sp = state_path if state_path is not None else default_state_path(meter.workdir)
    res = LiveFeed(sp, prices).poll(paths, harness)
    if res.usd > 0 or res.tokens > 0:
        meter.add_spend(challenge_id, round(res.usd, 10), res.tokens, source=f"tools.ledger:{harness}")
    return res
