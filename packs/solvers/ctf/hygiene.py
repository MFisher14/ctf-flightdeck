"""Tool-output hygiene (B-034): cap tool output, refuse whole-file windows, estimate tokens.

Every tool result is re-read on every later model turn, so a large result is paid for many times.
EFFICIENCY-PLAN section 3.6 found the two biggest reading wastes were results over 5K tokens (only the
first ~2K is usually needed) and 22,609 read windows of 150+ lines. This module is the one place those
limits live, so `ctf read`, intake and any other tool cap the same way and name the same reasons.

Nothing here reads a file or the environment; it is pure policy over text the caller already holds.
No silent truncation (rule 6): when output is capped, the result carries a note naming what was cut and
how to get the rest.

    from ctf import hygiene
    hygiene.estimate_tokens(text)                   # bytes / BYTES_PER_TOKEN, rounded up
    cap = hygiene.cap_text(text, max_tokens=2000)   # CapResult(text, capped, note, ...)
    print(cap.render())                             # the capped text, with the note appended if capped
    adv = hygiene.window_advice(n_lines, query=False)   # WindowAdvice(ok, reason, suggestion)
    hygiene.looks_binary(data_bytes)                # True for content that should not be dumped as text
"""
from __future__ import annotations

import math
from dataclasses import dataclass

__all__ = [
    "BYTES_PER_TOKEN", "CAP_TOKENS", "LOUD_TOKENS", "WINDOW_LINES",
    "HygieneError", "CapResult", "WindowAdvice",
    "estimate_tokens", "cap_text", "window_advice", "looks_binary",
]

# EFFICIENCY-PLAN section 3.10 measures 3.6 bytes per token; the same ratio is used everywhere.
BYTES_PER_TOKEN = 3.6
# Section 3.6: only the first ~2K tokens of a large result are usually needed; the rest is re-read waste.
CAP_TOKENS = 2000
# A result over this is re-read in full on every later turn (section 3.6, "results over 5K tokens").
LOUD_TOKENS = 5000
# Section 3.6: a read window of 150+ lines is the whole-file-window pattern (22,609 such calls).
WINDOW_LINES = 150

_ELISION_PREFIX = "... [ctf:"


class HygieneError(ValueError):
    """A hygiene function was called with an unusable argument (a non-positive budget, a bad mode)."""


def estimate_tokens(data: str | bytes) -> int:
    """An estimate of the model tokens `data` costs, as bytes / BYTES_PER_TOKEN rounded up. The same
    ratio the plan uses, so a caller can compare a read against a budget without a tokenizer."""
    raw = data.encode("utf-8", "surrogatepass") if isinstance(data, str) else bytes(data)
    if not raw:
        return 0
    return math.ceil(len(raw) / BYTES_PER_TOKEN)


@dataclass
class CapResult:
    """The outcome of capping text. `text` is what to show; `note` names the cut when `capped`."""
    text: str
    capped: bool
    shown_lines: int
    total_lines: int
    shown_tokens: int
    total_tokens: int
    note: str

    def render(self) -> str:
        """The text, with the cap note on its own last line when the output was capped."""
        return self.text if not self.capped else (self.text + ("\n" if self.text else "") + self.note)


def _within(chosen: list[str], max_tokens: int, max_lines: int | None) -> bool:
    if max_lines is not None and len(chosen) > max_lines:
        return False
    return estimate_tokens("\n".join(chosen)) <= max_tokens


def cap_text(text: str, *, max_tokens: int = CAP_TOKENS, max_lines: int | None = None,
             keep: str = "head") -> CapResult:
    """Cap `text` to at most `max_tokens` estimated tokens (and `max_lines` lines, if given), keeping
    whole lines. `keep="head"` keeps the first lines; `keep="head-tail"` keeps lines from both ends
    with an elision marker between them. The returned note names how many lines/tokens were hidden and
    how to get them; a line is never cut mid-way, so the budget may be overshot by one line."""
    if max_tokens <= 0:
        raise HygieneError(f"max_tokens must be positive, got {max_tokens}")
    if max_lines is not None and max_lines <= 0:
        raise HygieneError(f"max_lines must be positive, got {max_lines}")
    if keep not in ("head", "head-tail"):
        raise HygieneError(f"keep must be 'head' or 'head-tail', got {keep!r}")

    lines = text.split("\n")
    total_lines = len(lines)
    total_tokens = estimate_tokens(text)

    if _within(lines, max_tokens, max_lines):
        return CapResult(text, False, total_lines, total_lines, total_tokens, total_tokens, "")

    if keep == "head":
        kept: list[str] = []
        for ln in lines:
            if kept and not _within(kept + [ln], max_tokens, max_lines):
                break
            kept.append(ln)
            if not _within(kept, max_tokens, max_lines):   # first line already over budget: keep it alone
                break
        hidden_lines = total_lines - len(kept)
    else:  # head-tail: grow both ends alternately, reserving one line for the elision marker
        head: list[str] = []
        tail: list[str] = []
        hi, ti = 0, total_lines - 1
        take_head = True
        while hi <= ti:
            nxt = lines[hi] if take_head else lines[ti]
            trial = head + [nxt] + [_ELISION_PREFIX] + tail if take_head else head + [_ELISION_PREFIX] + [nxt] + tail
            if (head or tail) and not _within(trial, max_tokens, max_lines):
                break
            if take_head:
                head.append(nxt); hi += 1
            else:
                tail.insert(0, nxt); ti -= 1
            take_head = not take_head
        hidden_lines = total_lines - len(head) - len(tail)
        marker = f"{_ELISION_PREFIX} {hidden_lines} line(s) elided] ..."
        kept = head + [marker] + tail

    shown = "\n".join(kept)
    shown_tokens = estimate_tokens(shown)
    hidden_tokens = max(total_tokens - shown_tokens, 0)
    note = (f"[ctf: output capped to ~{shown_tokens} tokens; {hidden_lines} of {total_lines} lines "
            f"(~{hidden_tokens} tokens) hidden. Narrow the read with --lines or --grep, or pass "
            f"--no-cap for all of it.]")
    return CapResult(shown, True, len(kept), total_lines, shown_tokens, total_tokens, note)


@dataclass
class WindowAdvice:
    """Whether a requested read window is a targeted read or a discouraged whole-file/large window."""
    ok: bool
    reason: str
    suggestion: str


def window_advice(n_lines: int | None, *, query: bool = False, cap: int = WINDOW_LINES) -> WindowAdvice:
    """Judge a read window. A content query (`query=True`, e.g. a grep) is always targeted. Otherwise a
    window of `None` lines (the whole file) or `>= cap` lines is a large window the caller should refuse
    unless the operator overrides it (`ctf read --full`). `cap` is WINDOW_LINES by default."""
    if query:
        return WindowAdvice(True, "a content query is a targeted read", "")
    if n_lines is None:
        return WindowAdvice(False, "reading the whole file is a whole-file window",
                            f"ask for a range (--lines A-B, under {cap} lines) or a query (--grep)")
    if n_lines >= cap:
        return WindowAdvice(False, f"a {n_lines}-line window is a large window (>= {cap} lines)",
                            f"ask for a narrower range (under {cap} lines) or a query (--grep)")
    return WindowAdvice(True, "a bounded range under the window limit", "")


def looks_binary(data: bytes, *, sample: int = 8192) -> bool:
    """True when `data` should not be dumped as text: a NUL byte in the first `sample` bytes, or over
    30% of them outside the printable/whitespace range (so a caller shows a summary, not a flood)."""
    chunk = bytes(data[:sample])
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    text_bytes = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0C, 0x0D}
    nontext = sum(1 for b in chunk if b not in text_bytes and b < 0x80)
    return nontext > 0.30 * len(chunk)
