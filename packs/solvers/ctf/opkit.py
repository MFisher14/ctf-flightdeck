"""Operator read kit (B-210): the readers behind `python -m ctf show`, so agents stop writing throwaway
scripts to read questions, verdicts, keys, a challenge's timeline, HCFG containers and delivery members.

At Huntress 2026 agents ran thousands of inline Python commands against the same saved JSON (attempt.json
1,744, verdicts.jsonl 590, status 383 in one cohort), and 1,234 commands in 179 files re-investigated
HCFG containers. B-257 built `ctf.lanestate` (per-challenge state files, conventions, routes); this module
adds what it does not cover and reuses it for the rest:

    question_lines(body, ids=None)          one line per question: id, kind, syntax, literal none, accepted
    keys_lines(challenge_dir)               the frozen key beside the submitted answers, per answer id
    verdict_rows(records, cid=..., ...)     the verdict ledger: platform.submit, submit.done, hof.result
    verdict_lines(rows)                     one compact line each, then the count per status
    timeline_lines(records, cid=..., ...)   every ledger record of a challenge (or a lane), oldest first
    hcfg_rows(paths) / hcfg_lines(rows)     every HCFG container of a sample set: carrier, section, offset,
                                            encoding layer, key, CRC, member names
    member_rows(path, prefix=None)          a delivery's members in archive order (zip or folder), with
    member_lines(rows)                      size, sha256 and the day prefix each belongs to

Pure reading: no network, no model, no challenge binary run. A flag is never printed: a ledger record's
`flag` (kept when the event allows sharing) is shown as the first 12 hex of its SHA-256, like a
`flag_sha256`. An archive password is never printed. A missing or unreadable input raises OpKitError
naming it (R-6); an empty selection is said, never silently blank.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path

from . import lanestate as _ls

# Verdict ledger: the records that carry a platform verdict (ctf/platform/rules.py, queue.py, halloffame.py).
SUBMIT_EVENT = "platform.submit"
DONE_EVENT = "submit.done"
HOF_EVENT = "hof.result"
VERDICT_EVENTS = (SUBMIT_EVENT, DONE_EVENT, HOF_EVENT)

# fields shown per verdict event, in order (flag and flag_sha256 are rendered as sha:<12 hex>)
_VERDICT_FIELDS = {
    SUBMIT_EVENT: ("status", "judged", "guess", "confirmed", "provenance", "attempt_id", "remaining", "answers",
                   "partial", "post_stop", "rotating", "sweep", "ranked_retry"),
    DONE_EVENT: ("status", "attempts", "held_s", "queued"),
    HOF_EVENT: ("status", "attempt_id", "eligible", "regular", "pool", "note"),
}
# fields never shown in a timeline line (identity of the line, or a value that must not be printed)
_TIMELINE_SKIP = {"ts", "event", "challenge_id", "event_slug", "flag", "flag_sha256"}
DEFAULT_LIMIT = 200


class OpKitError(RuntimeError):
    """An input the kit cannot read: the message names it and the fix."""


# ---- small helpers -----------------------------------------------------------------------------------

def _utc(ts) -> str:
    try:
        return _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return "?"


def challenge_key(cid) -> str:
    """A multi-answer id `<cid>#<answer>` counts against `<cid>` (ctf.platform.rules)."""
    return str(cid).split("#", 1)[0]


def _cid_matches(rec_cid, cid: str) -> bool:
    if rec_cid is None:
        return False
    rec_cid = str(rec_cid)
    return rec_cid == cid if "#" in cid else challenge_key(rec_cid) == cid


def flag_ref(rec: dict) -> str | None:
    """`sha:<12 hex>` for a record's flag (its flag_sha256, else the SHA-256 of a kept flag), or None."""
    sha = rec.get("flag_sha256")
    if not sha and isinstance(rec.get("flag"), str):
        sha = hashlib.sha256(rec["flag"].encode("utf-8")).hexdigest()
    return f"sha:{str(sha)[:12]}" if sha else None


def _cell(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, float):
        return f"{v:g}"
    if isinstance(v, (int, str)):
        return _ls._clip(str(v), 80)
    if isinstance(v, (list, tuple)):
        return f"[{len(v)}]"
    if isinstance(v, dict):
        return f"{{{len(v)}}}"
    return _ls._clip(str(v), 80)


def parse_since(text: str | None, now: float | None = None) -> float | None:
    """Epoch seconds, ISO-8601 with an offset, or `<N>s|m|h` ago. A naive time is refused (no zone guess)."""
    if text is None:
        return None
    t = text.strip()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([smh])", t)
    if m:
        import time as _time
        mult = {"s": 1, "m": 60, "h": 3600}[m.group(2)]
        return (now if now is not None else _time.time()) - float(m.group(1)) * mult
    try:
        return float(t)
    except ValueError:
        pass
    try:
        when = _dt.datetime.fromisoformat(t.replace("Z", "+00:00"))
    except ValueError:
        raise OpKitError(f"--since {text!r}: not epoch seconds, ISO-8601 or <N>s/m/h") from None
    if when.tzinfo is None:
        raise OpKitError(f"--since {text!r} has no UTC offset; write e.g. 2026-11-07T08:00-05:00")
    return when.timestamp()


def _lane_of(rec: dict) -> str | None:
    """A record's lane: its `lane` field, else the first segment of its engine id."""
    if isinstance(rec.get("lane"), str):
        return rec["lane"]
    eng = rec.get("engine")
    if isinstance(eng, str) and "." in eng:
        return eng.split(".", 1)[0]
    return None


# ---- questions ---------------------------------------------------------------------------------------

def question_body(challenge_dir: Path | None = None, *, file: Path | None = None):
    """The JSON body holding the challenge's questions: `file`, else the first of start.json,
    live_start.json, attempt.json in the folder that has a question list."""
    if file is not None:
        p = Path(file).expanduser()
        if not p.is_file():
            raise OpKitError(f"--file: not a file: {p}")
        return p, _ls._load_json(p)
    if challenge_dir is None:
        raise OpKitError("give a challenge (id with --root, or --dir) or --file BODY")
    tried = []
    for name in (*_ls.VARIANT_FILES["start"], *_ls.VARIANT_FILES["attempt"]):
        p = Path(challenge_dir) / name
        if not p.exists():
            continue
        tried.append(name)
        body = _ls._load_json(p)
        if isinstance(body, dict) and isinstance(body.get("questions"), list):
            return p, body
    if tried:
        raise OpKitError(f"no question list in {', '.join(tried)} under {challenge_dir}; pass --file BODY")
    raise OpKitError(f"no start.json, live_start.json or attempt.json in {challenge_dir}; pass --file BODY")


def question_lines(body, ids=None, *, source: str = "") -> list[str]:
    """One line per question, in the body's order: `id  kind=K syntax=S none=yes|no accepted=[..]` and
    the clipped wording on the next line. `ids` keeps only those ids (an unknown one is an error)."""
    from .adapt import qdiff as _qdiff
    from . import idresolve as _idresolve
    try:
        qs = _qdiff.questions_of(body)
    except _qdiff.QDiffError as e:
        raise OpKitError(f"{source or 'body'}: {e}") from None
    if ids:
        have = {(q.get("id") or q.get("qid")) for q in qs}
        unknown = [i for i in ids if i not in have]
        if unknown:
            raise OpKitError(f"no question id {', '.join(unknown)} in {source or 'the body'}")
        qs = [q for q in qs if (q.get("id") or q.get("qid")) in set(ids)]
    head = f"questions{' ' + source if source else ''} ({len(qs)}):"
    out = [head]
    for q in qs:
        qid = q.get("id") or q.get("qid")
        fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        parts = [f"kind={fmt.get('kind', '?')}"]
        if fmt.get("syntax") is not None:
            parts.append(f"syntax={_cell(fmt['syntax'])}")
        parts.append("none=" + ("yes" if _idresolve.permits_literal_none(q) else "no"))
        acc = fmt.get("accepted_values")
        if isinstance(acc, list):
            parts.append("accepted=[" + ",".join(_ls._clip(str(a), 40) for a in acc[:8])
                         + (f",+{len(acc) - 8}" if len(acc) > 8 else "") + "]")
        elif acc is not None:
            parts.append(f"accepted={_cell(acc)}")
        out.append(f"  {qid}  " + " ".join(parts))
        if q.get("question"):
            out.append(f"      {_ls._clip(q['question'], 160)}")
    return out


# ---- keys --------------------------------------------------------------------------------------------

def keys_lines(challenge_dir: Path) -> list[str]:
    """The frozen key (key.json) beside the submitted answers (answers*.json), one answer id per line:
    `=` same, `!` differs, `-` only one side has it. At least one of the two files must exist."""
    d = Path(challenge_dir)
    key = ans = None
    key_name = ans_name = None
    try:
        p = _ls._pick_file(d, _ls.VARIANT_FILES["key"])
        key, key_name = _ls._load_json(p), p.name
    except _ls.LaneStateError:
        pass
    try:
        p = _ls._pick_file(d, _ls.VARIANT_FILES["answers"])
        ans, ans_name = _ls._load_json(p), p.name
    except _ls.LaneStateError:
        pass
    if key is None and ans is None:
        raise OpKitError(f"neither key.json nor one of {', '.join(_ls.VARIANT_FILES['answers'])} in {d}")
    for obj, name in ((key, key_name), (ans, ans_name)):
        if obj is not None and not isinstance(obj, dict):
            raise OpKitError(f"{d / name}: expected a JSON object mapping answer ids to values")
    key, ans = key or {}, ans or {}
    ids = sorted(set(key) | set(ans))
    same = sum(1 for i in ids if i in key and i in ans and _ls._one_value(key[i]) == _ls._one_value(ans[i]))
    out = [f"keys {d.name}: key={key_name or '(none)'} answers={ans_name or '(none)'} "
           f"({len(ids)} id(s), {same} same)"]
    for i in ids:
        kv = _ls._one_value(key[i]) if i in key else None
        av = _ls._one_value(ans[i]) if i in ans else None
        if kv is not None and av is not None:
            mark = "=" if kv == av else "!"
        else:
            mark = "-"
        out.append(f"  {mark} {i}  key={kv if kv is not None else '-'}  answer={av if av is not None else '-'}")
    return out


# ---- verdict ledger ----------------------------------------------------------------------------------

def verdict_rows(records, *, cid: str | None = None, status: str | None = None, since: float | None = None,
                 slug: str | None = None, events=VERDICT_EVENTS) -> list[dict]:
    """The verdict records (platform.submit, submit.done, hof.result), oldest first, filtered by challenge
    (`9` matches `9` and `9#a`; `9#a` only itself), status, time and event slug."""
    bad = [e for e in events if e not in VERDICT_EVENTS]
    if bad:
        raise OpKitError(f"--kind {', '.join(bad)}: one of {', '.join(VERDICT_EVENTS)}")
    rows = []
    for r in records:
        if r.get("event") not in events:
            continue
        if cid is not None and not _cid_matches(r.get("challenge_id"), cid):
            continue
        if status is not None and str(r.get("status")) != status:
            continue
        if since is not None and float(r.get("ts", 0)) < since:
            continue
        if slug is not None and r.get("event_slug") not in (None, slug):
            continue
        rows.append(r)
    rows.sort(key=lambda r: float(r.get("ts", 0)))
    return rows


def verdict_line(r: dict) -> str:
    ev = r.get("event")
    parts = [_utc(r.get("ts")), f"{ev:<15}", str(r.get("challenge_id", "-"))]
    for k in _VERDICT_FIELDS.get(ev, ()):
        if k in r and r[k] is not None and r[k] is not False:
            parts.append(f"{k}={_cell(r[k])}")
    ref = flag_ref(r)
    if ref:
        parts.append(f"flag={ref}")
    return " ".join(parts)


def verdict_lines(rows: list[dict], *, limit: int = DEFAULT_LIMIT) -> list[str]:
    if not rows:
        return ["verdicts: no matching platform.submit, submit.done or hof.result record in the ledger"]
    counts: dict[str, int] = {}
    for r in rows:
        if r.get("event") == SUBMIT_EVENT:
            counts[str(r.get("status"))] = counts.get(str(r.get("status")), 0) + 1
    shown = rows[-limit:] if limit else rows
    out = [f"verdicts ({len(rows)} record(s)" + (f", last {len(shown)} shown" if len(shown) < len(rows) else "")
           + "):"]
    out += ["  " + verdict_line(r) for r in shown]
    subs = sum(counts.values())
    out.append(f"sends: {subs}" + (" (" + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + ")"
                                   if counts else ""))
    return out


# ---- timeline ----------------------------------------------------------------------------------------

def timeline_rows(records, *, cid: str | None = None, lane: str | None = None, since: float | None = None,
                  events=None) -> list[dict]:
    if cid is None and lane is None:
        raise OpKitError("timeline: give a challenge id or --lane L")
    out = []
    for r in records:
        if cid is not None and not _cid_matches(r.get("challenge_id"), cid):
            continue
        if lane is not None and _lane_of(r) != lane:
            continue
        if since is not None and float(r.get("ts", 0)) < since:
            continue
        if events and r.get("event") not in events:
            continue
        out.append(r)
    out.sort(key=lambda r: float(r.get("ts", 0)))
    return out


def timeline_lines(rows: list[dict], *, label: str = "", limit: int = DEFAULT_LIMIT) -> list[str]:
    """`+SSSS.Ss event [cid] key=value ...` per record, relative to the first; flags as sha refs."""
    if not rows:
        return [f"timeline {label}: no ledger record"]
    t0 = float(rows[0].get("ts", 0))
    shown = rows[-limit:] if limit else rows
    out = [f"timeline {label}: {len(rows)} record(s) from {_utc(t0)}"
           + (f", last {len(shown)} shown" if len(shown) < len(rows) else "")]
    for r in shown:
        parts = [f"+{float(r.get('ts', 0)) - t0:9.1f}s", str(r.get("event"))]
        if r.get("challenge_id") is not None:
            parts.append(f"[{r['challenge_id']}]")
        for k in sorted(r):
            if k in _TIMELINE_SKIP:
                continue
            parts.append(f"{k}={_cell(r[k])}")
        ref = flag_ref(r)
        if ref:
            parts.append(f"flag={ref}")
        out.append("  " + " ".join(parts))
    return out


# ---- solver modules ----------------------------------------------------------------------------------

def _lane_module(name: str, root: Path | None = None):
    """Import a flat engine module (e.g. `hcfg`, `members`) on the engine sys.path, as the other
    lane-backed commands do. A missing module is an error naming it."""
    from .engines import layout
    for p in reversed(layout.sys_path(root)):
        if p not in sys.path:
            sys.path.insert(0, p)
    import importlib
    try:
        return importlib.import_module(name)
    except ImportError as e:
        raise OpKitError(f"engine module {name!r} does not import from the lanes ({e})") from None


# ---- hcfg dump ---------------------------------------------------------------------------------------

def section_of(data: bytes, offset: int) -> str:
    """The section of a PE or ELF image that holds file offset `offset`; `header`, `overlay` or `-`."""
    binfmt = _lane_module("binfmt")
    try:
        info = binfmt.pe(data)
    except Exception:  # noqa: BLE001 - a damaged image reads as no image, never a crash of the dump
        info = None
    if info:
        for s in info.get("sections") or ():
            if s.get("rsize") and s["raw"] <= offset < s["raw"] + s["rsize"]:
                return s.get("name") or "?"
        return "header" if offset < info.get("size_of_headers", 0) else "overlay"
    try:
        info = binfmt.elf(data)
    except Exception:  # noqa: BLE001
        info = None
    if info:
        for s in info.get("sections") or ():
            if s.get("type") != 8 and s.get("size") and s["offset"] <= offset < s["offset"] + s["size"]:
                return s.get("name") or "?"
        return "-"
    return "-"


def _samples(paths, *, members: bool = True) -> list[tuple[str, bytes | None]]:
    """(carrier name, bytes) for each path: a file; a folder's files (sorted, recursive); and with
    `members`, a zip's members (archive order, the known archive passwords) in place of the zip."""
    out: list[tuple[str, bytes | None]] = []
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_dir():
            files = sorted(q for q in p.rglob("*") if q.is_file() and not q.is_symlink())
            out += [(str(q.relative_to(p)), q.read_bytes()) for q in files]
        elif p.is_file():
            data = p.read_bytes()
            if members and data[:2] == b"PK":
                got = _zip_members(data, p.name)
                if got is not None:
                    names, bodies = got
                    # an unreadable member (locked or damaged) is listed with None: nothing to read
                    out += [(f"{p.name}!{n}", bodies.get(n)) for n in names]
                    continue
            out.append((p.name, data))
        else:
            raise OpKitError(f"sample not found: {p}")
    if not out:
        raise OpKitError("no sample to read (the paths hold no file)")
    return out


def _zip_members(data: bytes, label: str):
    """([member names in archive order], {name: bytes} of those that read) of a zip, or None when it is
    no zip. A member missing from the dict is locked (no known password) or damaged."""
    try:
        names = [i.filename for i in zipfile.ZipFile(io.BytesIO(data)).infolist() if not i.is_dir()]
    except zipfile.BadZipFile:
        return None
    ap = _lane_module("archive_passwords")
    try:
        got, _locked = ap.read_all(data)
    except Exception as e:  # noqa: BLE001 - the password store did not resolve: say so, never read blind
        raise OpKitError(f"{label}: an encrypted member needs the archive password store, which did not "
                         f"resolve ({type(e).__name__}: {e}); set CTF_WORKDIR or CTF_EVENT") from None
    unread = [n for n in names if n not in got]
    if unread:
        # archive_passwords reads a store it cannot locate as empty; a locked member must not hide that
        try:
            ap.store_path()
        except Exception as e:  # noqa: BLE001 - name the reason, never report "locked" blind
            raise OpKitError(f"{label}: {len(unread)} member(s) did not open and the archive password store "
                             f"did not resolve ({type(e).__name__}: {e}); set CTF_WORKDIR or CTF_EVENT") from None
    return names, got


def hcfg_rows(paths, *, others: bool = True) -> list[dict]:
    """One row per HCFG container in the samples (hcfg.containers, with the other encodings when
    `others`), or a headerless reading, or a `none` row: carrier, section, offset, version, encoding
    layer (`how`, plus the non-JSON serialisation), key, CRC, whether the CRC checks, member names."""
    hcfg = _lane_module("hcfg")
    rows = []
    for name, data in _samples(paths):
        if data is None:
            rows.append({"carrier": name, "found": False, "note": "unreadable (locked: no known password, or damaged)"})
            continue
        hits = hcfg.containers(data, others=others)
        if not hits:
            h = hcfg.headerless(data)
            hits = [dict(h, headerless=True)] if h else []
        if not hits:
            rows.append({"carrier": name, "found": False, "size": len(data)})
            continue
        for h in hits:
            obj = h.get("json") if isinstance(h.get("json"), dict) else {}
            key = h.get("key_bytes")
            key_s = (key.hex() if isinstance(key, (bytes, bytearray)) else str(key)) if key else f"{h['key']:02x}"
            layer = h.get("how", "xor") + (f"+{h['nonjson']}" if h.get("nonjson") else "")
            rows.append({"carrier": name, "found": True, "section": section_of(data, h["offset"]),
                         "offset": h["offset"], "version": h.get("version"), "layer": layer, "key": key_s,
                         "crc32": h.get("crc32"), "crc_ok": bool(h.get("crc_ok")),
                         "headerless": bool(h.get("headerless")), "members": sorted(map(str, obj))})
    return rows


def hcfg_lines(rows: list[dict]) -> list[str]:
    found = [r for r in rows if r.get("found")]
    carriers = len({r["carrier"] for r in rows})
    out = [f"hcfg: {len(found)} container(s) in {carriers} sample(s)"]
    for r in rows:
        if not r.get("found"):
            out.append(f"  {r['carrier']}: none" + (f" ({r['note']})" if r.get("note") else ""))
            continue
        crc = "-" if r.get("crc32") is None else f"0x{r['crc32']:08x}"
        ver = "-" if r.get("version") is None else str(r["version"])
        out.append(f"  {r['carrier']}: section={r['section']} offset=0x{r['offset']:x} v={ver} "
                   f"layer={r['layer']} key=0x{r['key']} crc32={crc} crc_ok={'yes' if r['crc_ok'] else 'no'}"
                   + (" headerless" if r.get("headerless") else ""))
        mem = r.get("members") or []
        out.append(f"      members({len(mem)}): " + (", ".join(mem[:24]) + (f", +{len(mem) - 24}" if len(mem) > 24 else "")
                                                     if mem else "-"))
    return out


# ---- member dump -------------------------------------------------------------------------------------

_DAY = re.compile(r"^(d\d{1,3})(?![0-9A-Za-z])", re.I)


def member_rows(path: Path, *, prefix: str | None = None) -> list[dict]:
    """A delivery's members (a zip, in archive order, read with the known archive passwords; or a folder's
    files, sorted) with index, size, sha256 and day prefix. With `prefix` (e.g. `d03`), only that day's
    members, chosen by members.day_members (the lane's own rule: archive order, the prefix not followed by
    a letter or digit), so `<prefix>_artifact_sha256_<n>` counts the same members the lane does."""
    p = Path(path).expanduser()
    if p.is_dir():
        files = {str(q.relative_to(p)): q.read_bytes() for q in sorted(p.rglob("*"))
                 if q.is_file() and not q.is_symlink()}
        order = list(files)
        delivery = b""
    elif p.is_file():
        delivery = p.read_bytes()
        got = _zip_members(delivery, p.name)
        if got is None:
            raise OpKitError(f"{p}: not a zip and not a folder (member dump reads a delivery)")
        order, files = got
    else:
        raise OpKitError(f"delivery not found: {p}")
    if prefix:
        mem = _lane_module("members")
        chosen = mem.day_members(files, {"delivery": delivery}, prefix)
        order = [n for n, _ in chosen]
    rows = []
    for i, n in enumerate(order):
        body = files.get(n)
        base = n.rsplit("/", 1)[-1]
        day = _DAY.match(base)
        rows.append({"index": i, "name": n, "locked": body is None,
                     "size": None if body is None else len(body),
                     "sha256": None if body is None else hashlib.sha256(body).hexdigest(),
                     "day": day.group(1).lower() if day else None})
    return rows


def member_lines(rows: list[dict], *, label: str = "", prefix: str | None = None) -> list[str]:
    head = f"members {label}" + (f" prefix {prefix}" if prefix else "") + f": {len(rows)}"
    if not rows:
        return [head + " (none)"]
    out = [head]
    for r in rows:
        if r["locked"]:
            out.append(f"  {r['index']:>3} {r['name']}  unreadable (locked: no known password, or damaged)")
            continue
        out.append(f"  {r['index']:>3} {r['name']}  {r['size']:>9}  {r['sha256'][:16]}  day={r['day'] or '-'}")
    return out
