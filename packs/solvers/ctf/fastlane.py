"""Wave "fast lane": the dead-simple, high-solve challenges, grabbed IN-PROCESS.

Scoring on CSCTF decays as more teams solve, so the first seconds of a wave matter. For the
cheapest, most-solved classes the orchestrator should not pay a subagent spin-up: this module runs
them directly in the main session and returns a flag/answer the instant one is *deterministically*
derived, else ``None`` (so the orchestrator falls back to a real solver).

The classes it covers:

  * **sanity "read the rules"**  -- recognise it (category ``sanity``, or ``rules``/``welcome`` in the
    name/description), and look for a ``CSCTF{...}`` first in the description itself, then on the
    event's rules page (fetched with one direct GET from ``base_url``).
  * **encoding-chain crypto** (CyberChef-style) -- run the warmups auto-decoder
    (``solvers/warmups/crib_decode.py``) over the attached files and any encoded-looking blob in the
    brief, and return any ``CSCTF{...}`` a layered decode surfaces.
  * **text tricks in the brief / rules page** (B-208, ``ctf.texttricks``) -- acrostics (first letter of
    every bullet or line), word initials, capitals, and whitespace / zero-width bit channels, checked
    against the event flag format. A full flag a hidden channel spells is returned; a prefix-led
    reading or a printable whitespace decode is a ``candidate`` for the player, never a flag.
  * **50-pt OSINT lookups** -- detect the lookup type from the brief and either perform one lookup
    through the allow-listed/throttled public OSINT client (Wayback CDX; NVD) or return a precise
    instruction.  A fetched value is a candidate for human verification, never an auto-submit flag.
    (MITRE ATT&CK, HIBP, web-check/WHOIS/DNS).  Last, the brief-URL branch (B-088,
    ``ctf/brieffield.py``): a brief that names a site and asks for one field on it ("the company
    registration number") gets one scope-checked GET and the page's matching label/value pair as a
    candidate.
  * **shipped-client User-Agent** (B-131) -- when nothing above matched and a handout file states a
    custom User-Agent (a browser inside a disk image, a script), return a flagless instruction to
    replay it with ``python -m ctf client-replay run``. Read offline; nothing is fetched here.

Hard rules this module keeps (see AGENTS.md):

  * It **never submits** and **never guesses**. It returns a flag only when a decode/fetch produced it
    deterministically; otherwise ``None`` or an instruction with ``flag=None``.
  * Any network is a *single, direct public lookup* -- never a scan, a sweep, or an off-target request.
    Every outbound GET is capped and times out; there is no retry sweep.

API
    ``try_solve(detail, files_dir, *, cfg=None, fetch=None, online=True) -> dict | None``

    The result dict (when not ``None``) carries::

        {"klass": <str>, "flag": <str|None>, "candidate": <str|None>, "how": <str>,
         "confidence": "high"|"medium"|"low", "source": <str|None>,
         "instruction": <str|None>}

    ``flag`` is set only for an offline decode or assigned-platform sanity result.  Public OSINT
    observations use ``candidate`` plus ``instruction`` so the player performs the final pin.

CLI
    ``python -m ctf.fastlane <workspace_dir>``  runs it on a pulled ``workspace/<id>-<slug>/`` and
    prints the outcome (highlighting a ``CSCTF{...}`` hit). ``--offline`` skips all network lookups.
"""
from __future__ import annotations

import json
import logging
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from . import config as _config
from . import flagfmt
from . import texttricks as _tt
from .platform import NotSupported
from .platform import legacy as _legacy

_log = logging.getLogger(__name__)

# --- make the carried warmups auto-decoder importable (solvers/common + solvers/warmups) ---------
_REPO = Path(__file__).resolve().parent.parent
for _p in (_REPO / "solvers" / "common", _REPO / "solvers" / "warmups", _REPO / "solvers" / "toolkits",
           _REPO / "solvers" / "web"):
    _ps = str(_p)
    if _ps not in sys.path:
        sys.path.insert(0, _ps)

try:
    import crib_decode as _crib  # noqa: E402
except Exception:  # pragma: no cover - the engine should always import, but never crash the lane
    _crib = None


def _double_spend():
    """Lazily import the B-048 race/TOCTOU burst engine (solvers/web/double_spend).

    Imported on demand because the race class is the only fast-lane branch that needs the
    heavier web toolkit; sanity/encoding/OSINT never pay for it. Returns None loudly-at-call
    (the caller reports an unavailable engine) rather than importing at module load."""
    try:
        import double_spend as _ds  # noqa: E402
        return _ds
    except Exception:  # pragma: no cover - the race lane reports this as unavailable
        return None

# The event's flag format (ctf.flagfmt), matched against decoded text and page bodies. OSINT answers
# are freeform (not a flag) and are handled by the lookup branch, not this pattern.
FLAG_RE = flagfmt.TEXT

# A blob that is plausibly an encoding chain: mostly base64/base32/hex/ascii-85 glyphs, some length.
_ENCODED_RE = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")

MAX_FETCH_BYTES = 512 * 1024   # never pull an unbounded page
FETCH_TIMEOUT_S = 10.0


# =================================================================================================
# small helpers
# =================================================================================================
def _result(klass: str, *, flag: Optional[str] = None, candidate: Optional[str] = None, how: str = "",
            confidence: str = "low", source: Optional[str] = None,
            instruction: Optional[str] = None) -> dict:
    return {"klass": klass, "flag": flag, "candidate": candidate, "how": how, "confidence": confidence,
            "source": source, "instruction": instruction}


def _text_of(detail: dict) -> str:
    """Name + description, lower-cased, for keyword detection."""
    return ((detail.get("name") or "") + "\n" + (detail.get("description") or "")).lower()


# Brief wording that points at a text trick (B-208): with it, even a plain acrostic reading is shown.
_TEXT_TRICK_WORDS = ("first letter", "acrostic", "initials", "capital letter", "capitalized",
                     "capitalised", "read between the lines", "hidden in plain sight", "whitespace",
                     "white space", "trailing space", "zero-width", "zero width", "every bullet",
                     "each bullet", "each line", "every line", "telestich")


def _hints_text_trick(detail: dict) -> bool:
    """True when the name or brief says the answer hides in the text itself (keyword match only)."""
    txt = _text_of(detail)
    return any(w in txt for w in _TEXT_TRICK_WORDS)


def _default_fetch(cfg: _config.Config) -> Callable[[str], Optional[str]]:
    """A capped, single-shot GET of the event platform's pages. Returns the body text or None and
    never retries. It raises only a manual-mode refusal (ctf.platform.legacy, R-02: the event is
    manual or forbids automation on its platform), before any request; try_sanity reports it."""
    ua = getattr(cfg, "user_agent", "csctf-2026-solver")

    def fetch(url: str) -> Optional[str]:
        _legacy.require("fastlane rules-page GET")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_S) as r:  # noqa: S310 (public lookup)
                raw = r.read(MAX_FETCH_BYTES)
            return raw.decode("utf-8", "replace")
        except Exception:
            return None

    return fetch


def _public_osint_fetch() -> Callable[[str], Optional[str]]:
    """Adapt the guarded public-source client to the legacy ``url -> text`` parser hook."""
    try:
        import osint_online
        client = osint_online.PublicOSINTClient(request_cap=4)
    except Exception:
        return lambda _url: None

    def fetch(url: str) -> Optional[str]:
        try:
            parsed = urllib.parse.urlsplit(url)
            host = parsed.hostname or ""
            provider = "wayback" if host == "web.archive.org" else "nvd"
            if provider == "wayback":
                target = urllib.parse.parse_qs(parsed.query).get("url", [""])[0]
                # The adapter uses the legacy CDX parser below, but still bind and scope-check the
                # embedded target before the public provider sees it.
                client._guard_value("url", target)
                target_host = urllib.parse.urlsplit(
                    target if "://" in target else "https://" + target).hostname or ""
                osint_online._domain(target_host)
                if osint_online._is_blocked_name(target_host, client.blocked_targets):
                    return None
            else:
                cve = urllib.parse.parse_qs(parsed.query).get("cveId", [""])[0]
                client._guard_value("cve", cve)
            result = client._request(provider, url)  # fixed URLs built below; redirects remain checked
            return result.body.decode("utf-8", "replace")
        except Exception:
            return None

    return fetch


def _first_flag(text: str) -> Optional[str]:
    """Return one unambiguous, non-placeholder flag-shaped value.

    Challenge prose and rules pages often contain the format itself (``CSCTF{...}``) or multiple
    examples.  Picking the first regex match would turn documentation into a costly submission.
    """
    if not text:
        return None
    placeholders = {"...", "flag", "your_flag", "example", "example_flag",
                    "insert_flag_here", "replace_me", "redacted", "answer"}
    hits = []
    for match in FLAG_RE.finditer(text):
        value = match.group(0)
        body = value[value.find("{") + 1:-1].strip().casefold()
        if body in placeholders or set(body) <= {".", "*", "?", "_", "-"}:
            continue
        if body.startswith("<") and body.endswith(">"):
            continue                  # a format template: "Flag format: CSCTF{<answer>}" (B-088)
        if value not in hits:
            hits.append(value)
    return hits[0] if len(hits) == 1 else None


def _read_small_files(files_dir: Path, cap: int = 1_000_000, each: int = 256 * 1024) -> list[tuple[str, bytes]]:
    """Return (name, bytes) for each regular file under files_dir, smallest first, within a byte cap.

    Files are read as untrusted DATA only -- never executed, never imported."""
    out: list[tuple[str, bytes]] = []
    if files_dir is None:
        return out
    try:
        paths = [p for p in sorted(files_dir.rglob("*")) if p.is_file()]
    except OSError:
        return out
    paths.sort(key=lambda p: p.stat().st_size if p.exists() else 0)
    total = 0
    for p in paths:
        try:
            data = p.read_bytes()[:each]
        except OSError:
            continue
        out.append((p.name, data))
        total += len(data)
        if total >= cap:
            break
    return out


def _crib_flag(data: bytes) -> Optional[tuple[str, str]]:
    """Run the warmups auto-decoder; return (flag, chain) only if it surfaced a flag-format string."""
    if _crib is None:
        return None
    try:
        got = _crib.solve_blob(data)
    except Exception:
        return None
    if not got or not isinstance(got, tuple):
        return None
    if _crib.LAST.get("route") != "flag":
        return None
    # The warmup engine retains every flag-shaped reading.  Require one distinct value instead of
    # silently promoting its simplest/first path when the input carries competing answers.
    readings = _crib.LAST.get("flags") or []
    # Reversible transforms can manufacture longer-path alternatives (for example swapcase after a
    # valid base64 decode).  Compare only the engine's simplest tied readings; a unique shorter,
    # lossless path is evidence, while two values at the same minimum complexity are ambiguous.
    structured = [reading for reading in readings
                  if isinstance(reading, (tuple, list)) and len(reading) >= 2
                  and isinstance(reading[1], (tuple, list))]
    if structured:
        minimum = min(len(reading[1]) for reading in structured)
        readings = [reading for reading in structured if len(reading[1]) == minimum]
    values = []
    for reading in readings:
        candidate = reading[0] if isinstance(reading, (tuple, list)) and reading else reading
        exact = _first_flag(str(candidate or ""))
        if exact and exact not in values:
            values.append(exact)
    if not values:
        exact = _first_flag(str(got[0] or ""))
        values = [exact] if exact else []
    if len(values) != 1:
        return None
    flag = values[0]
    chains = got[1] if len(got) > 1 else []
    chain = "+".join(chains[0]) if chains and isinstance(chains[0], (list, tuple)) else "decode"
    return flag, (chain or "plain")


# =================================================================================================
# text tricks in the brief and on the rules page (B-208)
# =================================================================================================
def try_text_tricks(detail: dict, *, texts: Optional[list] = None, force: bool = False) -> Optional[dict]:
    """Read the hidden text channels (``ctf.texttricks``) of the brief, or of ``texts`` -- a list of
    ``(source, text)`` pairs such as fetched rules pages -- for the event's flag format.

    Returns a ``text-trick`` result with ``flag`` set when the channels across all the texts spell
    exactly one complete flag that is not printed in plain text; a flagless result carrying the first
    ``candidate`` and an instruction when a channel spells a prefix-led reading or a printable
    whitespace decode, or when there is a clue worth reading (hidden capitals, zero-width characters;
    plain acrostics too when ``force`` -- a rules/sanity challenge or a brief that hints at a text
    trick); else None. Every result carries ``text_tricks``: the per-source scans.

    The texts are untrusted DATA: only read for the flag format, never followed. Offline, no submit.
    Raises ctf.event.EventError when no event flag format resolves (no silent default)."""
    if texts is None:
        texts = [("description", detail.get("description") or "")]
    scans = [(src, _tt.scan(t)) for src, t in texts if t]
    if not scans:
        return None
    flags: dict[str, list[str]] = {}
    for src, s in scans:
        for value, chans in s.flags.items():
            flags.setdefault(value, []).extend(f"{c} ({src})" for c in chans)
    detail_of = {src: s.to_dict() for src, s in scans}
    if len(flags) == 1:
        value, where = next(iter(flags.items()))
        src = next(src for src, s in scans if value in s.flags)
        r = _result("text-trick", flag=value, confidence="high", source=src,
                    how=f"hidden text channel spells the flag: {', '.join(where)} (text read as data only)")
        r["text_tricks"] = detail_of
        return r
    candidates = []
    if len(flags) > 1:
        candidates += [{"value": v, "channel": ", ".join(w), "why": "one of several hidden-channel flags"}
                       for v, w in flags.items()]
    for src, s in scans:
        candidates += [dict(c, source=src) for c in s.candidates if c["value"] not in flags]
    worth = [(src, s) for src, s in scans if s.clues and (force or _tt.notable(s))]
    if not candidates and not worth:
        return None
    lines = [f"{src}: {s.summary()}" for src, s in scans if s.candidates or s.clues or s.flags]
    how = ("several flags spelled by hidden text channels (ambiguous, none chosen)" if len(flags) > 1
           else "hidden text channels give a reading to verify" if candidates
           else "hidden text channels give a clue to read")
    r = _result("text-trick", candidate=candidates[0]["value"] if candidates else None, how=how,
                confidence="medium" if candidates else "low",
                source=(candidates[0].get("source") if candidates else worth[0][0]),
                instruction=("verify by hand before any submit (an inferred prefix is not a flag): "
                             + " || ".join(lines)))
    r["candidates"] = candidates
    r["text_tricks"] = detail_of
    return r


def _with_text_tricks(res: dict, tt: Optional[dict]) -> dict:
    """Attach a flagless text-trick reading to a flagless sanity/welcome result: the candidate, the
    per-source scans, and the reading appended to the instruction so the player reads it first."""
    if not tt:
        return res
    if tt.get("candidate") and not res.get("candidate"):
        res["candidate"] = tt["candidate"]
    res["text_tricks"] = tt.get("text_tricks")
    if tt.get("candidates"):
        res["candidates"] = tt["candidates"]
    extra = f"text tricks: {tt['instruction']}"
    res["instruction"] = f"{res['instruction']}; {extra}" if res.get("instruction") else extra
    return res


# =================================================================================================
# class 1: sanity "read the rules"
# =================================================================================================
_RULES_PATHS = ("/rules", "/", "/welcome", "/info")


def _looks_sanity(detail: dict) -> bool:
    cat = (detail.get("category") or "").strip().lower()
    txt = _text_of(detail)
    if cat == "sanity":
        return True
    return any(w in txt for w in ("read the rules", "the rules", "rules page", "welcome", "sanity"))


def try_sanity(detail: dict, cfg: _config.Config, fetch: Callable[[str], Optional[str]],
               online: bool) -> Optional[dict]:
    # A flag sitting in the description is the most common sanity gift -- take it without any network.
    inline = _first_flag(detail.get("description") or "")
    if inline:
        return _result("sanity", flag=inline, how="flag printed in the challenge description",
                       confidence="high", source="description")
    if not _looks_sanity(detail):
        return None
    # B-208: a rules/sanity brief can spell its flag in an acrostic or a whitespace channel.
    desc_tt = try_text_tricks(detail, force=True)
    if desc_tt and desc_tt.get("flag"):
        return desc_tt
    if not online:
        return _with_text_tricks(
            _result("sanity", how="sanity/rules challenge; rules page not fetched (offline)",
                    confidence="low",
                    instruction=f"read the rules page at {cfg.base_url}/rules and look for a flag in the event's format"),
            desc_tt)
    pages: list[tuple[str, str]] = []
    for path in _RULES_PATHS:
        url = cfg.base_url + path
        try:
            body = fetch(url)
        except NotSupported as e:
            return _with_text_tricks(
                _result("sanity", how=f"sanity/rules challenge; rules page not fetched: {e}",
                        confidence="low",
                        instruction=f"open {cfg.base_url}/rules in a browser and read for the flag"),
                desc_tt)
        flag = _first_flag(body or "")
        if flag:
            return _result("sanity", flag=flag, how=f"CSCTF flag found on the rules page ({path})",
                           confidence="high", source=url)
        if body:
            pages.append((url, body))
    # B-208: no flag printed on any page -- read the pages' hidden channels (first letter of every
    # bullet, line initials, capitals, whitespace). The pages are untrusted data, only read.
    page_tt = try_text_tricks(detail, texts=[("description", detail.get("description") or "")] + pages,
                              force=True) if pages else desc_tt
    if page_tt and page_tt.get("flag"):
        return page_tt
    return _with_text_tricks(
        _result("sanity", how="looks like a rules/sanity challenge but no flag on the fetched pages",
                confidence="low",
                instruction=f"open {cfg.base_url}/rules in a browser and read for the flag"),
        page_tt)


# =================================================================================================
# the welcome / zero-file / platform-profile auto-trigger (B-041)
# =================================================================================================
# The classes intake auto-runs the fast lane on at intake (ctf/intake/__init__.py): a welcome/intro
# "freebie" that prints its flag in the brief itself, a rules/sanity page, and a CTFd team-profile /
# learning-platform challenge whose answer the player reveals by filling in their profile or finishing
# a lesson. Detection is by name/category (not loose description prose, so a normal challenge that
# merely quotes the format or "the rules" in its body is never force-promoted); the inline-flag
# recovery below is offline and deterministic -- it never touches the network and never submits.
_WELCOME_WORDS = ("welcome", "getting started", "get started", "start here",
                  "introduction", "intro challenge", "first challenge")
_RULES_WORDS = ("read the rules", "the rules", "rules page", "sanity")
_PROFILE_WORDS = ("team profile", "your profile", "profile page", "update your profile",
                  "edit your profile", "where u from", "where you from", "set your country")


def _name_of(detail: dict) -> str:
    """The challenge NAME, lower-cased: the string the fast-lane word lists are matched against.

    The class signal is the name (plus the ``sanity`` category, checked separately in ``welcome_class``),
    never loose description prose. A welcome/sanity/profile challenge announces itself in its title, so a
    normal challenge whose body merely quotes ``the rules`` or ``your profile`` next to one flag-shaped
    value is NOT classed welcome and its brief flag is not force-promoted (B-041 finding 2). The brief
    still supplies the inline flag value itself, via ``_first_flag`` on the description -- the name
    governs only the class trigger."""
    return (detail.get("name") or "").lower()


def _looks_platform_profile(detail: dict) -> bool:
    """A CTFd team-profile / platform-settings challenge, by NAME: the flag is revealed once the player
    fills in their profile on the event platform (always a human step; no scripted profile write)."""
    return any(w in _name_of(detail) for w in _PROFILE_WORDS)


def welcome_class(detail: dict) -> Optional[str]:
    """The fast-lane auto-trigger class of a challenge -- ``"platform-profile"``, ``"sanity"`` or
    ``"welcome"`` -- or ``None`` when it is not one intake should auto-run the fast lane on.

    The class is decided from the NAME and CATEGORY only (never loose description prose, see
    ``_name_of``): a profile challenge first (its answer is a platform step), then a rules/sanity
    challenge (the ``sanity`` category or rules wording in the name), then an intro/welcome one by name
    wording. Whether the challenge ships files does not change the class; ``try_welcome`` records the
    zero-file fact separately."""
    if _looks_platform_profile(detail):
        return "platform-profile"
    name = _name_of(detail)
    cat = (detail.get("category") or "").strip().lower()
    if cat == "sanity" or any(w in name for w in _RULES_WORDS):
        return "sanity"
    if any(w in name for w in _WELCOME_WORDS):
        return "welcome"
    return None


def _has_files(files_dir) -> bool:
    """True when the challenge ships at least one handout file under ``files_dir``.

    A welcome / sanity / platform-profile challenge is typically *zero-file* -- the answer is printed
    in the brief or is a platform step -- so ``try_welcome`` records this fact (``zero_file``) to make
    the item's zero-file angle an explicit discriminator. When such a challenge does ship files, the
    encoding-chain decode stage (``ctf/intake/decode.py``) owns those blobs; ``try_welcome`` adds only
    the inline-brief flag either way."""
    if files_dir is None:
        return False
    try:
        return any(p.is_file() for p in Path(files_dir).rglob("*"))
    except OSError:
        return False


def _welcome_instruction(klass: str, base_url: Optional[str]) -> str:
    where = base_url or "the event platform"
    if klass == "platform-profile":
        return (f"fill in your team/player profile on {where} and read the flag it reveals, then submit "
                "it by hand (no scripted platform-profile write is on record)")
    if klass == "sanity":
        return (f"open the rules/welcome page on {where}, read for a flag in the event format, then "
                "submit it by hand")
    return (f"read the challenge page / lesson on {where} for a flag in the event format, then submit "
            "it by hand")


def try_welcome(detail: dict, files_dir=None, *, base_url: Optional[str] = None) -> Optional[dict]:
    """The B-041 auto-trigger: the OFFLINE fast lane for a welcome / zero-file / platform-profile
    challenge. Returns ``None`` when the challenge is not such a class.

    Otherwise it recovers a flag printed in the brief itself (the most common welcome freebie)
    deterministically, with no network: exactly one unambiguous, non-placeholder flag-format value in
    the description (``_first_flag``). When there is none, it returns a flagless instruction naming the
    human step on the event platform (the rules page, a CTFd profile, a learning-platform lesson),
    which is never scripted.

    It NEVER reaches the network and NEVER submits. The encoding-chain decode of brief blobs and
    handout files is intake's own fastlane decode stage (ctf/intake/decode.py); this adds only the
    inline-brief flag that intake would otherwise drop as brief-quoted template text, and the human
    step. The brief is untrusted DATA (read, never executed).

    ``files_dir`` is used to record the item's zero-file angle: the result carries ``zero_file`` (True
    when the challenge ships no handout file), so a caller can tell a zero-file welcome freebie -- the
    inline-brief case this path recovers -- from a with-files one the decode stage also covers."""
    klass = welcome_class(detail)
    if klass is None:
        return None
    zero_file = not _has_files(files_dir)
    inline = _first_flag(detail.get("description") or "")
    # B-208: no printed flag -- read the brief's hidden channels (acrostic, initials, whitespace).
    tt = None if inline else try_text_tricks(detail, force=True)
    if inline:
        res = _result(klass, flag=inline,
                      how="flag printed in the challenge description (welcome auto-trigger)",
                      confidence="high", source="description")
    elif tt and tt.get("flag"):
        res = _result(klass, flag=tt["flag"], how=f"{tt['how']} (welcome auto-trigger)",
                      confidence="high", source="description")
        res["text_tricks"] = tt.get("text_tricks")
    else:
        res = _with_text_tricks(
            _result(klass, how=f"{klass} challenge; no flag in the brief, the answer is a platform step",
                    confidence="low", instruction=_welcome_instruction(klass, base_url)),
            tt)
    res["zero_file"] = zero_file
    return res


# =================================================================================================
# class 2: encoding-chain crypto (CyberChef-style)
# =================================================================================================
def _encoded_blobs_from_desc(desc: str) -> list[bytes]:
    """Long encoded-looking tokens in the brief, plus the whole brief as a fallback blob, plus what the
    brief's hidden text channels spell (B-208): every printable whitespace / zero-width decode, and any
    acrostic reading that carries braces. Those go through the same decoders and guards as any blob,
    so a base64 written in trailing whitespace is decoded too. Profile-free (no flag format needed)."""
    blobs: list[bytes] = []
    for m in _ENCODED_RE.findall(desc or ""):
        if len(m) >= 16:
            blobs.append(m.encode())
    stripped = (desc or "").strip()
    if stripped:
        blobs.append(stripped.encode())
    for r in _tt.readings(desc or ""):
        if r.channel in _tt.DECODED or (r.channel in _tt.ACROSTIC and "{" in r.text and "}" in r.text):
            b = r.text.encode("utf-8", "replace")
            if b not in blobs:
                blobs.append(b)
    return blobs


def try_encoding(detail: dict, files_dir: Path) -> Optional[dict]:
    if _crib is None:
        return None
    # 1) attached files (the usual Chef-style blob delivery)
    for name, data in _read_small_files(files_dir):
        hit = _crib_flag(data)
        if hit:
            flag, chain = hit
            return _result("encoding", flag=flag, how=f"auto-decoded {name} via {chain}",
                           confidence="high", source=name)
    # 2) an encoded blob pasted into the description
    for blob in _encoded_blobs_from_desc(detail.get("description") or ""):
        hit = _crib_flag(blob)
        if hit:
            flag, chain = hit
            return _result("encoding", flag=flag, how=f"auto-decoded description blob via {chain}",
                           confidence="high", source="description")
    return None


# =================================================================================================
# class 3: 50-pt OSINT lookups
# =================================================================================================
_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)
_URL_RE = re.compile(r"https?://[^\s'\"<>)]+", re.I)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_ATTCK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _target_url_or_domain(text: str) -> Optional[str]:
    m = _URL_RE.search(text)
    if m:
        return m.group(0)
    m = _DOMAIN_RE.search(text)
    return m.group(1) if m else None


def _wayback_first_capture(target: str, fetch: Callable[[str], Optional[str]]) -> Optional[dict]:
    """The CDX API, one call, earliest capture. Deterministic date -> answer."""
    q = urllib.parse.urlencode({
        "url": target, "output": "json", "fl": "timestamp,original",
        "limit": "1", "from": "19960101",
    })
    url = f"https://web.archive.org/cdx/search/cdx?{q}"
    body = fetch(url)
    if not body:
        return _result("osint:wayback", how="Wayback CDX returned nothing", confidence="low", source=url,
                       instruction=f"query the Wayback CDX API: {url}")
    try:
        rows = json.loads(body)
    except ValueError:
        return _result("osint:wayback", how="Wayback CDX body was not JSON", confidence="low", source=url,
                       instruction=f"query the Wayback CDX API: {url}")
    # rows[0] is the header ["timestamp","original"]; rows[1] is the first capture.
    if isinstance(rows, list) and len(rows) >= 2 and rows[1]:
        ts = str(rows[1][0])
        if len(ts) >= 8 and ts[:8].isdigit():
            date = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
            return _result("osint:wayback", candidate=date,
                           how=f"first Wayback capture of {target} = {ts}",
                           confidence="medium", source=url,
                           instruction=("verify the capture row and exact requested date format; "
                                        f"candidate value: {date}"))
    return _result("osint:wayback", how="no capture found for the target", confidence="low", source=url,
                   instruction=f"query the Wayback CDX API: {url}")


def _nvd_cve(cve: str, text: str, fetch: Callable[[str], Optional[str]]) -> Optional[dict]:
    """One NVD 2.0 API call for a CVE. Returns the CVSS base score when the brief asks for a score."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve.upper()}"
    wants_score = any(w in text for w in ("cvss", "base score", "severity score", "score"))
    body = fetch(url)
    if not body:
        return _result("osint:nvd", how=f"NVD lookup for {cve.upper()} returned nothing",
                       confidence="low", source=url,
                       instruction=f"open the NVD record: https://nvd.nist.gov/vuln/detail/{cve.upper()}")
    try:
        doc = json.loads(body)
    except ValueError:
        return _result("osint:nvd", how="NVD body was not JSON", confidence="low", source=url,
                       instruction=f"open the NVD record: https://nvd.nist.gov/vuln/detail/{cve.upper()}")
    score = None
    try:
        metrics = doc["vulnerabilities"][0]["cve"]["metrics"]
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0]["cvssData"]["baseScore"]
                break
    except (KeyError, IndexError, TypeError):
        score = None
    if wants_score and score is not None:
        return _result("osint:nvd", candidate=str(score),
                       how=f"NVD CVSS base score for {cve.upper()} = {score}",
                       confidence="medium", source=url,
                       instruction=("confirm which CVSS version/field the brief wants; "
                                    f"candidate value: {score}"))
    return _result("osint:nvd",
                   how=f"NVD record fetched for {cve.upper()}" + (f" (base score {score})" if score is not None else ""),
                   confidence="medium", source=url,
                   instruction=f"read the NVD record for the exact field asked: https://nvd.nist.gov/vuln/detail/{cve.upper()}")


def try_osint(detail: dict, cfg: _config.Config, fetch: Callable[[str], Optional[str]],
              online: bool, *, profile=None,
              brief_fetch: Optional[Callable[[str], Optional[str]]] = None) -> Optional[dict]:
    """The OSINT lookup branches. The keyword branches (ATT&CK, NVD, Wayback, HIBP, web-check) use
    ``fetch`` (the allow-listed public client); the last, the brief-URL branch (B-088,
    ``ctf.brieffield.try_brief_url``), reads a named field off a site the brief names, with one
    scope-checked GET (``brief_fetch`` when injected; the scope check runs first either way)."""
    txt = _text_of(detail)
    desc = detail.get("description") or ""

    # -- MITRE ATT&CK technique: emit the authoritative source (final mapping is human judgment) -----
    if any(w in txt for w in ("att&ck", "attack technique", "mitre")) or _ATTCK_RE.search(desc):
        m = _ATTCK_RE.search(desc)
        if m:
            tid = m.group(0)
            sub = tid.split(".")
            page = (f"https://attack.mitre.org/techniques/{sub[0]}/{sub[1]}/"
                    if len(sub) == 2 else f"https://attack.mitre.org/techniques/{tid}/")
            return _result("osint:mitre", how=f"MITRE ATT&CK technique {tid}", confidence="medium",
                           source=page, instruction=f"read the ATT&CK page for {tid}: {page}")
        return _result("osint:mitre", how="MITRE ATT&CK lookup", confidence="low",
                       source="https://attack.mitre.org/techniques/",
                       instruction="identify the technique ID from the brief, then read its ATT&CK page")

    # -- CVE / VulnDB: NVD is a direct, deterministic fetch for a score ------------------------------
    cve = _CVE_RE.search(desc)
    if cve or any(w in txt for w in ("nvd", "vulndb", "cvss", "national vulnerability")):
        if cve and online:
            return _nvd_cve(cve.group(0), txt, fetch)
        if cve:
            return _result("osint:nvd", how=f"CVE lookup for {cve.group(0).upper()} (offline)",
                           confidence="low",
                           source=f"https://nvd.nist.gov/vuln/detail/{cve.group(0).upper()}",
                           instruction=f"open https://nvd.nist.gov/vuln/detail/{cve.group(0).upper()}")
        return _result("osint:nvd", how="vulnerability-DB lookup", confidence="low",
                       instruction="extract the CVE id from the brief and look it up on NVD")

    # -- Wayback "first capture / first archived" : CDX API is a direct, deterministic fetch ---------
    if any(w in txt for w in ("wayback", "web archive", "first archived", "first capture",
                              "first snapshot", "archived")):
        target = _target_url_or_domain(desc)
        if target and online:
            return _wayback_first_capture(target, fetch)
        if target:
            return _result("osint:wayback", how=f"Wayback first-capture of {target} (offline)",
                           confidence="low",
                           instruction=f"query the Wayback CDX API for the earliest capture of {target}")
        return _result("osint:wayback", how="Wayback first-capture lookup", confidence="low",
                       instruction="find the target URL in the brief, then query the Wayback CDX API")

    # -- HIBP / Pwned: needs an API key -> human-driven ---------------------------------------------
    if any(w in txt for w in ("have i been pwned", "haveibeenpwned", "hibp", "pwned", "breach")):
        return _result("osint:hibp", how="Have I Been Pwned lookup", confidence="low",
                       source="https://haveibeenpwned.com/",
                       instruction="look the account/domain up on HIBP (needs the player's API key)")

    # -- web-check / WHOIS / DNS / cert : recon tools, human reads the result ------------------------
    if any(w in txt for w in ("web-check", "webcheck", "whois", "dns record", "cert transparency",
                              "certificate transparency", "subdomain")):
        target = _target_url_or_domain(desc)
        tgt = f" for {target}" if target else ""
        return _result("osint:webcheck", how=f"web-check / WHOIS / DNS recon{tgt}", confidence="low",
                       source=(f"https://web-check.xyz/results/{target}" if target else "https://web-check.xyz/"),
                       instruction=f"run web-check / whois / crt.sh{tgt} and read the answer field the brief names")

    # -- brief URL + a named field (B-088): one scope-checked GET, label/value matched to the noun ----
    from . import brieffield
    return brieffield.try_brief_url(detail, profile=profile, fetch=brief_fetch, online=online)


# =================================================================================================
# class 4: race / TOCTOU burst (B-048)
# =================================================================================================
# Keywords that mark a race / two-person-rule / TOCTOU challenge. Used only to shape a flagless
# instruction when no live race plan was handed in; the actual burst NEVER fires without an explicit
# operator-supplied plan + a scope-locked client_factory (so the lane can never auto-burst a target).
_RACE_WORDS = (
    "two-person rule", "two person rule", "two-key", "two key turn", "dual control",
    "dual-control", "race condition", "toctou", "time-of-check", "double spend", "double-spend",
    "simultaneous", "concurrent approv", "two distinct", "both approvers", "second approver",
    "pending window", "approval window",
)


def _looks_race(detail: dict) -> bool:
    cat = (detail.get("category") or "").strip().lower()
    txt = _text_of(detail)
    return cat == "web" and any(w in txt for w in _RACE_WORDS)


def _race_transition_summary(report: Optional[dict]) -> str:
    """A compact, credential-free one-line trace of the observed state transitions."""
    if not isinstance(report, dict):
        return ""
    steps = []
    for row in report.get("transitions") or []:
        frm = row.get("from")
        arrow = f"{frm} -> {row.get('to')}" if frm else str(row.get("to"))
        steps.append(f"#{row.get('attempt')} {arrow} (ok {row.get('ok_count')}/{report.get('width')})")
    return "; ".join(steps)


def try_race(detail: dict, cfg: _config.Config, *, client_factory=None,
             plan: Optional[dict] = None, online: bool = True,
             clock=None, sleep=None) -> Optional[dict]:
    """Race a two-person-rule / TOCTOU approval by bursting N simultaneous requests (B-048).

    The burst only fires when the caller passes BOTH an explicit ``plan`` (the deterministic
    approve-route recipe derived from a live ``GET /schema``) AND a scope-locked
    ``client_factory``; otherwise this returns a flagless instruction (or None). It NEVER
    submits and NEVER guesses: a flag is returned only when a burst drives the resource into the
    operator's ``success_state`` and the authoritative readback actually contains a flag-format
    value. The result carries a ``race`` key with the credential-free state-transition report."""
    if not (plan or _looks_race(detail)):
        return None
    instruct = ("read GET /schema for the approve/confirm route and operator credential, then burst "
                "~6-8 simultaneous requests inside the pending window "
                "(solvers/web/double_spend.run_race_plan)")
    if not online:
        return _result("race", how="race / TOCTOU challenge; not run (offline)",
                       confidence="low", instruction=instruct)
    if not plan or not client_factory:
        return _result("race", how="race / TOCTOU challenge; no live race plan + client provided",
                       confidence="low", instruction=instruct)
    ds = _double_spend()
    if ds is None:
        return _result("race", how="race/TOCTOU burst engine unavailable (double_spend import failed)",
                       confidence="low", instruction=instruct)
    outcome = ds.run_race_plan(client_factory, plan, clock=clock, sleep=sleep)
    report = outcome.get("report")
    trace = _race_transition_summary(report)
    route = str(plan.get("route") or "")
    success_state = str(plan.get("success_state") or "")
    field = outcome.get("payoff_field")
    base_how = f"raced {route} ({(report or {}).get('mode', plan.get('mode') or 'separate')} burst"
    if trace:
        base_how += f"; {trace}"
    base_how += ")"
    if outcome.get("won"):
        flag = _first_flag(outcome.get("payoff_text") or "")
        if flag:
            r = _result("race", flag=flag, how=f"{base_how} -> {outcome.get('state')}",
                        confidence="high", source=route or None)
            r["race"] = report
            return r
        # Won the state transition but no flag-format value surfaced: hand the operator the field.
        candidate = (outcome.get("payoff_text") or "").strip()[:256] or None
        r = _result("race", candidate=candidate,
                    how=f"{base_how} reached {outcome.get('state')} but no flag-format value in the readback",
                    confidence="medium", source=route or None,
                    instruction=(f"read the '{field}' field of the readback for the flag" if field
                                 else "read the arming/authorization field of the readback for the flag"))
        r["race"] = report
        return r
    r = _result("race",
                how=f"{base_how} did not reach {success_state or 'the target state'} "
                    f"(stopped: {outcome.get('stopped') or outcome.get('error')})",
                confidence="low",
                instruction="raise width/retries, confirm the approve route and credential, or try mode='single-packet'")
    r["race"] = report
    return r


# =================================================================================================
# class 5: shipped-client constants (B-131)
# =================================================================================================
CLIENT_SCAN_BYTES = 64 * 1024 * 1024   # bytes of the handout read for client constants (the lane stays fast)


def try_shipped_client(detail: dict, files_dir) -> Optional[dict]:
    """A flagless hand-off when the handout ships a client with a hard-coded custom User-Agent (B-131).

    The files are read as data for User-Agent and URL constants (ctf.clientreplay.harvest: raw disk
    images and zip members included), within CLIENT_SCAN_BYTES. Nothing is fetched here: replaying
    the User-Agent against the client's URLs and their links is a crawl, not the single lookup this
    lane allows, so the result is an instruction naming the command that does it under the event's
    scope guard. None when no file states a custom User-Agent directly (a `nearby` one, passed by
    variable, is the engine's to list, not this lane's to stake a hand-off on). A handout that cannot
    be read is not a quiet None: the reason is logged as a warning (ctf.fastlane) before the lane
    moves on, so "no shipped client" and "could not look" stay apart."""
    if files_dir is None or not Path(files_dir).is_dir():
        return None
    from . import clientreplay
    try:
        h = clientreplay.harvest([files_dir], max_bytes=CLIENT_SCAN_BYTES)
    except (clientreplay.ReplayError, OSError) as e:
        _log.warning("fastlane: the shipped-client check did not run on %s: %s: %s (run "
                     "`python -m ctf client-replay harvest` on it to see why)", files_dir, type(e).__name__, e)
        return None
    direct = [c for c in h.custom_user_agents() if c.how == "direct"]
    if not direct:
        return None
    first = direct[0]
    urls = [c.value for c in h.client_urls()]
    how = (f"the handout ships a client with a hard-coded User-Agent {first.value!r} ({first.path})"
           + (f" and {len(urls)} URL(s) beside it ({', '.join(urls[:3])})" if urls else ""))
    if h.truncated:
        how += f"; only the first {CLIENT_SCAN_BYTES} bytes were read"
    return _result("client-replay", how=how, confidence="low", source=first.path,
                   instruction=("replay that User-Agent against the client's in-scope URLs and their "
                                "first-level links, and compare with a normal request: "
                                "python -m ctf client-replay run <workspace_dir>"))


# =================================================================================================
# top-level
# =================================================================================================
def try_solve(detail: dict, files_dir, *, cfg: Optional[_config.Config] = None,
              fetch: Optional[Callable[[str], Optional[str]]] = None,
              online: bool = True, race: Optional[dict] = None,
              race_client_factory=None) -> Optional[dict]:
    """Try the fast-lane classes in order; return the first hit (flag preferred) or None.

    ``detail``    : the CTFd challenge detail (name, category, description, value, ...).
    ``files_dir`` : the challenge's ``files/`` directory (untrusted data; read, never executed).
    ``fetch``     : optional ``url -> body|None`` for lookups (injected in tests); default is a capped GET.
    ``online``    : when False, no network lookup is made (encoding + inline-flag checks still run).
    ``race``      : optional deterministic race plan (B-048); fires only alongside ``race_client_factory``.
    ``race_client_factory`` : a scope-locked client factory for the race burst (injected; never default).

    A returned dict has ``flag`` set only when the answer was derived deterministically. The lane
    NEVER submits and NEVER guesses -- a ``None`` or a flagless instruction means "hand to a solver".
    """
    cfg = cfg or _config.load()
    files_dir = Path(files_dir) if files_dir is not None else None   # OSINT/sanity challenges have no files
    injected_fetch = fetch is not None
    platform_fetch = fetch or _default_fetch(cfg)
    public_fetch = fetch if injected_fetch else _public_osint_fetch()

    # 0) race / TOCTOU burst (B-048): most time-critical, so it runs first -- but ONLY when the caller
    #    handed in an explicit plan + scope-locked client_factory (it can never auto-burst a target).
    if race and race_client_factory is not None:
        r = try_race(detail, cfg, client_factory=race_client_factory, plan=race, online=online)
        if r and r.get("flag"):
            return r
        race_instruction = r
    else:
        race_instruction = None

    # 1) sanity / inline flag -- cheapest, often zero-network.
    r = try_sanity(detail, cfg, platform_fetch, online)
    if r and r.get("flag"):
        return r
    sanity_instruction = r  # keep a flagless sanity instruction as a fallback

    # 1b) text tricks in the brief (B-208, offline): acrostics, initials, capitals, whitespace. A sanity
    #     challenge's brief was already read by try_sanity; this covers every other brief.
    text_hint = None
    if sanity_instruction is None:
        r = try_text_tricks(detail, force=_hints_text_trick(detail))
        if r and r.get("flag"):
            return r
        text_hint = r

    # 2) encoding-chain crypto (fully offline).
    r = try_encoding(detail, files_dir)
    if r and r.get("flag"):
        return r

    # 3) OSINT 50-pt lookups.
    r = try_osint(detail, cfg, public_fetch, online, brief_fetch=fetch if injected_fetch else None)
    if r and (r.get("flag") or r.get("instruction")):
        return r

    # A flagless race result (e.g. a near-miss report, or a race-looking challenge with no live plan)
    # is a more specific hand-off than a generic sanity instruction, so prefer it; then a text-trick hint
    # from the brief (B-208). Last, and only when nothing else matched: a shipped client's hard-coded
    # User-Agent (B-131), read offline.
    return race_instruction or sanity_instruction or text_hint or try_shipped_client(detail, files_dir)  # may be None


# =================================================================================================
# CLI
# =================================================================================================
def _load_detail(ws: Path) -> dict:
    cj = ws / "challenge.json"
    if cj.exists():
        return json.loads(cj.read_text(encoding="utf-8"))
    raise SystemExit(f"no challenge.json in {ws}")


def report(ws: Path, online: bool = True) -> int:
    detail = _load_detail(ws)
    files_dir = ws / "files"
    res = try_solve(detail, files_dir, online=online)
    name = detail.get("name", "?")
    cat = detail.get("category", "?")
    print(f"[fastlane] {name}  [{cat}]")
    if res is None:
        print("  no fast-lane class matched -> hand to a solver")
        return 1
    print(f"  class      : {res['klass']}")
    print(f"  confidence : {res['confidence']}")
    if res.get("how"):
        print(f"  how        : {res['how']}")
    if res.get("source"):
        print(f"  source     : {res['source']}")
    if res.get("candidate"):
        print(f"  CANDIDATE  : {res['candidate']}  (human verification required)")
    if res.get("flag"):
        print(f"  FLAG       : {res['flag']}")
        return 0
    if res.get("instruction"):
        print(f"  next       : {res['instruction']}")
    return 2


def main(argv: list[str]) -> int:
    online = True
    args = []
    for a in argv:
        if a in ("--offline", "-O"):
            online = False
        else:
            args.append(a)
    if not args:
        print("usage: python -m ctf.fastlane <workspace_dir> [--offline]", file=sys.stderr)
        return 64
    return report(Path(args[0]), online=online)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
