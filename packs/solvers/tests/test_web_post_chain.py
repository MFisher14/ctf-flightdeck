#!/usr/bin/env python3
"""Local-fake regression for the observed Web D11--D13 POST-chain solver.

No network is used.  The fakes model the saved target contracts for Template
Temper, Ask Again Later, and Posted Too Much, including their misleading generic
POST acknowledgements and mixed-Mastery nonmatching targets.
"""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import json
import os
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import post_chain as PC  # noqa: E402


FAILED = []
COUNT = [0]


def check(label, condition, detail=""):
    COUNT[0] += 1
    print(("ok   " if condition else "FAIL ") + label + ("" if condition else f"  <- {detail!r}"))
    if not condition:
        FAILED.append(label)


def proof():
    return "proof_" + uuid.uuid4().hex


def response(status, body, path="/"):
    if not isinstance(body, (bytes, bytearray)):
        body = str(body).encode("utf-8")
    content_type = ("application/json" if bytes(body).lstrip()[:1] in (b"{", b"[")
                    else "text/html; charset=utf-8")
    return {"status": status, "body": bytes(body),
            "response_headers": {"Content-Type": content_type},
            "final_url": "http://fake.local" + path}


class FakeBase:
    def __init__(self):
        self.base = "http://fake.local/"
        self.log = []
        self.timeout = 8.0

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        headers = dict(headers or {})
        self.log.append({"method": method, "path": path, "data": data,
                         "headers": headers, "redirects": allow_redirects})
        return self.handle(method, path, data, headers)

    def handle(self, method, path, data, headers):
        raise NotImplementedError

    @property
    def posts(self):
        return [row for row in self.log if row["method"] == "POST"]


class TemplateServer(FakeBase):
    def __init__(self, answer=None, *, echo=False, root_decoy=None,
                 syntax="curly", field="template", encoding="form", framework="Spring Boot",
                 surround_product=False):
        super().__init__()
        self.answer = answer or proof()
        self.echo = echo
        self.root_decoy = root_decoy
        self.syntax = syntax
        self.field = field
        self.encoding = encoding
        self.framework = framework
        self.surround_product = surround_product
        self.feature = "/process-fbda5a"

    @staticmethod
    def expression(syntax, value):
        pairs = {
            "curly": ("{{", "}}"),
            "dollar": ("${", "}"),
            "hash": ("#{", "}"),
            "erb": ("<%= ", " %>"),
        }
        prefix, suffix = pairs[syntax]
        return prefix + value + suffix

    def handle(self, method, path, data, headers):
        if method == "GET" and path == "/":
            extra = self.root_decoy or ""
            return response(200, "<title>Message Mill · Spring Boot</title>" + extra, path)
        if method == "GET" and path == "/api/clues":
            clues = {"current_role": "analyst", "framework": self.framework,
                     "feature_route": self.feature}
            if self.field != "template":
                clues["template_field"] = self.field
            if self.encoding != "form":
                clues["content_type"] = "application/json"
            return response(200, json.dumps(clues), path)
        if method == "GET" and path == self.feature:
            return response(200, "<article><h1>Rendered message</h1><pre></pre></article>", path)
        if method == "POST" and path == self.feature:
            ctype = headers.get("Content-Type", "")
            if "json" in ctype:
                got_encoding = "json"
                try:
                    values = json.loads(data or "{}")
                except Exception:
                    values = {}
            else:
                got_encoding = "form"
                values = dict(urllib.parse.parse_qsl(data or "", keep_blank_values=True))
            value = values.get(self.field, "")
            if self.echo:
                rendered = value
            elif got_encoding != self.encoding:
                rendered = value
            elif value == self.expression(self.syntax, "objective"):
                rendered = self.answer
            else:
                expected = self.expression(self.syntax, "7213*4567")
                rendered = str(7213 * 4567) if value == expected else str(value)
            surround = f"<p>debug {7213 * 4567}</p>" if self.surround_product else ""
            return response(200, f"<article><h1>Rendered message</h1>{surround}<pre>{rendered}</pre></article>", path)
        return response(404, '{"error":"not_found"}', path)


class SecondOrderServer(FakeBase):
    def __init__(self, answer=None, *, effect="delayed_query_revealed_private_row", ack_decoy=None,
                 filter_field="filter", encoding="json", winning_payload="' OR 1=1-- -"):
        super().__init__()
        self.answer = answer or proof()
        self.effect = effect
        self.ack_decoy = ack_decoy
        self.filter_field = filter_field
        self.encoding = encoding
        self.winning_payload = winning_payload
        self.feature = "/submit-e89284"
        self.secondary = "/result-725403"
        self.injected = False

    def handle(self, method, path, data, headers):
        if method == "GET" and path == "/":
            return response(200, "<title>Report Replay · Sinatra</title>", path)
        if method == "GET" and path == "/api/clues":
            clues = {"framework": "Sinatra", "feature_route": self.feature,
                     "secondary_route": self.secondary, "current_role": "analyst"}
            if self.filter_field != "filter":
                clues["filter_parameter"] = self.filter_field
            if self.encoding == "form":
                clues["content_type"] = "application/x-www-form-urlencoded"
            return response(200, json.dumps(clues), path)
        if method == "GET" and path == self.feature:
            return response(405, '{"error":"post_required"}', path)
        if method == "GET" and path == self.secondary:
            rows = ["Ordinary workspace note"]
            if self.injected:
                rows.append(self.answer)
            return response(200, json.dumps({"rows": rows, "effect": self.effect}), path)
        if method == "POST" and path == self.feature:
            if self.encoding == "json" and headers.get("Content-Type") == "application/json":
                try:
                    doc = json.loads(data or "{}")
                except Exception:
                    doc = {}
            elif self.encoding == "form" and "x-www-form-urlencoded" in headers.get("Content-Type", ""):
                doc = dict(urllib.parse.parse_qsl(data or "", keep_blank_values=True))
            else:
                doc = {}
            self.injected = doc.get(self.filter_field) == self.winning_payload
            ack = {"ok": True, "saved": True}
            if self.ack_decoy:
                ack["evidence"] = self.ack_decoy
            return response(201, json.dumps(ack), path)
        return response(404, '{"error":"not_found"}', path)


class MassAssignmentServer(FakeBase):
    def __init__(self, answer=None, *, winning_field="is_admin", root_decoy=None):
        super().__init__()
        self.answer = answer or proof()
        self.winning_field = winning_field
        self.root_decoy = root_decoy
        self.feature = "/inspect-12990e"
        self.secondary = "/audit-b370ea"
        self.admin = False

    def handle(self, method, path, data, headers):
        if method == "GET" and path == "/":
            return response(200, "<title>Profile Binder · NestJS</title>" + (self.root_decoy or ""), path)
        if method == "GET" and path == "/api/clues":
            return response(200, json.dumps({"framework": "NestJS", "feature_route": self.feature,
                                             "secondary_route": self.secondary,
                                             "current_role": "analyst"}), path)
        if method == "GET" and path == self.feature:
            return response(405, '{"error":"post_required"}', path)
        if method == "GET" and path == self.secondary:
            if not self.admin:
                return response(403, '{"error":"administrator_required"}', path)
            return response(200, json.dumps({"ok": True, "effect": "bound_privileged_property",
                                             "evidence": self.answer}), path)
        if method == "POST" and path == self.feature:
            try:
                doc = json.loads(data or "{}")
            except Exception:
                doc = {}
            value = doc.get(self.winning_field)
            if self.winning_field == "role":
                self.admin = value == "administrator"
            else:
                self.admin = value is True
            # Deliberately indistinguishable for every candidate.  The solver
            # must read the secondary route and must not stop on this ack.
            return response(201, '{"ok":true,"saved":true}', path)
        return response(404, '{"error":"not_found"}', path)


class MultipartMassAssignmentServer(MassAssignmentServer):
    def __init__(self, *, split):
        super().__init__()
        self.split = split

    def handle(self, method, path, data, headers):
        if method == "GET" and path == self.secondary and self.admin:
            doc = {"ok": True, "effect": "bound_privileged_property",
                   "administrator": True}
            if not self.split:
                doc["evidence"] = self.answer
            boundary = "mass-assignment-carriers"
            plain = self.answer if self.split else "diagnostic only"
            body = (f"--{boundary}\r\nContent-Type: text/plain\r\n\r\n{plain}\r\n"
                    f"--{boundary}\r\nContent-Type: application/json\r\n\r\n"
                    + json.dumps(doc, separators=(",", ":")) + "\r\n"
                    f"--{boundary}--\r\n").encode()
            return {"status": 200, "body": body,
                    "response_headers": {"Content-Type": f"multipart/mixed; boundary={boundary}"},
                    "final_url": "http://fake.local" + path}
        return super().handle(method, path, data, headers)


class UnrelatedServer(FakeBase):
    def __init__(self, clue=None, clue_status=200):
        super().__init__()
        self.clue = clue
        self.clue_status = clue_status

    def handle(self, method, path, data, headers):
        if method == "GET" and path == "/":
            return response(200, "<title>Pocket SOC</title>", path)
        if method == "GET" and path == "/api/clues":
            if self.clue is None:
                return response(404, '{"error":"not_found"}', path)
            return response(self.clue_status, json.dumps(self.clue), path)
        return response(404, '{"error":"not_found"}', path)


class FailedSSTIDecoyServer(TemplateServer):
    """Expose the eventual answer only in a losing confirmation header first."""

    def __init__(self):
        super().__init__(syntax="dollar")

    def handle(self, method, path, data, headers):
        result = super().handle(method, path, data, headers)
        if method == "POST" and "%7B%7B7213%2A4567%7D%7D" in str(data or ""):
            result["response_headers"]["X-Debug-Proof"] = self.answer
        return result


class FailedPlantDecoyServer(SecondOrderServer):
    """Leak the eventual row on a rejected first quote context."""

    def __init__(self):
        super().__init__(winning_payload='" OR 1=1-- -')

    def handle(self, method, path, data, headers):
        if method == "POST" and path == self.feature and len(self.posts) == 1:
            return response(400, json.dumps({"error": "bad_quote", "evidence": self.answer}), path)
        return super().handle(method, path, data, headers)


class FailedPromotionDecoyServer(MassAssignmentServer):
    """Leak the eventual privileged proof on the losing first field."""

    def __init__(self):
        super().__init__(winning_field="role")

    def handle(self, method, path, data, headers):
        if method == "POST" and path == self.feature:
            try:
                doc = json.loads(data or "{}")
            except Exception:
                doc = {}
            if "is_admin" in doc:
                return response(201, json.dumps({"ok": True, "evidence": self.answer}), path)
        return super().handle(method, path, data, headers)


def target(url="http://fake.local/", aid="proof-1"):
    return {"answer_id": aid, "url": url, "question": "Recover the proof from Target 1."}


def all_safe_requests(server):
    return (all(row["method"] in {"GET", "POST"} and row["redirects"] is False for row in server.log)
            and all("authorization" not in {key.lower() for key in row["headers"]} for row in server.log))


def test_day11_post_ssti():
    server = TemplateServer()
    meta = {}
    got = PC.solve(target(), {"client": server,
                              "prompt": "The template engine evaluates everything it hears; whisper an expression.",
                              "result_sink": meta, "max_requests": 20})
    bodies = [str(row["data"] or "") for row in server.posts]
    forbidden = ("__class__", "getclass", "getenv", "popen", "import", "/etc/", "/proc/", "cat+")
    check("D11: cold POST-SSTI returns the target proof", got == server.answer, (got, server.answer))
    check("D11: exact bounded count is 5 requests / 2 POSTs", len(server.log) == 5 and len(server.posts) == 2,
          server.log)
    check("D11: form template arithmetic comes before the scalar objective read",
          "template=%7B%7B7213%2A4567%7D%7D" in bodies[0]
          and "template=%7B%7Bobjective%7D%7D" in bodies[1], bodies)
    check("D11: no reflective/file/environment/RCE template gadget is sent",
          not any(word in "\n".join(bodies).lower() for word in forbidden), bodies)
    check("D11: class and counts are exposed to integration", meta["proof-1"]["class"] == "post_ssti"
          and meta["proof-1"]["requests"] == 5 and meta["proof-1"]["posts"] == 2, meta)
    check("D11: transport is GET/POST, no redirects and no authority header", all_safe_requests(server), server.log)


def test_day11_reflection_and_future_candidate():
    echo = TemplateServer(echo=True)
    got = PC.solve(target(), {"client": echo,
                              "prompt": "Template expressions are evaluated.", "max_requests": 20})
    check("D11 negative: literal arithmetic reflection is not evaluation", got is None and len(echo.posts) == 10,
          (got, len(echo.posts)))

    future = "proof_next.format-v5"
    server = TemplateServer(answer=future)
    evidence, meta = [], {}
    got = PC.solve(target(), {"client": server, "prompt": "Template expression evaluation.",
                              "evidence": evidence, "result_sink": meta, "max_requests": 20})
    check("D11 format change: successful different-shaped proof is not auto-returned", got is None, got)
    check("D11 format change: candidate is surfaced with a successful anchor",
          any(future in line for line in evidence) and future in meta["proof-1"]["candidates"],
          (evidence, meta))


def test_day11_engine_field_and_transport_depth():
    expected_posts = {"curly": 2, "dollar": 3, "hash": 4, "erb": 5}
    for syntax, posts in expected_posts.items():
        server = TemplateServer(syntax=syntax, framework="Flask/Jinja-compatible renderer")
        got = PC.solve(target(), {"client": server,
                                  "prompt": "Evaluate a template expression.", "max_requests": 20})
        sent = "\n".join(str(row["data"] or "") for row in server.posts).lower()
        check(f"D11 depth: harmless {syntax} syntax confirms then reads the scalar objective",
              got == server.answer and len(server.posts) == posts and
              not any(word in sent for word in ("__class__", "getenv", "popen", "import", "/etc/")),
              server.log)

    server = TemplateServer(syntax="erb", field="note_body", encoding="json", framework="Ruby ERB")
    meta = {}
    got = PC.solve(target(), {"client": server, "result_sink": meta, "max_requests": 20})
    payloads = [json.loads(row["data"]) for row in server.posts]
    check("D11 depth: advertised JSON field and non-Spring engine solve without a shared prompt",
          got == server.answer and len(server.log) == 8 and len(server.posts) == 5 and
          all(list(body) == ["note_body"] for body in payloads) and
          meta["proof-1"]["where"] == "post_ssti:note_body:json:erb",
          (server.log, meta))

    surround = TemplateServer(echo=True, surround_product=True)
    got = PC.solve(target(), {"client": surround, "prompt": "Evaluate a template expression.",
                              "max_requests": 20})
    check("D11 depth: arithmetic in surrounding debug text cannot confirm slot evaluation",
          got is None and len(surround.posts) == PC.POST_SSTI_CONFIRM_CAP, surround.log)


def test_day12_second_order():
    server = SecondOrderServer()
    meta = {}
    got = PC.solve(target(), {"client": server,
                              "prompt": "Plant your question inside the data and come back later.",
                              "result_sink": meta, "max_requests": 20})
    paths = [(row["method"], row["path"]) for row in server.log]
    check("D12: cold second-order SQLi returns the delayed private-row proof", got == server.answer,
          (got, server.answer))
    check("D12: exact bounded count is 6 requests / one POST", len(server.log) == 6 and len(server.posts) == 1,
          server.log)
    check("D12: secondary baseline is read before the POST and freshly read after it",
          paths == [("GET", "/"), ("GET", "/api/clues"), ("GET", server.feature),
                    ("GET", server.secondary), ("POST", server.feature), ("GET", server.secondary)], paths)
    posted = server.posts[0]
    check("D12: sole mutation is JSON filter with the historical tautology",
          posted["headers"].get("Content-Type") == "application/json"
          and json.loads(posted["data"]) == {"filter": "' OR 1=1-- -"}, posted)
    check("D12: class and counts are exposed to integration", meta["proof-1"]["class"] == "second_order_sqli"
          and meta["proof-1"]["requests"] == 6 and meta["proof-1"]["posts"] == 1, meta)
    check("D12: transport is GET/POST, no redirects and no authority header", all_safe_requests(server), server.log)


def test_day12_ack_decoy_and_wrong_effect():
    decoy = proof()
    server = SecondOrderServer(ack_decoy=decoy)
    got = PC.solve(target(), {"client": server, "max_requests": 20})
    check("D12 decoy: a distinct plain acknowledgement proof is subtracted, not globally poisoning",
          got == server.answer and got != decoy and len(server.posts) == 1, (got, decoy))

    repeated = proof()
    server = SecondOrderServer(answer=repeated, ack_decoy=repeated)
    got = PC.solve(target(), {"client": server, "max_requests": 20})
    check("D12 decoy: the same proof on plain acknowledgement and payoff is ineligible",
          got is None and len(server.posts) == 1, got)

    wrong = SecondOrderServer(effect="ordinary_result_list")
    got = PC.solve(target(), {"client": wrong, "max_requests": 20})
    check("D12 applicability: a generic POST+secondary pair receives no mutation", got is None
          and not wrong.posts and len(wrong.log) == 4, wrong.log)


def test_day12_field_transport_and_quote_depth():
    winning = '" OR 1=1-- -'
    server = SecondOrderServer(filter_field="where_clause", encoding="form",
                               winning_payload=winning)
    meta = {}
    got = PC.solve(target(), {"client": server, "result_sink": meta, "max_requests": 20})
    sent = [dict(urllib.parse.parse_qsl(row["data"] or "", keep_blank_values=True))
            for row in server.posts]
    check("D12 depth: advertised form field reaches a double-quoted SQL context",
          got == server.answer and len(server.log) == 8 and len(server.posts) == 2 and
          sent == [{"where_clause": "' OR 1=1-- -"}, {"where_clause": winning}] and
          meta["proof-1"]["where"] ==
          "second_order_sqli:where_clause:form:double_numeric",
          (server.log, sent, meta))
    check("D12 depth: quote-context probes remain tautology-only and non-destructive",
          all(not any(word in str(row["data"]).lower() for word in
                      ("union", "select", "sleep", "drop", "insert", "update", "delete"))
              for row in server.posts), server.posts)

    bounded = SecondOrderServer(winning_payload="never")
    got = PC.solve(target(), {"client": bounded, "max_requests": 20})
    check("D12 depth: an unmatched quote context stops at four POST/readback pairs",
          got is None and len(bounded.posts) == PC.SECOND_ORDER_POST_CAP and
          len(bounded.log) == 4 + 2 * PC.SECOND_ORDER_POST_CAP, bounded.log)


def test_day13_mass_assignment():
    server = MassAssignmentServer()
    meta = {}
    got = PC.solve(target(), {"client": server,
                              "prompt": "The API binds whatever you hand it, so hand it a promotion.",
                              "result_sink": meta, "max_requests": 20})
    check("D13: cold mass assignment returns the privileged readback proof", got == server.answer,
          (got, server.answer))
    check("D13: historical is_admin body wins in exactly 6 requests / one POST",
          len(server.log) == 6 and len(server.posts) == 1
          and json.loads(server.posts[0]["data"]) == {"name": "attacker", "is_admin": True}, server.log)
    check("D13: proof comes from same-client secondary transition, not the generic POST ack",
          server.log[-1]["method"] == "GET" and server.log[-1]["path"] == server.secondary
          and meta["proof-1"]["where"] == "mass_assignment:is_admin:json", meta)
    check("D13: transport is GET/POST, no redirects and no authority header", all_safe_requests(server), server.log)

    split = MultipartMassAssignmentServer(split=True)
    got = PC.solve(target(), {"client": split, "prompt": "mass assignment promotion",
                              "max_requests": 20})
    check("D13: privilege JSON cannot bless a proof in an independent MIME sibling",
          got is None and len(split.posts) == 1, (got, split.log))

    coherent = MultipartMassAssignmentServer(split=False)
    got = PC.solve(target(), {"client": coherent, "prompt": "mass assignment promotion",
                              "max_requests": 20})
    check("D13: privilege anchor and proof in one JSON member remain eligible",
          got == coherent.answer and len(coherent.posts) == 1, (got, coherent.log))


def test_day13_ack_does_not_stop_grid():
    server = MassAssignmentServer(winning_field="isAdmin")
    got = PC.solve(target(), {"client": server,
                              "prompt": "The API binds every property; over-post a promotion.",
                              "max_requests": 20})
    sent = [json.loads(row["data"]) for row in server.posts]
    check("D13: generic ok:true acknowledgements do not stop failed promotion candidates",
          got == server.answer and len(server.posts) == 3, (got, sent))
    check("D13: bounded isolated order is is_admin, role=administrator, isAdmin",
          [next(key for key in body if key != "name") for body in sent] == ["is_admin", "role", "isAdmin"], sent)
    check("D13: three candidates cost exactly 10 requests", len(server.log) == 10, server.log)
    check("D13: no broad/prototype-pollution property is ever sent",
          all("__proto__" not in body and "constructor" not in body for body in sent), sent)


def test_baseline_decoy_and_strict_routes():
    case_value = proof()
    case_info = PC.extract_anchored(
        response(200, {"proof": case_value}),
        [json.dumps({"proof": case_value.upper()})], anchored=True,
    )
    check("baseline subtraction: a case-only proof spelling is not novel",
          case_info.get("auto") is None, case_info)

    decoy = proof()
    server = MassAssignmentServer(root_decoy=f"<p>evidence: {decoy}</p>")
    got = PC.solve(target(), {"client": server,
                              "prompt": "The API binds whatever you hand it; promotion.", "max_requests": 20})
    check("baseline subtraction: a distinct plain-page decoy does not hide the novel privileged proof",
          got == server.answer and got != decoy and len(server.posts) == 1 and len(server.log) == 6,
          (got, decoy, server.log))

    repeated = proof()
    server = MassAssignmentServer(answer=repeated, root_decoy=f"<p>evidence: {repeated}</p>")
    got = PC.solve(target(), {"client": server,
                              "prompt": "The API binds whatever you hand it; promotion.", "max_requests": 20})
    check("baseline subtraction: a value repeated from plain page to payoff is never returned",
          got is None and len(server.posts) == 1, (got, server.log))

    capped = MassAssignmentServer()
    cached = preloaded_for(capped, ("/", "/api/clues", capped.feature, capped.secondary))
    meta = {}
    got = PC.solve(target(), {
        "client": capped,
        "preloaded": cached,
        "baseline_texts": [f"ordinary-{index}" for index in range(80)] + [capped.answer],
        "prompt": "The API binds whatever you hand it; promotion.",
        "result_sink": meta,
        "max_requests": 2,
    })
    check("baseline subtraction: cap+1 late decoy marks the runner incomplete",
          got is None and meta["proof-1"]["baseline_incomplete"] is True
          and len(capped.log) == 2,
          (got, meta, capped.log))

    carrier_proof = proof()
    for index, carrier in enumerate((f"https://evil.invalid/{carrier_proof}",
                                     f"ftp://evil.invalid/{carrier_proof}",
                                     f"//evil.invalid/{carrier_proof}",
                                     f"https%3A%2F%2Fevil.invalid%2F{carrier_proof}",
                                     f"https:\\/\\/evil.invalid\\/{carrier_proof}",
                                     f"https:\\u002f\\u002fevil.invalid\\u002f{carrier_proof}",
                                     f"https:&#47;&#47;evil.invalid&#47;{carrier_proof}")):
        offhost = TemplateServer(answer=carrier)
        got = PC.solve(target(), {"client": offhost, "prompt": "Template expression evaluation.",
                                  "max_requests": 20})
        check(f"payoff extraction: off-host URL carrier variant {index} is ignored",
              got is None and len(offhost.posts) == 2, (got, offhost.log))
    for depth in (4, 6, 10, 13):
        encoded_host = "https://evil.invalid"
        for _ in range(depth):
            encoded_host = urllib.parse.quote(encoded_host, safe="")
        carrier = encoded_host + "/" + carrier_proof
        info = PC.extract_anchored(
            response(200, json.dumps({"success": True, "proof": carrier})),
            anchored=True, host="fake.local")
        check(f"payoff extraction: {depth}x-encoded off-host carrier fails closed",
              info.get("auto") is None and carrier_proof not in (info.get("candidates") or []), info)
    for index, carrier in enumerate((
            "https:" + "\\" + "evil.invalid\\" + carrier_proof,
            "https:" + "\\\\" + "evil.invalid\\" + carrier_proof,
            "\\\\" + "evil.invalid\\" + carrier_proof,
            "http:////evil.invalid/" + carrier_proof,
            "https:///evil.invalid/" + carrier_proof,
            "http:/" + "\\" + "evil.invalid/" + carrier_proof,
            "http:" + "\\" + "/evil.invalid/" + carrier_proof)):
        info = PC.extract_anchored(
            response(200, json.dumps({"success": True, "proof": carrier})),
            anchored=True, host="fake.local")
        check(f"payoff extraction: backslash-authority carrier {index} fails closed",
              info.get("auto") is None and carrier_proof not in (info.get("candidates") or []), info)

    rejected_clues = UnrelatedServer({"feature_route": "/process", "framework": "template"},
                                      clue_status=403)
    got = PC.solve(target(), {"client": rejected_clues,
                              "prompt": "Template expression evaluation.", "max_requests": 20})
    check("clue authorization: JSON from non-2xx /api/clues cannot authorize a POST",
          got is None and not rejected_clues.posts and len(rejected_clues.log) == 2,
          rejected_clues.log)

    first, second = proof(), proof()
    ambiguous = TemplateServer(answer=first + " " + second)
    got = PC.solve(target(), {"client": ambiguous, "prompt": "Template expression evaluation.",
                              "max_requests": 20})
    check("payoff ambiguity: two novel strict proofs return None", got is None and len(ambiguous.posts) == 2,
          (got, first, second))

    for route in ("https://evil.invalid/submit", "/delete-account",
                  "/" + "r" * (PC.MAX_ROUTE_BYTES + 1)):
        unsafe = UnrelatedServer({"framework": "NestJS", "feature_route": route,
                                  "secondary_route": "/audit", "current_role": "analyst"})
        got = PC.solve(target(), {"client": unsafe, "prompt": "mass assignment promotion", "max_requests": 20})
        check(f"route guard: {route!r} is refused before a state change",
              got is None and not unsafe.posts and len(unsafe.log) == 2, unsafe.log)

    body_server = UnrelatedServer()
    body_runner = PC._Runner(target(), {"client": body_server, "max_requests": 20})
    oversized = "x" * (PC.MAX_REQUEST_BODY_BYTES + 1)
    response_value = body_runner._request("POST", "/process-safe", data=oversized,
                                          headers={"Content-Type": "application/json"},
                                          role="body-cap-test")
    check("request body guard: oversized serialized POST is refused before transport",
          response_value is None and not body_server.log and body_runner.requests == 0
          and body_runner.posts == 0, (response_value, body_server.log, body_runner.stopped))
    body_runner.stop_now()

    wrong_scope = UnrelatedServer()
    wrong_scope.base = "http://other.local/"
    got = PC.solve(target(), {"client": wrong_scope, "prompt": "mass assignment promotion", "max_requests": 20})
    check("client scope: a mismatched injected client is refused without a fallback request",
          got is None and not wrong_scope.log, wrong_scope.log)


def test_failed_attempts_are_controls():
    ssti = FailedSSTIDecoyServer()
    got = PC.solve(target(), {"client": ssti, "prompt": "Evaluate a template expression.",
                              "max_requests": 20})
    check("cross-attempt baseline: losing SSTI response headers poison a repeated objective token",
          got is None and len(ssti.posts) == 3, (got, ssti.log))

    second = FailedPlantDecoyServer()
    got = PC.solve(target(), {"client": second, "max_requests": 20})
    check("cross-attempt baseline: rejected SQLi plant poisons the same later private-row token",
          got is None and len(second.posts) == 2, (got, second.log))

    mass = FailedPromotionDecoyServer()
    got = PC.solve(target(), {"client": mass,
                              "prompt": "The profile binder over-posts a promotion.",
                              "max_requests": 20})
    check("cross-attempt baseline: losing promotion acknowledgement poisons a later readback token",
          got is None and len(mass.posts) == 2, (got, mass.log))


def test_selected_payoff_keeps_sibling_and_header_ambiguity():
    first, second = proof(), proof()
    boundary = "post-chain-payoff-siblings"
    multipart_body = (
        f"--{boundary}\r\nContent-Type: text/plain\r\n\r\n{first}\r\n"
        f"--{boundary}\r\nContent-Type: text/plain\r\n\r\n{second}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    response_value = {
        "status": 200,
        "body": multipart_body,
        "response_headers": {
            "Content-Type": f"multipart/mixed; boundary={boundary}",
            "X-Other-Proof": second,
        },
    }
    runner = PC._Runner(target(), {"client": UnrelatedServer(), "max_requests": 4})
    got = runner._record_payoff(
        response_value, extra=[first], payoff_text=json.dumps([first]),
        where="coherent-payoff-test",
    )
    runner.stop_now()
    check("selected payoff: a distinct MIME sibling/header proof keeps the result ambiguous",
          got is None and {first, second} <= set(runner.candidates),
          (got, runner.candidates))

    crowded = {
        "status": 200,
        "body": json.dumps({f"evidence_{index}": f"benign-{index}"
                            for index in range(24)}).encode(),
        "response_headers": {"Content-Type": "application/json",
                             "X-Evidence": second},
    }
    runner = PC._Runner(target(), {"client": UnrelatedServer(), "max_requests": 4})
    got = runner._record_payoff(
        crowded, extra=[first], payoff_text=json.dumps([first]),
        where="candidate-cap-payoff-test",
    )
    runner.stop_now()
    check("selected payoff: candidate saturation cannot displace a strict header proof",
          got is None and second in runner.candidates, (got, runner.candidates))

    late = "HUNTRESS-WEB-PROOF-31-LATE-CANDIDATE"
    overflow = {
        "status": 200,
        "body": json.dumps({f"evidence_{index}": f"ordinary-{index}"
                            for index in range(24)} | {"evidence_late": late}).encode(),
        "response_headers": {"Content-Type": "application/json"},
    }
    runner = PC._Runner(target(), {"client": UnrelatedServer(), "max_requests": 4})
    got = runner._record_payoff(
        overflow, extra=[first], payoff_text=json.dumps([first]),
        where="late-generic-candidate-test",
    )
    runner.stop_now()
    check("selected payoff: a generic labelled value beyond the display cap fails closed",
          got is None and "candidate scan" in str(runner.stopped),
          (got, runner.stopped, runner.candidates))


def test_mixed_mastery_dispatch():
    servers = {
        "http://backup.local/": UnrelatedServer(),
        "http://idor.local/": UnrelatedServer(),
        "http://mass.local/": MassAssignmentServer(),
    }

    def factory(url, timeout):
        servers[url].base = url
        servers[url].timeout = timeout
        return servers[url]

    targets = [target(url, f"proof-{index}") for index, url in enumerate(servers, 1)]
    got = PC.solve_targets(targets, {"client_factory": factory,
                                     "prompt": "The API binds whatever you hand it; promotion.",
                                     "deadline": time.time() + 5, "max_requests": 20})
    check("mixed Mastery: unrelated backup/IDOR targets remain unanswered",
          got["proof-1"] is None and got["proof-2"] is None, got)
    check("mixed Mastery: only the fingerprinted mass-assignment target solves",
          got["proof-3"] == servers["http://mass.local/"].answer, got)
    check("mixed Mastery: no POST lands on either unrelated target",
          not servers["http://backup.local/"].posts and not servers["http://idor.local/"].posts
          and len(servers["http://mass.local/"].posts) == 1,
          {url: server.log for url, server in servers.items()})


def preloaded_for(server, paths):
    """Build proof_hunt-shaped cached controls without recording fake wire requests."""
    out = {}
    for path in paths:
        raw = server.handle("GET", path, None, {})
        out[path] = {"status": raw["status"], "text": raw["body"].decode("utf-8", "replace")}
    return out


def test_preloaded_layer1_request_counts():
    prompt_ssti = "The template engine evaluates every expression."
    ssti = TemplateServer()
    meta = {}
    cached = preloaded_for(ssti, ("/", "/api/clues", ssti.feature))
    got = PC.solve(target(), {"client": ssti, "preloaded": cached, "prompt": prompt_ssti,
                              "result_sink": meta, "max_requests": 20})
    check("Layer-1 cache: D11 adds exactly its two POSTs", got == ssti.answer
          and len(ssti.log) == 2 and meta["proof-1"]["requests"] == 2, (ssti.log, meta))

    second = SecondOrderServer()
    meta = {}
    cached = preloaded_for(second, ("/", "/api/clues", second.feature, second.secondary))
    got = PC.solve(target(), {"client": second, "preloaded": cached, "result_sink": meta,
                              "max_requests": 20})
    check("Layer-1 cache: D12 adds one POST plus one fresh secondary GET", got == second.answer
          and len(second.log) == 2 and meta["proof-1"]["requests"] == 2, (second.log, meta))

    second = SecondOrderServer()
    cached = preloaded_for(second, ("/", "/api/clues", second.feature, second.secondary))
    got = PC.solve(target(), {"client": second, "preloaded": cached,
                              "result_sink": {}, "max_requests": 1})
    check("Layer-1 budget: D12 never plants when no readback slot remains",
          got is None and not second.log and not second.posts, second.log)

    mass = MassAssignmentServer()
    meta = {}
    cached = preloaded_for(mass, ("/", "/api/clues", mass.feature, mass.secondary))
    got = PC.solve(target(), {"client": mass, "preloaded": cached,
                              "prompt": "The API binds whatever you hand it; promotion.",
                              "result_sink": meta, "max_requests": 20})
    check("Layer-1 cache: D13 adds one POST plus one privileged GET", got == mass.answer
          and len(mass.log) == 2 and meta["proof-1"]["requests"] == 2, (mass.log, meta))

    mass = MassAssignmentServer()
    cached = preloaded_for(mass, ("/", "/api/clues", mass.feature, mass.secondary))
    got = PC.solve(target(), {"client": mass, "preloaded": cached,
                              "prompt": "The API binds whatever you hand it; promotion.",
                              "result_sink": {}, "max_requests": 1})
    check("Layer-1 budget: D13 never promotes when no audit/readback slot remains",
          got is None and not mass.log and not mass.posts, mass.log)

    mass = MassAssignmentServer()
    cached = preloaded_for(mass, ("/", "/api/clues", mass.feature, mass.secondary))
    got = PC.solve(target(), {"client": mass, "preloaded": cached,
                              "prompt": "The API binds whatever you hand it; promotion.",
                              "deadline": time.time() + PC.DEADLINE_PAD + 0.1,
                              "max_requests": 2})
    check("Layer-1 deadline: D13 never promotes without time reserved for its readback",
          got is None and not mass.log and not mass.posts, mass.log)


def test_budget_deadline_and_stop():
    server = TemplateServer()
    got = PC.solve(target(), {"client": server, "prompt": "Template expression evaluation.",
                              "max_requests": 2})
    check("request budget: two GETs exhaust the run and no POST escapes", got is None
          and len(server.log) == 2 and not server.posts, server.log)

    server = TemplateServer()
    got = PC.solve(target(), {"client": server, "prompt": "Template expression evaluation.",
                              "deadline": time.time() - 1, "max_requests": 20})
    check("deadline: an expired run sends zero requests", got is None and not server.log, server.log)

    stop = threading.Event()
    stop.set()
    server = TemplateServer()
    got = PC.solve(target(), {"client": server, "prompt": "Template expression evaluation.",
                              "stop": stop, "max_requests": 20})
    check("stop gate: a pre-set shared stop sends zero requests", got is None and not server.log, server.log)


def test_complete_policy_walk():
    proof = "proof_" + "1" * 32
    doc = {"ok": True, "proof": proof}
    doc.update((f"f{i:03d}", "x") for i in range(199))
    doc["error"] = "denied"
    parsed = PC._json_document(json.dumps(doc))
    check("policy walk sees an error beyond the old 200-member prefix",
          PC._error(parsed) == "denied", PC._error(parsed))


def main():
    old = dict(os.environ)
    try:
        for name in ("CTF_WEB_POST_CHAIN", "CTF_WEB_POST_SSTI",
                     "CTF_WEB_SECOND_ORDER_SQLI", "CTF_WEB_MASS_ASSIGNMENT"):
            os.environ.pop(name, None)
        for fn in (
            test_day11_post_ssti,
            test_day11_reflection_and_future_candidate,
            test_day11_engine_field_and_transport_depth,
            test_day12_second_order,
            test_day12_ack_decoy_and_wrong_effect,
            test_day12_field_transport_and_quote_depth,
            test_day13_mass_assignment,
            test_day13_ack_does_not_stop_grid,
            test_baseline_decoy_and_strict_routes,
            test_failed_attempts_are_controls,
            test_selected_payoff_keeps_sibling_and_header_ambiguity,
            test_mixed_mastery_dispatch,
            test_preloaded_layer1_request_counts,
            test_budget_deadline_and_stop,
            test_complete_policy_walk,
        ):
            try:
                fn()
            except Exception as exc:
                import traceback
                traceback.print_exc()
                FAILED.append(f"{fn.__name__} raised: {exc}")
    finally:
        os.environ.clear()
        os.environ.update(old)
    print()
    if FAILED:
        print(f"FAILED: {len(FAILED)} of {COUNT[0]} check(s)")
        raise SystemExit(1)
    print(f"PASS: {COUNT[0]} checks")


if __name__ == "__main__":
    main()
