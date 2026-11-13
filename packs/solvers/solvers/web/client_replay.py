#!/usr/bin/env python3
"""Shipped-client User-Agent replay: harvest a client's User-Agent and URLs, replay them in scope (B-131).

A handout that ships its own client (a browser inside a disk image, a script, an app) may be served
different content when a request carries that client's hard-coded User-Agent. At PINK+ "PINK OS" the
flag's second half came back, as text/plain, only to `PINK-OS-CTF/1.0`, one link away from the
client's home page; nothing replayed the client, and the gap was filled with eight wrong guesses.

Offline (the default, and what intake runs): every file of the handout is read as data
(ctf.clientreplay.harvest: raw disk images, zip members, ASCII and UTF-16LE) for User-Agent constants
and URLs. The result names each custom User-Agent, the URLs beside it, and for each of those URLs
whether the event's scope guard would allow it. Written to `recon/client/constants.json`.

Replay (`--opt replay=true`; network): each allowed URL and its first-level links (`hops`, default 1)
are fetched once normally and once per shipped User-Agent, and the replies compared
(ctf.clientreplay.replay). Every URL, link and redirect passes `ctf.scope.check_url` first, so only
hosts in the event's `rules.live_service_scope` are contacted and the event platform never is; a
refused URL is reported with the reason, for the player to decide. GET only. Written to
`recon/client/replay.json`.

Result:
  solved     a value in the event's flag format that only the shipped User-Agent received
  candidate  a flag-format value the normal request received too, or `head` (a literal first part,
             `--opt head=...`, e.g. read off the booted screen) joined to a literal tail the replay
             received, when the join is exactly one flag (nothing inserted, trimmed or re-cased)
  unsure     a User-Agent-only reply, a fragment, or refused client URLs: a human reads or decides
  none       nothing shipped a custom User-Agent, or the replay found no difference
  blocked    the replay could not run (no event scope, bad option); notes name why

A fragment is never completed here. With `--opt challenge_id=<id>` the notes also carry the submit
gate's count for the challenge (wrong answers against the stop, guesses against the budget).

Entry: ``solve(challenge_dir, profile, **opts) -> SolverResult`` (an intake ``run = "challenge"`` adapter).
"""
from __future__ import annotations

import json
from pathlib import Path

ENGINE = "web.client_replay"
INTAKE_MAX_BYTES = 1024 ** 3          # bytes harvested by default: keeps an intake run inside its timeout
MAX_LISTED = 12


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("1", "true", "yes", "on"):
        return True
    if v in (None, 0, "") or (isinstance(v, str) and v.strip().lower() in ("0", "false", "no", "off")):
        return False
    raise ValueError(f"expected true or false, got {v!r}")


def _listed(v, what: str) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple)) and all(isinstance(x, str) for x in v):
        return list(v)
    raise ValueError(f"{what} takes a string or a list of strings, got {v!r}")


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def solve(challenge_dir, profile, *, replay=False, head=None, url=None, user_agent=None, hops: int = 1,
          max_requests: int | None = None, include_stock=False, max_bytes: int = INTAKE_MAX_BYTES,
          challenge_id=None, interval: float | None = None, connect=None, sleep=None, **_opts):
    """Harvest the handout's User-Agent and URL constants; with replay=true, replay them in scope."""
    from ctf import clientreplay as cr
    from ctf import scope
    from ctf.result import Evidence, SolverResult

    challenge_dir = Path(challenge_dir)
    try:
        do_replay, stock = _truthy(replay), _truthy(include_stock)
        extra_urls, extra_uas = _listed(url, "url"), _listed(user_agent, "user_agent")
        h = cr.harvest([challenge_dir], max_bytes=max_bytes)
    except (ValueError, OSError) as e:
        return SolverResult(status="blocked", engine=ENGINE, notes=f"harvest did not run: {e}")
    out = challenge_dir / "recon" / "client"
    _write(out / "constants.json", h.to_dict())

    uas = [c.value for c in h.custom_user_agents()]
    if stock:
        uas += [c.value for c in h.user_agents if c.stock]
    for ua in extra_uas:
        if ua not in uas:
            uas.append(ua)
    evidence = []
    for c in h.custom_user_agents()[:MAX_LISTED]:
        evidence.append(Evidence(kind="user-agent",
                                 detail=f"shipped User-Agent {c.value!r} ({c.how}, {c.encoding}, seen {c.count}x)",
                                 path=c.path, offset=c.offset))
    notes = []
    for line in h.truncated:
        notes.append(f"harvest incomplete: {line}")
    if not uas:
        stock_n = sum(1 for c in h.user_agents if c.stock)
        return SolverResult(status="none", engine=ENGINE, challenge_id=challenge_id,
                            notes="; ".join(notes + [
                                f"no custom User-Agent constant in {h.files} file(s) ({h.scanned_bytes} bytes read; "
                                f"{stock_n} stock one(s), {len(h.urls)} URL(s))"]))

    # The URLs to replay: the client's own (beside its User-Agent), else every harvested URL the
    # scope allows. Scope is checked here without a connection, so the offline result already says
    # which URLs a replay would contact and which it would not.
    urls = [c.value for c in h.client_urls()]
    for u in extra_urls:
        if u not in urls:
            urls.append(u)
    allowed, refused = [], []
    scope_error = None
    pool = urls if urls else [c.value for c in h.urls]
    for u in pool:
        try:
            scope.check_url(u, what=f"shipped-client URL {u!r}", profile=profile)
            allowed.append(u)
        except scope.OutOfScope as e:
            if urls:
                refused.append((u, str(e)))
            scope_error = str(e)
    if not urls:
        urls = allowed[:MAX_LISTED]
        if not urls and h.urls:
            notes.append(f"none of the {len(h.urls)} harvested URL(s) is in the event's live-service scope "
                         f"(last refusal: {scope_error})")
    for u in allowed[:MAX_LISTED]:
        evidence.append(Evidence(kind="client-url", detail=f"in scope, replayable: {u}"))
    for u, why in refused[:MAX_LISTED]:
        evidence.append(Evidence(kind="client-url-refused", detail=f"not contacted: {u}: {why}"))
    if len(refused) > MAX_LISTED:
        notes.append(f"{len(refused) - MAX_LISTED} more refused client URL(s) are in recon/client/constants.json")

    if challenge_id:
        try:
            notes.append(cr.guess_stop(profile, str(challenge_id)).line())
        except (ValueError, OSError) as e:
            notes.append(f"guess state of challenge {challenge_id} not read: {e}")

    if not do_replay:
        if allowed:
            notes.append(f"{len(allowed)} client URL(s) in scope: replay with python -m ctf client-replay run "
                         f"{challenge_dir} (network: only hosts in rules.live_service_scope)")
        if refused:
            notes.append(f"{len(refused)} client URL(s) are outside the scope or are the event platform: the "
                         "player decides whether to open them with the shipped User-Agent")
        if not allowed and not refused:
            notes.append("a custom User-Agent but no URL beside it: pass the URL (--opt url=...) once known")
        return SolverResult(status="unsure", engine=ENGINE, evidence=evidence, challenge_id=challenge_id,
                            notes="; ".join(notes))

    if not allowed:
        return SolverResult(status="unsure" if refused else "blocked", engine=ENGINE, evidence=evidence,
                            challenge_id=challenge_id,
                            notes="; ".join(notes + ["replay not run: no shipped-client URL is in the event's "
                                                     "live-service scope" + (f" ({scope_error})" if scope_error else
                                                                             " (no URL was harvested or passed)")]))
    kw = {"profile": profile, "hops": hops}
    if max_requests is not None:
        kw["max_requests"] = max_requests
    if interval is not None:
        kw["interval"] = interval
    if connect is not None:
        kw["connect"] = connect
    if sleep is not None:
        kw["sleep"] = sleep
    try:
        rep = cr.replay(urls, uas, **kw)
    except (cr.ReplayError, scope.OutOfScope) as e:
        return SolverResult(status="blocked", engine=ENGINE, evidence=evidence, challenge_id=challenge_id,
                            notes="; ".join(notes + [f"replay did not run: {e}"]))
    _write(out / "replay.json", rep.to_dict())

    for d in rep.diffs[:MAX_LISTED]:
        tag = "ua-diff-unstable" if d.unstable else "ua-diff"
        evidence.append(Evidence(kind=tag, detail=f"{d.url} (hop {d.hop}) with User-Agent {d.ua!r}: "
                                                  f"{'; '.join(d.what)}; reply starts {d.excerpt[:160]!r}"))
    for r in rep.refused[:MAX_LISTED]:
        if not any(r.url == u for u, _ in refused):
            evidence.append(Evidence(kind="client-url-refused",
                                     detail=f"not contacted ({r.via} of {r.parent or 'the client'}): {r.url}: {r.reason}"))
    notes.append(f"replay: {rep.requests} request(s), {len(rep.gated())} User-Agent-only repl(ies), "
                 f"{len(rep.refused)} URL(s) refused by the scope guard")
    if rep.capped:
        notes.append(f"request cap reached; not fetched: {', '.join(rep.not_fetched[:6]) or 'later requests'}")
    notes.extend(rep.operator_steps()[:MAX_LISTED])

    ua_only = [f for f in rep.flags if f.ua_only]
    if ua_only:
        for f in ua_only:
            evidence.append(Evidence(kind="wire", detail=f"flag-format value received from {f.url} only with "
                                                         f"User-Agent {f.ua!r} (the normal request did not get it)"))
        return SolverResult(status="solved", flags=[f.value for f in ua_only], evidence=evidence, engine=ENGINE,
                            challenge_id=challenge_id, notes="; ".join(notes))

    flags = []
    tails = [f for f in rep.fragments if f.kind == "tail"]
    if head:
        for t in tails:
            joined = cr.join_fragments(str(head), t.value, profile)
            if joined and joined not in flags:
                flags.append(joined)
                evidence.append(Evidence(kind="join", detail=f"literal head {str(head)!r} (given) + literal tail "
                                                             f"{t.value!r} (from {t.url} with User-Agent {t.ua!r}), "
                                                             "nothing added or changed"))
        if tails and not flags:
            notes.append(f"head {str(head)!r} joined to no received tail gives a flag in the event's format: "
                         "not joined (a join that needs an edit is a guess)")
    for f in rep.fragments:
        evidence.append(Evidence(kind=f"fragment-{f.kind}", detail=f"{f.value!r} from {f.url} with User-Agent {f.ua!r}"))
    for f in rep.flags:
        if f.value not in flags:
            flags.append(f.value)
            evidence.append(Evidence(kind="wire", detail=f"flag-format value in the reply of {f.url}"
                                                         + (" (the normal request received it too)" if f.ua is None
                                                            else f" with User-Agent {f.ua!r} on a page that changes by itself")))
    if flags:
        return SolverResult(status="candidate", flags=flags, evidence=evidence, engine=ENGINE,
                            challenge_id=challenge_id, notes="; ".join(notes))
    if rep.fragments:
        notes.append("fragment only: it is reported as received and not completed; find the other part "
                     "(pass a literal first part as --opt head=...)")
    if rep.fragments or rep.gated() or rep.refused or refused:
        return SolverResult(status="unsure", engine=ENGINE, evidence=evidence, challenge_id=challenge_id,
                            notes="; ".join(notes))
    notes.append("the shipped User-Agent received the same replies as a normal request")
    return SolverResult(status="none", engine=ENGINE, challenge_id=challenge_id, notes="; ".join(notes))
