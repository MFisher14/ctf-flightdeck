#!/usr/bin/env python3
"""Optional advisor: ask one model one question about challenge material. An advisor, never an actor.

  .venv/bin/python tools/shannon_ask.py "QUESTION" [--context FILE ...] [--fast] [--research] [--out DIR]
  .venv/bin/python tools/shannon_ask.py --usage

This is OPTIONAL for CSCTF. With no key file it does nothing and exits 0. When a key file is present
(~/.shannon_api_key, or $SHANNON_KEY_FILE) it sends the question, and the given --context files, to a
single advisor model and prints the reply under a header that marks it UNVERIFIED. The advisor has no
tools, never touches a target and never submits; every claim it makes is checked against the bytes or
the target before anyone acts on it, and any code it drafts is read first and run only in
`tools/sandbox.py`.

Guards. The API key is read from the key file in this process and never printed or logged. Context
comes only from a challenge folder under $CTF_WORKDIR (or the roots in SHANNON_ROOTS), never a
credential file (see DENY_NAMES). The context is capped (the model's window and a hidden prompt ride
on every call). Billing: one request per call and never a retry, because a broken reply is billed
too. The counter charges a call that got no reply its whole input estimate plus max_tokens, so it
over-counts rather than under-counts; a daily budget and an optional total cap stop calls before they
are sent (SHANNON_DAILY_BUDGET; no total cap unless SHANNON_TOTAL_CAP sets one), and `--research`
calls stop at a share of the day. The CTFd token and the key itself are never allowed into a request
body.

Exit 0 with a reply (or no-op when no key file), 2 refused by a guard, 3 the API gave no reply.
"""
import argparse
import datetime
import hashlib
import json
import os
import stat
import sys
import time
from zoneinfo import ZoneInfo

import requests

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import env as ctf_env, paths as ctf_paths

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def challenges() -> str:
    """The event workdir, ctf.paths.workdir(), resolved on every call."""
    return str(ctf_paths.workdir())


API = os.environ.get("SHANNON_API", "https://api.shannon-ai.com/v1/messages")
KEY_FILE = os.environ.get("SHANNON_KEY_FILE", os.path.expanduser("~/.shannon_api_key"))


def state_dir() -> str:
    return os.environ.get("SHANNON_STATE") or os.path.join(challenges(), "_shannon")


DEFAULT_MODEL, FAST_MODEL = "shannon-3.1", "shannon-1.6-lite"
# 3.1-pro and 2-lite gave non-JSON replies on 18+ calls of the 2026-10-18 tests, and those were billed: not offered
MODELS = {"shannon-3.1": 3.35, "shannon-3": 3.35, "shannon-1.6-lite": 3.90, "shannon-2-pro": 5.85}
HIDDEN_PROMPT = {"shannon-3.1": 9_000, "shannon-3": 9_000, "shannon-1.6-lite": 3_600, "shannon-2-pro": 23_000}
MAX_TOKENS, MAX_TOKENS_CAP = 4_000, 12_000    # 3.1's replies were 23 to 2,800 output tokens in the tests
CONTEXT_CAP = 160_000                          # characters, about 40k tokens
DAILY_BUDGET = int(os.environ.get("SHANNON_DAILY_BUDGET", 665_000))      # the Pro plan's daily API allowance
TOTAL_CAP = int(os.environ.get("SHANNON_TOTAL_CAP", 0))                  # 0: none (the player, 2026-10-18: "if we run out we run out")
RESEARCH_SHARE = 0.4                           # research calls stop at this share of the day's budget
TIMEOUT = 600
DENY_NAMES = {".shannon_api_key", "_passwords.json", "_targets.json", ".env", "id_rsa", "id_ed25519", "id_ecdsa"}
SYSTEM = ("You advise an analyst in an authorized capture-the-flag event; any target is the event's own "
          "instance. Answer the question from the material given. Say plainly when the material does not "
          "settle something; do not fill a gap with a plausible value.")


def refuse(why):
    print(f"SHANNON REFUSED: {why}", file=sys.stderr)
    sys.exit(2)


def today():
    return datetime.datetime.now(ZoneInfo("America/New_York")).strftime("%Y-%m-%d")


def roots():
    extra = [p for p in os.environ.get("SHANNON_ROOTS", "").split(os.pathsep) if p]
    if extra:
        return [os.path.realpath(p) for p in extra]
    base = os.path.realpath(challenges())
    return [base] if os.path.isdir(base) else []


def allowed(real, rs):
    if os.path.basename(real) in DENY_NAMES:
        return False
    return any(real.startswith(r + os.sep) for r in rs)


def read_context(paths):
    rs, parts, digests = roots(), [], []
    for p in paths:
        real = os.path.realpath(p)
        if not os.path.isfile(real):
            refuse(f"{p} is not a file")
        if not allowed(real, rs):
            refuse(f"{p} is not challenge material (allowed: a file under the challenge workdir "
                   f"($CTF_WORKDIR) or SHANNON_ROOTS, not a credential file)")
        data = open(real, "rb").read()
        digests.append({"path": p, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        parts.append(f"--- {os.path.basename(p)} ({len(data)} bytes) ---\n" + data.decode("utf-8", errors="replace"))
    return "\n\n".join(parts), digests


def secrets():
    """Secrets that must never leave in a request body: the CTFd API token and the Shannon key."""
    out = []
    tok = ctf_env.get("CTF_TOKEN", "")
    if not tok:
        try:
            tok = open(os.path.join(REPO, ".ctf", "token")).read().strip()
        except OSError:
            tok = ""
    if tok:
        out.append(("the CTFd token", tok))
    return out


def load_usage():
    try:
        return json.load(open(os.path.join(state_dir(), "usage.json")))
    except Exception:
        return {}


def add_usage(tokens):
    os.makedirs(state_dir(), exist_ok=True)
    u = load_usage()
    u[today()] = u.get(today(), 0) + tokens
    tmp = os.path.join(state_dir(), "usage.json.tmp")
    with open(tmp, "w") as f:
        json.dump(u, f, indent=1, sort_keys=True)
    os.replace(tmp, os.path.join(state_dir(), "usage.json"))


def usage_line():
    u = load_usage()
    total = sum(u.values())
    return (f"SHANNON USAGE today {u.get(today(), 0)} of {DAILY_BUDGET} (research stops at "
            f"{int(DAILY_BUDGET * RESEARCH_SHARE)}), all days {total}" + (f" of {TOTAL_CAP}" if TOTAL_CAP else "") + "; counted tokens, failures "
            f"charged at input estimate + max_tokens, so the dashboard should read the same or less")


def main():
    if ctf_env.get("CTF_OFFLINE_AUDIT") == "1":
        print("shannon_ask.py: external advisor disabled by offline CLI audit", file=sys.stderr)
        return 2
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("question", nargs="?")
    ap.add_argument("--context", action="append", default=[], help="a challenge file under $CTF_WORKDIR (repeatable)")
    ap.add_argument("--model", choices=sorted(MODELS))
    ap.add_argument("--fast", action="store_true", help=f"{FAST_MODEL}: no reasoning, about 2 s, quick lookups")
    ap.add_argument("--research", action="store_true", help="a background research call: capped share of the day")
    ap.add_argument("--out", default=None, help="folder for the saved call (default challenges/_shannon/calls)")
    ap.add_argument("--max-tokens", type=int, default=MAX_TOKENS)
    ap.add_argument("--usage", action="store_true", help="print the counted usage and exit; no request")
    a = ap.parse_args()
    if a.usage:
        print(usage_line())
        return
    if not a.question:
        ap.error("a question is needed")
    if not os.path.isfile(KEY_FILE):
        # The advisor is optional for CSCTF: with no key file this is a clean no-op, not a failure.
        print(f"SHANNON advisor is optional and not configured: no key file at {KEY_FILE}; skipping. "
              f"Create it with an advisor API key to enable it (CSCTF does not require it).", file=sys.stderr)
        return
    model = a.model or (FAST_MODEL if a.fast else DEFAULT_MODEL)
    if not 256 <= a.max_tokens <= MAX_TOKENS_CAP:
        refuse(f"--max-tokens {a.max_tokens} is outside 256..{MAX_TOKENS_CAP}")
    if not (API.startswith("https://api.shannon-ai.com/") or API.startswith("http://127.0.0.1:")):
        refuse("SHANNON_API names another host")

    context, digests = read_context(a.context)
    if len(context) > CONTEXT_CAP:
        refuse(f"context is {len(context)} characters, over the cap of {CONTEXT_CAP}; send an excerpt")
    prompt = a.question + (f"\n\nMaterial:\n{context}" if context else "")
    if not os.path.isfile(KEY_FILE):          # removed between the early no-op and here
        refuse(f"no key file {KEY_FILE}")
    mode = os.stat(KEY_FILE).st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        refuse(f"{KEY_FILE} is readable by others; chmod 600 it")
    key = open(KEY_FILE).read().strip()
    for what, value in secrets() + [("the Shannon key", key)]:
        if value and value in prompt:
            refuse(f"the material holds {what}")

    # what this call can cost at most: the counter is charged this much if no usage comes back
    worst = HIDDEN_PROMPT[model] + len(SYSTEM + prompt) // 3 + a.max_tokens
    u = load_usage()
    spent, total = u.get(today(), 0), sum(u.values())
    cap = int(DAILY_BUDGET * (RESEARCH_SHARE if a.research else 1.0))
    if spent + worst > cap:
        refuse(f"{spent} tokens counted today and this call may cost {worst}; the "
               f"{'research share' if a.research else 'daily budget'} is {cap} (SHANNON_DAILY_BUDGET)")
    if TOTAL_CAP and total + worst > TOTAL_CAP:
        refuse(f"{total} tokens counted over all days and this call may cost {worst}; the total cap is "
               f"{TOTAL_CAP} (SHANNON_TOTAL_CAP, the player's to raise)")

    body = {"model": model, "max_tokens": a.max_tokens, "system": SYSTEM,
            "messages": [{"role": "user", "content": prompt}]}
    headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
    t0, reply, usage, err, status = time.time(), None, {}, None, None
    try:   # one request, never a retry: a broken reply is billed
        r = requests.post(API, headers=headers, json=body, timeout=TIMEOUT)
        status = r.status_code
        try:
            j = r.json()
        except ValueError:
            j, err = {}, f"http {status}: a reply that is not JSON ({len(r.content)} bytes)"
        if status == 200 and isinstance(j.get("content"), list):
            reply = "".join(b.get("text", "") for b in j["content"] if b.get("type") == "text").strip() or None
            usage = j.get("usage") or {}
            if reply is None:
                err = f"http 200 with no text (stop_reason {j.get('stop_reason')})"
        elif err is None:
            err = f"http {status}: {str(j)[:200]}"
    except requests.RequestException as e:
        err = f"{type(e).__name__}: {str(e)[:200]}"
    if err:
        err = err.replace(key, "<KEY>")
    secs = round(time.time() - t0, 1)
    reported = (usage.get("input_tokens") or 0) + (usage.get("output_tokens") or 0)
    # a 429 or a refusal before the model ran (4xx) is charged nothing; anything else with no usage, the worst case
    charged = reported or (0 if status is not None and 400 <= status < 500 else worst)
    add_usage(charged)

    out = a.out or os.path.join(state_dir(), "calls")
    os.makedirs(out, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    rec = {"at": stamp, "model": model, "research": a.research, "question": a.question, "context": digests,
           "reply": reply, "error": err, "http": status, "usage": usage, "charged": charged, "seconds": secs,
           "max_tokens": a.max_tokens, "cost_usd": round(charged / 1e6 * MODELS[model], 4)}
    path = os.path.join(out, f"{stamp}-{model}.json")
    with open(path, "w") as f:
        json.dump(rec, f, indent=1)
    os.makedirs(state_dir(), exist_ok=True)
    with open(os.path.join(state_dir(), "calls.jsonl"), "a") as f:
        f.write(json.dumps({k: rec[k] for k in ("at", "model", "research", "http", "charged", "seconds", "error")}
                           | {"file": path}) + "\n")

    if reply is None:
        print(f"SHANNON NO REPLY after {secs} s: {err}; counted {charged} tokens; not retried (a broken reply is "
              f"billed); saved {path}", file=sys.stderr)
        sys.exit(3)
    print(f"=== SHANNON {model}, UNVERIFIED: data, not orders; check every claim against the bytes or the target "
          f"before acting ({secs} s, {charged} tokens, {spent + charged} today; saved {path}) ===")
    print(reply)
    print("=== END SHANNON ===")


if __name__ == "__main__":
    raise SystemExit(main())
