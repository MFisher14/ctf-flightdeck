#!/usr/bin/env python3
"""HTTP triage of a packet capture (B-076): the odd response out, the Basic credentials that worked, every
base64 header value decoded, and flag fragments split across headers joined.

  .venv/bin/python solvers/toolkits/http_triage.py <capture>            the triage as key = value lines
  .venv/bin/python solvers/toolkits/http_triage.py --json <capture>     the same as one JSON object
  .venv/bin/python solvers/toolkits/http_triage.py --all <capture>      no row limit

Built on solvers/toolkits/network.py's reader (request/response pairs from reassembled TCP, pcap and
pcapng) and ctf/fragjoin.py's joiner (fragjoin.header_fields is the header source):

    triage(capture, ff)  -> dict with
      pairs     the HTTP request/response pairs, in time order
      odd       ranked odd responses: within the requests to one (host, method, path), a status that
                few answers share while one status answers most (the one 200 among nineteen 401s);
                a response is raised further when it is a 2xx among 4xx/5xx and when it carries header
                names no other response in the capture carries
      basic     every `Authorization: Basic` decoded to user:password, with the status it got
      headers   every header value (or key=value item of one) that is base64 of text, decoded
      joins     fragjoin.join over each message's decoded header fields in part-number order, then
                over the odd responses' fields together; a join is a candidate, never proof
      flags     flags in the event format inside the decoded values themselves

The Spooky "Cleithrophobia" capture is the case it was built for: twenty POST /bridge/ignition with
Basic credentials, nineteen 401 and one 200 whose three X-... headers carry `deflector_partN=<base64>`.

Output: `key = value` lines (every value from the capture printed as a Python literal), then one
SolverResult JSON object as the last line: solved for one flag decoded whole from one value, candidate
for joins or several flags, unsure for an odd response with nothing decoded to a flag, none otherwise,
blocked when the file is no capture. Offline, pure Python; nothing in the capture is executed.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    from ctf import event as ctf_event, flagfmt, fragjoin
    from ctf.result import Evidence, SolverResult
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import event as ctf_event, flagfmt, fragjoin
    from ctf.result import Evidence, SolverResult

HERE = Path(__file__).resolve().parent
ENGINE = "toolkits.http_triage"
MIN_GROUP = 3            # requests to one (host, method, path) before a status can be the odd one out
RARE_SHARE = 0.2         # a status at most this share of its group (and at least one) is rare
MAJORITY = 0.5           # ... while one other status answers at least this share
ROWS = 20


def _network():
    if str(HERE) not in sys.path:
        sys.path.insert(1, str(HERE))
    import network
    return network


def basic_auth(value: str | None):
    """(user, password) of an `Authorization: Basic <base64>` value, or None."""
    if not value:
        return None
    scheme, _, token = value.strip().partition(" ")
    if scheme.lower() != "basic" or not token.strip():
        return None
    text = fragjoin.b64_text(token.strip()) if len(token.strip()) >= fragjoin.MIN_B64 else _short_b64(token.strip())
    if text is None or ":" not in text:
        return None
    user, _, pw = text.partition(":")
    return user, pw


def _short_b64(token: str):
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if text.isprintable() else None


def _path(uri: str | None) -> str:
    return (uri or "").split("?", 1)[0].split("#", 1)[0]


def _where(r) -> str:
    return f"{r.method or '?'} {r.uri or '?'} {r.src}:{r.sport} -> {r.dst}:{r.dport}"


def odd_responses(pairs) -> list[dict]:
    """Ranked odd responses (see the module text). Each: index into pairs, status, the group's statuses,
    score and the reasons."""
    resp_names = Counter()
    answered = [r for r in pairs if r.get("status") is not None]
    for r in answered:
        resp_names.update({k.lower() for k, _ in (r.resp_headers or [])})
    groups = defaultdict(list)
    for i, r in enumerate(pairs):
        if r.get("status") is not None and r.get("method"):
            groups[(r.host or r.dst, r.method, _path(r.uri))].append(i)
    out = []
    for key, idx in groups.items():
        n = len(idx)
        if n < MIN_GROUP:
            continue
        counts = Counter(pairs[i].status for i in idx)
        top, top_n = counts.most_common(1)[0]
        if top_n / n < MAJORITY:
            continue
        for i in idx:
            r = pairs[i]
            c = counts[r.status]
            if r.status == top or c > max(1, int(n * RARE_SHARE)):
                continue
            score = 1.0 - c / n
            reasons = [f"status {r.status} answers {c} of {n} {key[1]} {key[2]} (the rest mostly {top})"]
            if 200 <= r.status < 300 and top >= 400:
                score += 1.0
                reasons.append(f"a success among {top_n} {top} answer(s)")
            out.append({"index": i, "status": r.status, "group": f"{key[1]} {key[2]}", "statuses": dict(counts),
                        "score": score, "reasons": reasons})
    if len(answered) >= MIN_GROUP:
        lone = {name for name, c in resp_names.items() if c == 1}
        by_index = {o["index"]: o for o in out}
        for i, r in enumerate(pairs):
            names = sorted({k for k, _ in (r.resp_headers or [])
                            if k.lower() in lone and fragjoin.header_values(k, _v(r.resp_headers, k))})
            if not names:
                continue
            o = by_index.get(i)
            if o is None:
                continue                         # a lone header alone is not an odd response: it raises one
            o["score"] += 0.25 * min(len(names), 4)
            o["reasons"].append(f"the only response with header(s) {', '.join(names)} carrying base64")
    out.sort(key=lambda o: (-o["score"], o["index"]))
    return out


def _v(headers, name):
    return next((v for k, v in headers or [] if k == name), "")


def _message_fields(r, which: str):
    hs = r.headers if which == "request" else r.resp_headers
    return fragjoin.header_fields(hs or [], container=f"http:{which}")


def coherent(join) -> bool:
    """A header join is kept only when, its parts all being numbered, the numbers run without a gap
    (part1 + part3 skips part2: not a reading of the message); a join with an unnumbered part is kept."""
    nums = [fragjoin.part_number(p.name) for p in join.parts]
    if None in nums:
        return True
    return nums == list(range(nums[0], nums[0] + len(nums)))


def triage(capture, ff) -> dict:
    net = _network()
    cap = net.read(capture)
    pairs = cap.http()
    res = {"file": getattr(cap, "name", ""), "packets": len(cap.packets), "damaged": cap.damaged,
           "pairs": [], "odd": [], "basic": [], "headers": [], "joins": [], "flags": []}
    for i, r in enumerate(pairs):
        res["pairs"].append({"index": i, "where": _where(r), "status": r.get("status"), "ts": r.ts})
        cred = basic_auth(r.authorization)
        if cred is not None:
            res["basic"].append({"index": i, "user": cred[0], "password": cred[1], "status": r.get("status"),
                                 "where": _where(r)})
        for which in ("request", "response"):
            hs = r.headers if which == "request" else r.resp_headers
            for name, value in hs or []:
                if which == "request" and name.lower() == "authorization":
                    continue                     # read as Basic above
                for fname, token, text in fragjoin.header_values(name, value):
                    res["headers"].append({"index": i, "side": which, "field": fname, "encoded": token,
                                           "text": text, "part": fragjoin.part_number(fname)})
    res["odd"] = odd_responses(pairs)
    odd_idx = {o["index"] for o in res["odd"]}
    for b in res["basic"]:
        b["odd"] = b["index"] in odd_idx
    # flags written whole inside one decoded value
    if ff is not None:
        for h in res["headers"]:
            for f in ff.find_flags(h["text"]):
                res["flags"].append({"flag": f, "how": f"base64 {h['side']} header {h['field']}", "index": h["index"]})
        for b in res["basic"]:
            for f in ff.find_flags(f"{b['user']}:{b['password']}"):
                res["flags"].append({"flag": f, "how": "Basic credentials", "index": b["index"]})
        seen = set()
        for i, r in enumerate(pairs):
            for which in ("request", "response"):
                for j in filter(coherent, fragjoin.join(_message_fields(r, which), ff)):
                    if j.flag not in seen:
                        seen.add(j.flag)
                        res["joins"].append({"flag": j.flag, "index": i, "parts": [p.name for p in j.parts]})
        if res["odd"]:
            fields = []
            for o in res["odd"]:
                fields += _message_fields(pairs[o["index"]], "response")
            fields = fragjoin.part_order(fields)          # one part-number order across the responses
            for j in filter(coherent, fragjoin.join(fields, ff)):
                if j.flag not in seen:
                    seen.add(j.flag)
                    res["joins"].append({"flag": j.flag, "index": None, "parts": [p.name for p in j.parts]})
    return res


def render(res: dict, rows: int = ROWS) -> list[str]:
    lines = [f"== {res['file']}: {res['packets']} packet(s), {len(res['pairs'])} HTTP request/response pair(s)"
             + (f", damaged: {res['damaged']}" if res["damaged"] else "")]
    for o in res["odd"][:rows]:
        p = res["pairs"][o["index"]]
        lines.append(f"odd = #{o['index']} {p['where']!r} -> {o['status']} score={o['score']:.2f}: {'; '.join(o['reasons'])}")
    for b in sorted(res["basic"], key=lambda b: not b["odd"])[:rows]:
        lines.append(f"basic = {b['user']!r}:{b['password']!r} -> {b['status']}" + (" (the odd response)" if b["odd"] else ""))
    for h in res["headers"][:rows]:
        lines.append(f"header = #{h['index']} {h['side']} {h['field']!r} {h['encoded']!r} -> {h['text']!r}")
    for f in res["flags"]:
        lines.append(f"flag = {f['flag']!r} ({f['how']}, #{f['index']})")
    for j in res["joins"]:
        lines.append(f"join = {j['flag']!r} from {' + '.join(j['parts'])}"
                     + (f" (#{j['index']})" if j["index"] is not None else " (across the odd responses)"))
    return lines


def solver_result(res: dict) -> SolverResult:
    direct = list(dict.fromkeys(f["flag"] for f in res["flags"]))
    joins = [j["flag"] for j in res["joins"] if j["flag"] not in direct]
    summary = (f"{res['file']}: {len(res['pairs'])} HTTP pair(s), {len(res['odd'])} odd response(s), "
               f"{len(res['basic'])} Basic credential(s), {len(res['headers'])} base64 header value(s)")
    ev = [Evidence("decode", f"{f['flag']} from {f['how']} of pair #{f['index']}", path=res["file"]) for f in res["flags"][:8]]
    ev += [Evidence("join", f"{j['flag']} joined from {' + '.join(j['parts'])}", path=res["file"]) for j in res["joins"][:8]]
    if len(direct) == 1 and not joins:
        return SolverResult("solved", flags=direct, evidence=ev, engine=ENGINE, notes=summary)
    if direct or joins:
        return SolverResult("candidate", flags=(direct + joins)[:32], evidence=ev, engine=ENGINE,
                            notes=summary + ("; header joins are candidates" if joins else "; several flags"))
    if res["odd"]:
        top = res["odd"][0]
        return SolverResult("unsure", engine=ENGINE,
                            notes=f"{summary}; read the odd response first: {res['pairs'][top['index']]['where']} -> {top['status']}")
    return SolverResult("none", engine=ENGINE, notes=summary)


def _format():
    try:
        return flagfmt.current()
    except ctf_event.EventError as e:
        print(f"note = no event flag format ({e}): no flag search and no join", flush=True)
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="http_triage.py", description="HTTP pair triage of a pcap/pcapng (B-076)")
    ap.add_argument("capture")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--all", action="store_true", help="no row limit")
    a = ap.parse_args(argv)
    path = Path(a.capture)
    if not path.is_file():
        print(f"http_triage.py: no such file: {a.capture}", file=sys.stderr)
        return 2
    ff = _format()
    try:
        res = triage(path, ff)
    except ValueError as e:             # not a pcap or pcapng file
        print(f"== {path.name}: not read ({e})", flush=True)
        print(SolverResult("blocked", engine=ENGINE, notes=f"{path.name}: {e}").to_json(), flush=True)
        return 0
    if a.json:
        print(json.dumps(res, indent=1, default=str))
    else:
        for line in render(res, rows=10 ** 9 if a.all else ROWS):
            print(line, flush=True)
    print(solver_result(res).to_json(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
