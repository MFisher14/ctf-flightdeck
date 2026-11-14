"""Text rendering of the cockpit for the player's terminal (B-209).

The rule from Spooky ("I asked you for everything still needing something"): the total number of
open needs is always printed, with the challenges they belong to, even when only the next N are
listed; nothing is ever hidden without saying how many.
"""
from __future__ import annotations

from .core import Need, SweepReport


def _short(s: str, n: int = 100) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def needs_lines(needs: list[Need], batch: int | None) -> list[str]:
    if not needs:
        return ["NEEDS  nothing open: every challenge has what it needs"]
    chals = len({n.challenge for n in needs})
    shown = needs if batch is None or batch >= len(needs) else needs[:batch]
    head = f"NEEDS  {len(needs)} open across {chals} challenge(s)"
    if len(shown) < len(needs):
        head += f"; next {len(shown)} (all: `ctf cockpit needs --all`)"
    out = [head]
    for n in shown:
        out.append(f"  [{n.id}] {n.challenge} ({n.kind}): {_short(n.text, 140)}")
    return out


def queue_lines(pending: list[dict], show_flags: bool = True, limit: int | None = 1) -> list[str]:
    if not pending:
        return ["QUEUE  empty: no flag waiting for you to submit"]
    held = sum(1 for q in pending if q.get("held"))
    pending = sorted(pending, key=lambda q: bool(q.get("held")))     # sendable first, else in order
    out = [f"QUEUE  {len(pending)} flag(s) to submit by hand, oldest first"
           + (f"; {held} HELD by the event rules: do not send" if held else "")]
    for q in pending if limit is None else pending[:limit]:
        val = q["flag"] if show_flags else "(hidden)"
        tags = "".join(t for t, on in ((" [answer outside the flag format]", q["nonstandard"]),
                                       (" [guess]", q["guess"]),
                                       (" [past the wrong-answer stop: player confirmed]", q["confirmed"]))
                       if on)
        out.append(f"  #{q['id']} {q['challenge']}: {val}{tags}")
        out.append(f"      from: {_short(q['provenance'], 120)}")
        if q.get("held"):
            out.append(f"      HELD: {_short(q['held'], 160)}")
            out.append(f"      then: ctf cockpit confirm {q['id']}   |   ctf cockpit withdraw {q['id']}")
        else:
            out.append(f"      then: ctf cockpit accepted {q['id']}   |   ctf cockpit rejected {q['id']}")
    if limit is not None and len(pending) > limit:
        out.append(f"  ... {len(pending) - limit} more (`ctf cockpit queue`)")
    return out


def sweep_lines(rep: SweepReport) -> list[str]:
    out = []
    for f in rep.filed:
        line = f"FILED  {f['challenge']}/files/{f['rel']}  <- {f['how']}  [{f['detail']}]"
        out.append(line)
        out += [f"  !! {p}" for p in f["problems"]]
    for d in rep.duplicates:
        out.append(f"DUP    {d['src']}: identical to {d['challenge']}/files/{d['rel']}; removed the copy")
    for c in rep.conflicts:
        out.append(f"CLASH  {c['src']}: {c['challenge']}/files/{c['rel']} exists with other bytes; "
                   f"`ctf cockpit file {c['src']} {c['challenge']} --replace` or --as NEWNAME")
    for u in rep.unfiled:
        out.append(f"INBOX  {u['src']}: {u['reason']}")
    for r in rep.refused:
        out.append(f"REFUSED {r['src']}: {r['reason']}")
    for w in rep.waiting:
        out.append(f"WAIT   {w['src']}: {w['reason']}")
    for cid in rep.described:
        out.append(f"DESC   {cid}: description set from the dropped file")
    return out


def render(board: dict, rep: SweepReport | None = None, *, batch: int | None = 3) -> str:
    rows = board["challenges"]
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "none yet"
    out = [f"cockpit: {board['event']}   {len(rows)} challenge(s): {summary}",
           f"drop zone: {board['inbox']}" + (f"   focus: {board['focus']} (loose drops go here)"
                                              if board["focus"] else "")]
    if rep is not None:
        out += sweep_lines(rep)
    out += needs_lines([Need(**n) for n in board["needs"]], batch)
    out += queue_lines(board["queue"])
    return "\n".join(out)


def status_lines(board: dict) -> list[str]:
    out = []
    for r in board["challenges"]:
        pts = "" if r["points"] is None else f" {r['points']}pt"
        out.append(f"{r['id']:<32} {r['state']:<18} files={r['files']:<3} needs={r['needs']:<2} "
                   f"queued={r['queued']}{pts} {r['category']}".rstrip())
    return out or ["no challenges yet: `ctf cockpit add NAME...` or drop a folder in the inbox"]
