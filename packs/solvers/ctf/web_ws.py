"""ctf.web_ws: the WebSocket proof-reader class in the no-model web first pass (B-237).

Huntress Day 22 "Socket to Me": the target's clue document names an exact ``feature_route`` and a
``stream_reference``; a plain GET of the route answers ``426 websocket_upgrade_required``; an upgrade with
``?stream=<reference>`` answers 101 and the proof is in the first server frame.  The read itself is the
carried ``solvers/web/realtime_read.py`` server-first class, which ``proof_hunt`` runs before its ordinary
clue controls, over ``WebClient.websocket_receive`` (one HTTP upgrade, then no WebSocket frame at all).

Where it sits against the web lane's GET-only rule (Open O-2).  The web lane (B-007) runs the reader with
``get_only``: no non-GET HTTP request and no WebSocket *application message* reaches the target.  The
server-first read is inside that rule -- its only request is the GET upgrade, and it sends zero frames (not
even a pong or close) -- so it runs in the lane.  A clue ``websocket_read`` contract that needs a client
message (``WebClient.websocket_conversation``) stays refused until O-2 is settled.  The player's switch for
the whole real-time class is ``CTF_WEB_REALTIME=off`` or a ``_web_realtime.off`` file in the event workdir;
when it is off the lane says so by name.

This module turns ``proof_hunt``'s per-target class summaries (``ctx['class_sink']``) into the named
lines the lane reports for a target it did not read.  Day 22 spent about 40 s of agent time reading the
hunt log to name the cause; the first pass now names it.
"""
from __future__ import annotations

from typing import Any, Mapping

REALTIME_LABEL = "realtime-read"    # proof_hunt's peer label for solvers/web/realtime_read.py
MAX_NOTES = 8
MAX_NOTE_CHARS = 400


def _clip(text: str) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= MAX_NOTE_CHARS else text[:MAX_NOTE_CHARS - 3] + "..."


def websocket_report(entry: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    """The realtime class's WebSocket report for one target's ``class_sink`` entry, or None."""
    if not isinstance(entry, Mapping):
        return None
    classes = entry.get("classes")
    summary = classes.get(REALTIME_LABEL) if isinstance(classes, Mapping) else None
    if not isinstance(summary, Mapping):
        return None
    report = summary.get("websocket")
    return report if isinstance(report, Mapping) else None


def realtime_off_reason(class_sink: Mapping[str, Any]) -> str | None:
    """The named reason the real-time class was off for this hunt, or None when it ran."""
    for entry in (class_sink or {}).values():
        classes = entry.get("classes") if isinstance(entry, Mapping) else None
        summary = classes.get(REALTIME_LABEL) if isinstance(classes, Mapping) else None
        stopped = str(summary.get("stopped") or "") if isinstance(summary, Mapping) else ""
        if stopped.startswith("off: "):
            return stopped[len("off: "):]
    return None


def class_notes(class_sink: Mapping[str, Any], answers: Mapping[str, Any]) -> list[str]:
    """Named lines for every target the hunt did not read: why the WebSocket class did not read it (when
    it was indicated), and proof_hunt's own class hint (the clue routes' first answers, e.g. ``426
    websocket_upgrade_required``).  A switched-off real-time class is named once.  Bounded and
    deterministic (sorted by answer id)."""
    notes: list[str] = []
    off = realtime_off_reason(class_sink)
    if off:
        notes.append(_clip(f"WebSocket class off: {off}"))
    for aid in sorted(class_sink or {}):
        if answers.get(aid):
            continue
        entry = class_sink[aid]
        report = websocket_report(entry)
        if report is not None and report.get("outcome") in ("declined", "ambiguous"):
            route = report.get("route") or "?"
            notes.append(_clip(f"{aid}: WebSocket class {report['outcome']} on {route}: "
                               f"{report.get('reason') or 'no reason recorded'}"))
        hint = entry.get("class_hint") if isinstance(entry, Mapping) else None
        if isinstance(hint, Mapping) and hint.get("line"):
            notes.append(_clip(f"{aid}: class hint: {hint['line']}"))
    return notes[:MAX_NOTES]
