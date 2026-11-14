"""ctf mavlink dissect | extract-key | verify | forge | resign | send -- the MAVLink 2 engine (B-031).

    python -m ctf mavlink dissect CAPTURE [--json]
        parse a .pcap / .tlog / raw MAVLink 2 stream: frame count, msgids, signed frames, link ids,
        and any SETUP_SIGNING secret leaked in-band.
    python -m ctf mavlink extract-key CAPTURE [--json]
        print every SETUP_SIGNING signing key leaked in the capture (the csctf 9127 break).
    python -m ctf mavlink verify CAPTURE --key HEX
        how many signed frames verify under a 32-byte (64-hex) signing key.
    python -m ctf mavlink forge --msgid N --payload HEX --key HEX [--seq N --sysid N --compid N
        --link-id N --timestamp N] : print a signed frame as hex (timestamp defaults to now).
    python -m ctf mavlink resign --prov-key HEX --new-key HEX [--target-sys N --target-comp N
        --timestamp N ...] : a SETUP_SIGNING(256) frame signed with the provisioning key that installs
        NEW-KEY -- the csctf 9147 provisioning re-sign primitive.
    python -m ctf mavlink send HOST PORT [--frame HEX ...] [--listen S] [--recv S] [--event SLUG]
        drive a live link: (optionally) read the banner, send each pre-built frame, print received
        STATUSTEXT and any flag. Scope-guarded: a non-loopback host must be in the event's
        rules.live_service_scope. No frame is sent to event infrastructure from build work.

Reads only the capture path you give (no platform contact except the explicit `send` target). Exit
codes: 0 ok, 2 a usage/parse error, 4 refused by the event's scope rules.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HELP = "the MAVLink 2 engine: dissect, extract-key, verify, forge, resign, live send"

REFUSED_EXIT = 4


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)

    d = sp.add_parser("dissect", help="parse a capture: frames, msgids, signed frames, leaked keys")
    d.add_argument("capture")
    d.add_argument("--json", action="store_true")

    e = sp.add_parser("extract-key", help="print SETUP_SIGNING keys leaked in the capture")
    e.add_argument("capture")
    e.add_argument("--json", action="store_true")

    v = sp.add_parser("verify", help="count signed frames that verify under a key")
    v.add_argument("capture")
    v.add_argument("--key", required=True, help="32-byte signing key, 64 hex chars")

    f = sp.add_parser("forge", help="build one signed MAVLink 2 frame")
    f.add_argument("--msgid", type=int, required=True)
    f.add_argument("--payload", default="", help="payload bytes, hex (empty for none)")
    f.add_argument("--key", required=True, help="signing key, 64 hex chars")
    f.add_argument("--seq", type=int, default=0)
    f.add_argument("--sysid", type=int, default=255)
    f.add_argument("--compid", type=int, default=190)
    f.add_argument("--link-id", type=int, default=0)
    f.add_argument("--timestamp", type=int, help="48-bit signing timestamp (default: now)")
    f.add_argument("--extra", type=int, help="override CRC_EXTRA (for an unknown msgid)")

    r = sp.add_parser("resign", help="SETUP_SIGNING frame signed with the provisioning key")
    r.add_argument("--prov-key", required=True, help="provisioning key, 64 hex chars")
    r.add_argument("--new-key", required=True, help="the signing key to install, 64 hex chars")
    r.add_argument("--target-sys", type=int, default=1)
    r.add_argument("--target-comp", type=int, default=1)
    r.add_argument("--initial-timestamp", type=int, default=0)
    r.add_argument("--seq", type=int, default=0)
    r.add_argument("--sysid", type=int, default=255)
    r.add_argument("--compid", type=int, default=190)
    r.add_argument("--link-id", type=int, default=0)
    r.add_argument("--timestamp", type=int, help="48-bit signing timestamp (default: now)")

    s = sp.add_parser("send", help="drive a live link (scope-guarded)")
    s.add_argument("host")
    s.add_argument("port", type=int)
    s.add_argument("--frame", action="append", default=[], help="a pre-built frame, hex (repeatable)")
    s.add_argument("--listen", type=float, default=0.0, help="read the banner for this many seconds first")
    s.add_argument("--gap", type=float, default=0.2, help="seconds between sent frames")
    s.add_argument("--recv", type=float, default=3.0, help="seconds to read responses after sending")
    s.add_argument("--event", help="event slug for the scope guard (default: the current event)")


def _hex(s: str, what: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise SystemExit(f"ctf mavlink: {what} is not valid hex")


def _load(mod_capture: str):
    import mavlink_link as mav
    try:
        return mav, mav.parse_capture(mod_capture)
    except (mav.MavlinkError, OSError) as exc:
        print(f"ctf mavlink: {exc}", file=sys.stderr)
        raise SystemExit(2)


def _profile(args):
    from .. import event
    try:
        return event.load(args.event) if getattr(args, "event", None) else event.current()
    except Exception:
        return None


def run(args: argparse.Namespace) -> int:
    import mavlink_link as mav

    if args.action == "dissect":
        _, got = _load(args.capture)
        frames = [f for _, f in got]
        signed = [f for f in frames if f.signed]
        leaks = mav.extract_setup_signing(frames)
        out = {
            "frames": len(frames),
            "signed": len(signed),
            "msgids": sorted({f.msgid for f in frames}),
            "sysids": sorted({f.sysid for f in frames}),
            "link_ids": sorted({f.link_id for f in signed if f.link_id is not None}),
            "setup_signing": [{"target_system": s.target_system,
                               "target_component": s.target_component,
                               "key": s.key_hex} for s in leaks],
        }
        if args.json:
            print(json.dumps(out))
        else:
            print(f"{out['frames']} frames, {out['signed']} signed")
            print("msgids:", ", ".join(str(i) for i in out["msgids"]))
            print("sysids:", ", ".join(str(i) for i in out["sysids"]))
            if out["link_ids"]:
                print("link ids:", ", ".join(str(i) for i in out["link_ids"]))
            for s in out["setup_signing"]:
                print(f"SETUP_SIGNING leak: key={s['key']} "
                      f"target={s['target_system']}/{s['target_component']}")
        return 0

    if args.action == "extract-key":
        _, got = _load(args.capture)
        leaks = mav.extract_setup_signing([f for _, f in got])
        if args.json:
            print(json.dumps([{"target_system": s.target_system,
                               "target_component": s.target_component,
                               "key": s.key_hex} for s in leaks]))
        else:
            if not leaks:
                print("no SETUP_SIGNING leaked in this capture")
            for s in leaks:
                print(f"{s.key_hex}  (target {s.target_system}/{s.target_component})")
        return 0 if leaks else 1

    if args.action == "verify":
        _, got = _load(args.capture)
        key = _hex(args.key, "--key")
        signed = [f for _, f in got if f.signed]
        ok = sum(1 for f in signed if mav.verify_signature(f, key))
        print(f"{ok}/{len(signed)} signed frames verify with the given key")
        return 0 if signed and ok == len(signed) else 1

    if args.action == "forge":
        key = _hex(args.key, "--key")
        payload = _hex(args.payload, "--payload") if args.payload else b""
        try:
            frame = mav.build_signed(args.msgid, payload, key, seq=args.seq, sysid=args.sysid,
                                     compid=args.compid, link_id=args.link_id,
                                     timestamp=args.timestamp, extra=args.extra)
        except mav.MavlinkError as exc:
            print(f"ctf mavlink: {exc}", file=sys.stderr)
            return 2
        print(frame.hex())
        return 0

    if args.action == "resign":
        prov = _hex(args.prov_key, "--prov-key")
        newk = _hex(args.new_key, "--new-key")
        try:
            frame = mav.resign_setup_signing(prov, newk, target_sys=args.target_sys,
                                             target_comp=args.target_comp,
                                             initial_timestamp=args.initial_timestamp, seq=args.seq,
                                             sysid=args.sysid, compid=args.compid,
                                             link_id=args.link_id, timestamp=args.timestamp)
        except mav.MavlinkError as exc:
            print(f"ctf mavlink: {exc}", file=sys.stderr)
            return 2
        print(frame.hex())
        return 0

    if args.action == "send":
        return _send(args, mav)

    print("ctf mavlink: unknown action", file=sys.stderr)
    return 2


def _send(args, mav) -> int:
    from .. import scope
    profile = _profile(args)
    try:
        mav.guard_target(args.host, args.port, profile)
    except scope.OutOfScope as exc:
        print(f"ctf mavlink: refused: {exc}", file=sys.stderr)
        return REFUSED_EXIT

    frames = []
    for h in args.frame:
        frames.append(_hex(h, "--frame"))

    try:
        link = mav.LiveLink.connect(args.host, args.port, profile=profile)
    except scope.OutOfScope as exc:
        print(f"ctf mavlink: refused: {exc}", file=sys.stderr)
        return REFUSED_EXIT
    except OSError as exc:
        print(f"ctf mavlink: could not connect to {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2

    seen = []
    try:
        if args.listen > 0:
            seen += link.recv_frames(max_seconds=args.listen)
        for fr in frames:
            link.send_raw(fr)
            time.sleep(args.gap)
        seen += link.recv_frames(max_seconds=args.recv)
    finally:
        link.close()

    fmt = _flagfmt(profile)
    flag = None
    for f in seen:
        txt = mav.statustext_text(f)
        if txt:
            print(f"STATUSTEXT: {txt}")
        if fmt is not None:
            for cand in fmt.find_flags(f.payload):
                flag = flag or cand
    if flag:
        print(f"FLAG: {flag}")
        return 0
    print(f"received {len(seen)} frames; no flag in the event format", file=sys.stderr)
    return 1


def _flagfmt(profile):
    try:
        from ctf import flagfmt
        return flagfmt.for_profile(profile) if profile is not None else None
    except Exception:
        return None
