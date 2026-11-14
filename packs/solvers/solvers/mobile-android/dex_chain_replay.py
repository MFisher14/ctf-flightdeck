#!/usr/bin/env python3
"""Trace the dex-chain VM over one mobile delivery (B-229).

Why did the VM not read this `analysis` APK? Day 31 Mastery set 10 declined at Context.getAssets and the standby
agent spent minutes dumping strings to find that out. trace_delivery() runs the same chain dex_chain_codec runs,
with every ANS-referencing method's outcome (code, decline, no-code, skipped) and the decline's reason (the call or
opcode the VM has no model of), plus the armed reader's answer (codec_search.solve_delivery: plain, unsure or None).

Fail closed: a trace never offers a code the reader would not answer. `verdict` is the VM's own reading:

  one-code      exactly one ANS code and no decline (the only shape dex_chain_codec.recover returns)
  partial       one code beside a declined method (unsure: the decline may hide the real chain)
  candidates    two or more distinct codes (unsure: the bytes do not prove which is asked)
  declined      no code, at least one method declined or ran to no code
  no-entry      no method references an ANS literal
  not-analysis  the document's codec is not `analysis` (the VM is not this delivery's reader)
  unreadable    not a zip archive

    import dex_chain_replay as R
    t = R.trace_delivery(blob)          # dict: verdict, codes, declines, entries, reasons, answer, unsure, route

Command line (fix round 1): `dex_chain_replay.py APK` prints the trace as one JSON line. It is the engine
`python -m ctf dexvm show` runs through ctf.openers.run_engine, so a delivery is parsed under the intake network
guard, in its own process group, with the secrets-scrubbed engine environment, never inside the ctf process. The
replay of earlier builds before a release is ctf/dexvm.py (it runs codec_search, the lane's reader, the same way and
records accepted builds as B-036 `adapt` event cases).
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
from pathlib import Path

import codec_search
import dex_chain_codec as dcc
import labels


def _verdict(codec: str, codes: list, declines: int) -> str:
    if codec != dcc.CODEC:
        return "not-analysis"
    if len(codes) == 1:
        return "one-code" if not declines else "partial"
    if codes:
        return "candidates"
    return "declined" if declines else "no-entry"


def trace_members(files: dict) -> dict:
    """The VM's reading of one package's member map (no armed answer): see the module text."""
    doc, layer = dcc.document_ex(files)
    codec = str(doc.get("codec")).strip().lower() if isinstance(doc, dict) else ""
    dexes = [k for k in files if isinstance(k, str) and k.endswith(".dex")]
    entries: list[dict] = []
    codes, declines = [], 0
    if codec == dcc.CODEC:
        codes, declines = dcc.analysis_codes_ex(files, _trace=entries)
    reasons = sorted({e["reason"] for e in entries if e["outcome"] in ("decline", "no-code", "skipped")})
    return {"codec": codec or None, "layer": layer, "dexes": dexes, "codes": list(codes), "declines": declines,
            "entries": entries, "reasons": reasons, "verdict": _verdict(codec, codes, declines)}


def trace_delivery(blob: bytes, name: str = "delivery.apk") -> dict:
    """trace_members over the delivery's own members, plus the armed reader's answer for it (`answer`: the plain
    code or None; `unsure`: the unsure options it offered instead, never sent on a clock; `route`)."""
    members, _inner = codec_search.read_members(blob, clock=codec_search._FOREVER)
    if not members:
        return {"name": name, "verdict": "unreadable", "codec": None, "layer": "", "dexes": [], "codes": [],
                "declines": 0, "entries": [], "reasons": ["not a readable zip archive"], "answer": None,
                "unsure": None, "route": "unreadable", "sha256": hashlib.sha256(blob).hexdigest()}
    out = trace_members(members)
    noise = io.StringIO()
    with contextlib.redirect_stderr(noise):        # the reader's NOTE lines: kept, not printed
        armed = codec_search.solve_delivery(blob, name)
    unsure = None
    if labels.is_unsure(armed):
        parsed = labels.parse(armed)
        unsure = {"key": parsed.key, "options": [list(o) for o in parsed.options]} if parsed else {"raw": armed}
        armed = None
    out.update(name=name, answer=armed, unsure=unsure, route=str(codec_search.LAST.get("route")),
               computed=codec_search.LAST.get("computed"), sha256=hashlib.sha256(blob).hexdigest(),
               notes=noise.getvalue().splitlines()[-20:])
    return out


def main(argv) -> int:
    """One JSON line per APK named (the trace); exit 2 when one cannot be read."""
    if not argv or any(a.startswith("-") for a in argv):
        print("usage: dex_chain_replay.py <file.apk> [...]", file=sys.stderr)
        return 2
    status = 0
    for path in argv:
        try:
            blob = Path(path).read_bytes()
        except OSError as e:
            print("dex_chain_replay.py: %s: %s" % (path, e.strerror or e), file=sys.stderr)
            status = 2
            continue
        print(json.dumps(trace_delivery(blob, Path(path).name), default=str, sort_keys=True))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
