#!/usr/bin/env python3
"""Check the VBScript analyzer against itself on any set of specimens. No answer key needed.

Usage:
  python3 solvers/script-analysis/vbs_selfcheck.py <specimen.vbs | folder> [...]

vbscript.py reaches every fact two independent ways: by evaluating the specimen's
own routines, and by reading the codec label, the material and the wrapper from
the raw text. This prints one line per specimen and flags any place the two
disagree, any name the code-derived reading gives that differs from the label,
and any fallback that was needed. Run it on a new day's delivery before a timed
attempt: a flag here is a question the judge will probably reject.
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vbscript as V  # noqa: E402


def check(source: str):
    info, flags = V.analyze(source), []
    seen = V.text_scan(source)
    if info["source"] != "evaluated":
        flags.append(f"configuration came from {info['source'] or 'nowhere'}")
    if seen["control"] != info["control"]:
        flags.append(f"wrapper: tree says {info['control']}, text says {seen['control']}")
    if V.CONTROL_NAMES.get(info["control"]) is None:
        flags.append(f"no judge name for wrapper {info['control']!r}")
    if seen["codec"] != info["codec"]:
        flags.append(f"codec label: {info['codec']} vs text {seen['codec']}")
    if info["codec"]:
        try:
            if V.label_decode(seen["material"], seen["codec"]) != info["text"]:
                flags.append("label decode differs from the evaluated configuration")
        except Exception as e:  # noqa: BLE001
            flags.append(f"label decode failed: {e}")
        if info["representation_seen"] != info["representation"]:
            flags.append(f"representation: label {info['representation']}, code reads as {info['representation_seen']}")
        if info["transform_seen"] != info["transform"]:
            flags.append(f"transform: label {info['transform']}, code reads as {info['transform_seen']}")
    else:
        flags.append("no codec label: names are code-derived")
    if info["role"] is None:
        flags.append("no role")
    return info, flags + info["notes"]


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    paths = []
    for arg in sys.argv[1:]:
        p = Path(arg)
        paths += sorted(p.rglob("*.vb[se]")) if p.is_dir() else [p]
    flagged, tally = 0, {"representation": Counter(), "transform": Counter(), "control": Counter()}
    for p in paths:
        try:
            info, flags = check(V.text_of(p.read_bytes()))
        except Exception as e:  # noqa: BLE001
            print(f"FLAG {p}: analysis raised {type(e).__name__}: {e}")
            flagged += 1
            continue
        for k in tally:
            tally[k][V.CONTROL_NAMES.get(info[k]) if k == "control" else info[k]] += 1
        print(f"{'FLAG' if flags else 'ok  '} {p}: {info['representation']} | {info['transform']} | "
              f"{V.CONTROL_NAMES.get(info['control'])} | {info['role']}")
        for f in flags:
            print(f"       {f}")
        flagged += bool(flags)
    for k, c in tally.items():
        print(f"{k}: " + ", ".join(f"{name} x{n}" for name, n in c.most_common()))
    print(f"{len(paths)} specimens, {flagged} flagged")
    sys.exit(1 if flagged else 0)


if __name__ == "__main__":
    main()
