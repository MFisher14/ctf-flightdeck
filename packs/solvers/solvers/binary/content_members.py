#!/usr/bin/env python3
"""Pick any day's files out of a delivery: by name, then leniently, then by content (B-216).

d03_members.py did this for Day 3 alone (one PE with a CLI header). Huntress Day 22 renamed every per-build
member (`dNN--variant-NNN-<build>` to `dNN--sample-<build>`) and the lane stood ~10.5 min; Day 19 and 20
brought new containers. select() is the day-agnostic form of d03_members.select, with the content test as a
parameter and a default that needs no knowledge of the day's runtime:

  1. name      members.day_members(): every basename that starts with the prefix (unchanged behaviour)
  2. lenient   a `dNN` or `dayNN` word on the basename or on a folder of the path
  3. content   among the files no other day claims by name and that are not archives, those `accept(bytes)`
               takes (default: an executable image by its magic, IMAGE_MAGICS), with the files that share
               their stem (x.dll beside x.runtimeconfig.json). With `accept` given, exactly the files it
               takes; with the default, exactly one image (two images no day claims are ambiguous: nothing
               is picked, and the notes say so)

The Selection's `how` says which step decided, because an absence is only established by name: "the day's
second file is absent" is a fact when step 1 found one file, not when content picked it.
"""
from __future__ import annotations

import d03_members as _d03
import members as lane_members

Selection = _d03.Selection
IMAGE_MAGICS = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
                b"\xca\xfe\xba\xbe", b"\x00asm", b"dex\n")


def is_image(data) -> bool:
    """Whether bytes open with the magic of an executable image (ELF, PE, Mach-O thin or fat, WASM, DEX)."""
    return isinstance(data, (bytes, bytearray)) and any(bytes(data[:len(m)]) == m for m in IMAGE_MAGICS)


def select(files: dict, ctx: dict, day: int, accept=None) -> Selection:
    """The day's files as Selection(members, inner, how, notes); see the module docstring."""
    notes = []
    prefix = f"d{int(day):02d}"
    delivery, delivery_name = (ctx or {}).get("delivery") or b"", (ctx or {}).get("delivery_name")

    def wrapper(name, blob) -> bool:
        return name == delivery_name and blob == delivery and (_d03.is_archive(blob) or blob[:2] == b"PK")

    picked = [(n, b) for n, b in lane_members.day_members(files, ctx, prefix)
              if isinstance(b, (bytes, bytearray)) and not wrapper(n, b)]
    how = "name"
    if not picked:
        pool, order = _d03._pool(files, ctx)
        names = [n for n in pool if not wrapper(n, pool[n]) and _d03.day_of(n) == day]
        how = "lenient"
        if not names:
            how = "content"
            free = {n: pool[n] for n in pool
                    if not wrapper(n, pool[n]) and _d03.day_of(n) is None and not _d03.is_archive(pool[n])}
            test = accept or is_image
            hits = [n for n in free if test(free[n])]
            if accept is not None and hits:
                names = sorted({m for h in hits for m in _d03._stem_mates(h, free)})
            elif len(hits) == 1:
                names = _d03._stem_mates(hits[0], free)
            elif hits:
                notes.append(f"no file is named for day {day} and {len(hits)} images are unclaimed "
                             f"({', '.join(sorted(hits)[:4])}): not picking one")
        picked = [(n, pool[n]) for n in _d03._ordered(names, order)]
        if picked:
            notes.append(f"no file named {prefix}*: picked by {how} " + ", ".join(n for n, _ in picked[:4]))
        else:
            how = None
            notes.append(f"no file of day {day} in the delivery")
    outer, inner = _d03._split_nested(picked, files)
    return Selection(outer, inner, how, notes)
