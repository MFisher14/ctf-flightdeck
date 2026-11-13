"""Pick the Day 3 files out of a delivery: by name, and by content when the naming has drifted.

members.day_members() takes the files whose basename starts with `d03`, which is how
Days 3 and 4 named them (d03--variant-000.dll, d03--variant-000.runtimeconfig.json). The
lane has renamed its files twice already (Day 1: symbol-orientation.elf, Day 2:
day02-cpp.elf), and under any other name the old rule answered the literal `none` for both
hashes and all three config fields. So the day's files are looked for in three steps, and
the first step that finds any decides:

  1. `name`     members.day_members(), unchanged: every saved delivery is picked here.
  2. `lenient`  a `dNN` or `dayNN` prefix on the basename or on a folder of the path
                (day03-variant-000.dll, d03/variant-000.dll).
  3. `content`  among the files no other day claims by name: the one PE with a CLI header,
                plus the files that share its stem (x.dll, x.runtimeconfig.json). Two such
                PEs are ambiguous, and nothing is picked.

The delivery archive itself (evidence.zip, under any name) is never one of the day's files.
A delivery that is not an archive is: a sample handed over bare is picked like any member.

select() returns a Selection. `how` says which step picked the files, because an answer may
depend on it: "the day's second file is absent" is established when the set was picked by
name, and is not when it was picked by content.

A day's file that is itself an archive (d03--bundle.zip) is kept as a member, and the files
inside it are listed in `inner`, so the analyzer can still read the sample. Which of the two
a hash question means has never been judged.
"""
import io
import re
import zipfile
from collections import namedtuple

import members as lane_members

Selection = namedtuple("Selection", "members inner how notes")
ARCHIVE_MAGICS = (b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c")


def is_archive(data: bytes) -> bool:
    return data[:4] == ARCHIVE_MAGICS[0] or data[:6] == ARCHIVE_MAGICS[1]


def _parts(name: str) -> list:
    return [p for p in name.replace("\\", "/").split("/") if p]


def day_of(name: str):
    """The day a file is named for, read from its basename or a folder of its path, or None.

    `d` must be followed by the number and then a separator (d03--x.dll, d3.dll), so that
    d3d9.dll is nobody's; `day` only needs the number to end (day03-x.dll, day3x.dll)."""
    for part in reversed(_parts(name)):
        m = re.match(r"d0*(\d+)(?![0-9A-Za-z])", part, re.I) or re.match(r"day[-_ ]?0*(\d+)(?!\d)", part, re.I)
        if m:
            return int(m.group(1))
    return None


def _archive_order(delivery: bytes) -> list:
    # File names sit in the central directory in the clear, even in an encrypted zip.
    try:
        return [i.filename for i in zipfile.ZipFile(io.BytesIO(delivery)).infolist() if not i.is_dir()]
    except Exception:
        return []


def _read_delivery(delivery: bytes) -> dict:
    """Every member of a (possibly AES-encrypted) zip, for a runner that could not expand it,
    with the known archive passwords (members.py)."""
    return lane_members._decrypt(delivery)


def _pool(files: dict, ctx: dict):
    """({name: bytes} of every file the delivery holds, the delivery's own archive order)."""
    delivery = (ctx or {}).get("delivery") or b""
    pool = {n: b for n, b in files.items() if " -> " not in n and isinstance(b, (bytes, bytearray))}
    order = _archive_order(delivery) if delivery[:2] == b"PK" else []
    if order and not any(n in pool for n in order):
        pool.update(_read_delivery(delivery))
    return pool, order


def _ordered(names, order: list) -> list:
    return sorted(names, key=lambda n: (order.index(n) if n in order else len(order), n))


def _stem_mates(name: str, pool: dict) -> list:
    """The files next to `name` that share its stem: x.dll -> x.dll, x.runtimeconfig.json, x.exe."""
    folder, _, base = name.replace("\\", "/").rpartition("/")
    stem = base.rsplit(".", 1)[0] if "." in base else base
    out = []
    for other in pool:
        ofolder, _, obase = other.replace("\\", "/").rpartition("/")
        if ofolder == folder and (obase == stem or obase.startswith(stem + ".")):
            out.append(other)
    return out


def _split_nested(picked: list, files: dict):
    """(members, inner): the files that sit inside a picked archive are moved to `inner`."""
    inner, inner_names = [], set()
    for name, blob in picked:
        if not is_archive(blob):
            continue
        lead = name + " -> "
        for key, body in files.items():
            if key.startswith(lead) and isinstance(body, (bytes, bytearray)) and not is_archive(body):
                leaf = key.rsplit(" -> ", 1)[1]
                inner.append((leaf, body))
                inner_names.add(leaf)
    outer = [(n, b) for n, b in picked if n not in inner_names]
    return outer, inner


def select(files: dict, ctx: dict, day: int, is_managed) -> Selection:
    """The day's files as Selection(members, inner, how, notes).

    members   [(name, bytes)] in archive order; empty when nothing could be attributed to the day
    inner     [(name, bytes)] found inside a member that is an archive
    how       'name', 'lenient', 'content' or None
    notes     one line per decision worth a look in the triage
    is_managed(bytes) says whether a file is a PE with a CLI header (the analyzer's own test)."""
    notes = []
    prefix = f"d{day:02d}"
    delivery, delivery_name = (ctx or {}).get("delivery") or b"", (ctx or {}).get("delivery_name")

    def wrapper(name, blob) -> bool:
        # The delivery archive is the wrapping, never one of the day's files, whatever it is called. A delivery
        # that is not an archive is a file of the lane handed over bare (the DLL as the artifact itself), and
        # dropping it would leave the side file as "file 1" and the literal none as "file 2".
        return name == delivery_name and blob == delivery and (is_archive(blob) or blob[:2] == b"PK")

    picked = [(n, b) for n, b in lane_members.day_members(files, ctx, prefix)
              if isinstance(b, (bytes, bytearray)) and not wrapper(n, b)]
    how = "name"
    if not picked:
        pool, order = _pool(files, ctx)
        names = [n for n in pool if not wrapper(n, pool[n]) and day_of(n) == day]
        how = "lenient"
        if not names:
            how = "content"
            free = [n for n in pool if not wrapper(n, pool[n]) and day_of(n) is None and not is_archive(pool[n])]
            managed = [n for n in free if is_managed(pool[n])]
            if len(managed) == 1:
                names = _stem_mates(managed[0], {n: pool[n] for n in free})
            elif managed:
                notes.append(f"no file is named for day {day} and {len(managed)} managed PEs are unclaimed "
                             f"({', '.join(sorted(managed)[:4])}): not picking one")
        picked = [(n, pool[n]) for n in _ordered(names, order)]
        if picked:
            notes.append(f"no file named {prefix}*: picked by {how} " + ", ".join(n for n, _ in picked[:4]))
        else:
            how = None
            notes.append(f"no file of day {day} in the delivery")
    outer, inner = _split_nested(picked, files)
    archives = [n for n, b in outer if is_archive(b)]
    if archives:
        notes.append(f"a day file is an archive ({', '.join(archives[:4])}): {len(inner)} file(s) inside it are "
                     "analysed; which file a hash question means is unjudged")
    return Selection(outer, inner, how, notes)
