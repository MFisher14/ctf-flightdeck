"""Choose the Day 3 sample's HCFG container by pattern, not by its position in the file.

hcfg.find() returns the first container in file order whose CRC verifies. For a .NET
assembly that order means nothing: the compiler lays static array data out sorted by a name
derived from the SHA-256 of the bytes, so with a second container in the assembly the first
one is the real config on one variant and a decoy on the next (reproduced with real compiler
builds, prototypes/skeptic/build: decoy-anycpu and decoy2-anycpu).

So every container is collected first, from every file of the day:

  raw      the container bytes as they are (layout in hcfg.py), wherever they sit
  base64   the container inside a base64 run, in ASCII or in UTF-16 (a string constant
           lands in the #US heap as UTF-16)

and then one is chosen:

  - the CRC-valid ones are preferred to the ones whose payload only parses;
  - one container left: that one, unless it does not fit the pattern below while a container
    with a CRC mismatch does (the sample never checks the CRC, so a decoy can carry a valid
    one next to a real config whose CRC is stale): then None;
  - several: the one that fits the lane's pattern for (day, variant), which held in all ten
    distinct d02, d03 and d04 samples on disk: key = 0x11 + 0x10*day + variant, and the
    campaign ends in the variant number. The variant number is read from the file names and
    from the assembly (its module is named variant-NNN.dll);
  - no unique fit: None. The caller then answers None for every config field, never `none`.
"""
import base64
import json
import re
import struct
import zlib

MAGIC = b"HCFG"
# One character class, NUL included, so that a UTF-16 run is one match too (the NULs are dropped before decoding).
# The earlier form, a group `(?:[A-Za-z0-9+/]\x00?){24,}`, took 0.5 s on a 4 MB file of 23-character words, a
# third of the lane's solve cap; this one takes 0.05 s on the same file and matches a superset of the runs.
B64_RUN = re.compile(rb"[A-Za-z0-9+/\x00]{24,}")
B64_LIMIT = 4 << 20      # the base64 pass costs about 17 ms per MB; day files are a few KB
VARIANT_IN_NAME = re.compile(r"variant[-_]?(\d{1,4})(?!\d)", re.I)
VARIANT_IN_BYTES = re.compile(rb"variant[-_]?(\d{1,4})(?!\d)", re.I)


def parse_at(data: bytes, o: int):
    """The container whose magic is at data[o], or None if the header or the payload does not hold."""
    if data[o:o + 4] != MAGIC or o + 12 > len(data):
        return None
    version, key = data[o + 4], data[o + 5]
    length, crc = struct.unpack_from("<HI", data, o + 6)
    enc = data[o + 12:o + 12 + length]
    if not length or len(enc) != length:
        return None
    plain = bytes(b ^ key for b in enc)
    try:
        obj = json.loads(plain.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    return {"version": version, "key": key, "crc32": crc, "crc_ok": zlib.crc32(plain) & 0xFFFFFFFF == crc,
            "json": obj, "plain": plain}


def _raw(data: bytes):
    for m in re.finditer(re.escape(MAGIC), data):
        hit = parse_at(data, m.start())
        if hit:
            yield m.start(), "raw", hit


def _base64(data: bytes):
    for m in B64_RUN.finditer(data):
        text = m.group(0).replace(b"\x00", b"")
        if len(text) < 24:
            continue
        for skip in range(4):   # the run may start anywhere inside a 4-character group
            chunk = text[skip:]
            extra = len(chunk) % 4
            chunk = chunk[:-1] if extra == 1 else chunk + b"=" * ((4 - extra) % 4)
            try:
                dec = base64.b64decode(chunk)
            except Exception:
                continue
            hits = [h for h in (parse_at(dec, x.start()) for x in re.finditer(re.escape(MAGIC), dec)) if h]
            for hit in hits:
                yield m.start(), "base64", hit
            if hits:
                break


def candidates(members: list, notes: list = None) -> list:
    """Every distinct container in [(name, bytes)]: the hcfg fields plus `where` and `via`."""
    out, seen = [], set()
    for name, data in members:
        scans = [_raw(data)]
        if len(data) <= B64_LIMIT:
            scans.append(_base64(data))
        elif notes is not None:
            notes.append(f"{name}: {len(data)} bytes, not searched for a base64 container")
        for scan in scans:
            for offset, via, hit in scan:
                ident = (hit["key"], hit["crc32"], hit["plain"])
                if ident in seen:
                    continue
                seen.add(ident)
                out.append({**hit, "offset": offset, "via": via, "where": f"{name}@{offset:#x} ({via})"})
    return out


def variant_numbers(names: list, blobs: list) -> set:
    """The variant numbers the day's files state: in their names and inside the sample.

    When both say something they must agree; a disagreement leaves nothing to match on."""
    from_names = {int(v) for n in names for v in VARIANT_IN_NAME.findall(n)}
    from_bytes = {int(v) for b in blobs for v in VARIANT_IN_BYTES.findall(b)}
    if from_names and from_bytes:
        return from_names & from_bytes
    return from_names or from_bytes


def fits(cfg: dict, day: int, variant: int) -> bool:
    """True when the container follows the lane's (day, variant) pattern."""
    want = 0x11 + 0x10 * day + variant
    campaign = cfg["json"].get("campaign")
    tail = re.search(r"(\d+)$", campaign) if isinstance(campaign, str) else None
    return want <= 0xFF and cfg["key"] == want and tail is not None and int(tail.group(1)) == variant


def choose(found: list, day: int, variants) -> tuple:
    """(container or None, why). None means: do not answer any config field."""
    if not found:
        return None, "no HCFG container found"
    good = [c for c in found if c["crc_ok"]]
    pool = good or found
    kind = "CRC-valid" if good else "parseable (CRC mismatch)"
    if len(pool) == 1:
        # The sample's own code checks neither the magic nor the CRC, so a valid CRC alone does not make a
        # container the config: a decoy can carry one while the real container's is stale. If the one CRC-valid
        # container does not fit the (day, variant) pattern and a CRC-mismatched one does, neither is established.
        rivals = [c for c in found if c is not pool[0] and any(fits(c, day, v) for v in variants)]
        if rivals and not any(fits(pool[0], day, v) for v in variants):
            return None, (f"the only {kind} container, {pool[0]['where']}, does not fit day {day}, variant "
                          f"{sorted(variants)}, and {rivals[0]['where']} (CRC mismatch) does: config fields are "
                          "not answered")
        return pool[0], f"the only {kind} container, {pool[0]['where']}"
    match = [c for c in pool if any(fits(c, day, v) for v in variants)]
    listing = ", ".join(c["where"] for c in pool[:4])
    if len(match) == 1:
        return match[0], f"{len(pool)} {kind} containers ({listing}); {match[0]['where']} fits day {day}, variant {sorted(variants)}"
    return None, (f"{len(pool)} {kind} containers ({listing}) and {len(match)} fit day {day}, "
                  f"variant {sorted(variants) or 'unknown'}: config fields are not answered")
