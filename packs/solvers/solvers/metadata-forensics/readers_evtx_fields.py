#!/usr/bin/env python3
"""Metadata Forensics reader pack: EVTX first-record follow-up fields under their NATURAL names.

Closes the Day-25 look-ahead's GAP #1 (docs/retro/day-25-predictions-metadata-forensics.md), measured a
STOP on the armed tree. Day 24 introduced EVTX and judged ``evtx.record_count`` **plain**; the lane is
cumulative, so the single most likely Day-25 metadata question is a *second EVTX property* -- a field of the
first/only record (its event id, channel, provider, computer, time, level, task, user, record id).

The shipped solver ALREADY parses every one of these values: ``readers_day14_impl.evtx_field`` reads them
from the first record of the first chunk with python-evtx. But that reader is reachable ONLY through the
``evtx_first_([a-z_]+)`` family (readers_day14.py:445), i.e. under the spelling ``evtx.first_event_id``. The
author's own convention omits ``first_`` (Day-24's judged id was ``...-evtx-record-count``, not
``...-first-record-count``), so the natural spellings ``evtx.event_id``, ``evtx.channel``,
``evtx.provider_name``, ``evtx.computer``, ``evtx.time_created``, ``evtx.record_id``, ``evtx.level``,
``evtx.task``, ``evtx.user_id`` all returned **None** -> GATE NO.

This pack registers those bare names as a family that delegates to the SAME ``evtx_field`` extractor. It
changes nothing else:

  * Every name is a forecast (unconfirmed). The strict wrapper offers each through ``labels.pick`` until the
    judge accepts a rendering for its key -- never plain before that. A one-second base probe on Day 25 turns
    the unsure answer into the judged plain, exactly as ``evtx.first_event_id`` would.
  * ``lookup()`` consults REG before FAMILIES, and the alternation here excludes every already-registered
    EVTX name (``record_count``, ``event_record_count``, ``total_records``, the ``header_*`` block,
    ``next_record_*``), so no plain/judged reading is shadowed or moved.
  * ``first_record_*`` spellings are already carried by the existing ``evtx_first_([a-z_]+)`` family
    (``evtx.first_record_event_id`` -> group ``record_event_id`` -> ``evtx_field`` strips ``record_``), so
    they are deliberately NOT re-registered here.
  * The extractor returns the value read from the bytes, None when the file is not an EVTX, and raises
    ``M.Unknown``/``M.Ambiguous`` (handled by the wrapper as unsure) for a cut/ambiguous record. Any other
    exception becomes ``M.Unknown`` so a reader of this pack never crashes the solve.

Because it registers only free family names and adds nothing to conventions.json, every saved attempt replays
byte for byte as before (preflight --regress moves nothing).
"""

M = None  # properties_strict, set by register()

# The first-record fields the shipped evtx_field reader understands, under their natural (no ``first_``)
# spellings. Every token here resolves inside evtx_field via its EVTX_SAME table; the few it does not know
# verbatim are normalised by _FIELD_ALIAS below before the call.
_EVTX_NATURAL = (
    "event_id",
    "channel", "channel_name",
    "provider", "provider_name",
    "computer", "computer_name",
    "time_created", "time_created_utc", "time_created_iso8601",
    "record_id", "record_number",
    "level",
    "task",
    "user_id", "security_user_id",
)

# Tokens evtx_field does not map verbatim (its EVTX_SAME has no 'channelname'): translate to one it knows.
_FIELD_ALIAS = {
    "channel_name": "channel",
}

_IMPL = []


def _impl():
    """readers_day14_impl.evtx_field, reusing the already-loaded readers_day14 pack when present."""
    if not _IMPL:
        mod = getattr(M, "MORE_MODULES", {}).get("readers_day14.py")
        if mod is None:  # defensive: load the pack ourselves if MORE_MODULES lacks it
            mod = M._load_beside("metadata_readers_day14", "readers_day14.py")
            mod.M = M
        _IMPL.append(mod.impl())
    return _IMPL[0]


def _evtx_natural(name, data, field):
    """Delegate a natural-name EVTX field to readers_day14's first-record reader. Returns the value, None
    when the file is not an event log, and raises M.Unknown/M.Ambiguous (handled as unsure) otherwise."""
    field = _FIELD_ALIAS.get(field, field)
    try:
        return _impl().evtx_field(name, data, field)
    except (M.Unknown, M.Ambiguous):
        raise
    except Exception as e:  # never let an unexpected parser error escape a reader of this pack
        raise M.Unknown(f"the bytes do not read as an event-log record ({type(e).__name__})")


def register(module):
    """properties_strict loads this by name (MORE_FILES) and calls register(self)."""
    global M
    M = module
    before_fams = len(M.FAMILIES)
    before_reg = len(M.REG)
    # Only names nothing already reads as a plain/registered property. We check REG directly (not M.lookup):
    # lookup() would iterate the FAMILIES and compile readers_day14's lazy evtx family, which a test pins
    # uncompiled at import. REG is enough -- lookup() consults REG before FAMILIES, so a registered reader
    # already wins over this family, and the alternation below never overlaps an existing evtx family
    # (evtx_first_* and evtx.record_count/header_* are registered or lazily matched on other spellings).
    free = [x for x in _EVTX_NATURAL if M.canon(f"evtx.{x}") not in M.REG]
    if free:
        pattern = r"evtx_(" + "|".join(free) + r")"
        M.family(pattern, "text")(_evtx_natural)
        # a forecast: never joins a synonym's tie-break and never becomes plain before the judge
        M.TIE_FREE.add(_evtx_natural)
    return len(M.REG) - before_reg, len(M.FAMILIES) - before_fams
