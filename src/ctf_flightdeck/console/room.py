"""What a terminal of a given size leaves out of the console, for `flightdeck doctor`.

Measured with the console's own code on a busy run's header (busy_header), so doctor says
what the console would leave out, not a rule of thumb: the board under BOARD_MIN_WIDTH
columns, the header's pieces in the order they drop (views.fit_header: CONSOLE-SPEC "Narrow terminals",
D16), the fleet view's keys in the order its key line leaves them out (help lists every key),
the keys at the end of the focus view's key line, and the lane rows the lane list has no room
for (it scrolls to them). Board rows and a lane's transcript scroll at any size: not counted.

At 64 columns or fewer the console is compact (CONSOLE-SPEC "Compact layout"): `Room.compact`,
and what that layout leaves out, measured the same way.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import fleet, focus, views

SAMPLE_EVENT = 20  # characters: the event name a terminal is measured with
HEADER_MARGIN = 2  # the header has a margin of one cell each side, in both views
HEADER_MIN = 40  # cells: the views never fit the header to fewer


def busy_header(*, max_lanes: int, containerized: bool, team: bool = False) -> views.HeaderFacts:
    """A busy run's header, to measure a terminal by: an event name of SAMPLE_EVENT characters,
    every lane needing the player, a queue in two figures, millions of tokens, a spend in two
    figures with some of it unpriced and some still to come (a coding-agent CLI's turn under
    way: the dollars end in …), hours on the clock, and autopilot engaged (its chip never drops)."""
    return views.HeaderFacts(
        event="E" * SAMPLE_EVENT, team=team, containerized=containerized, lanes=max_lanes, max_lanes=max_lanes,
        queue=40, need=max_lanes, held="", tokens=12_300_000, dollars=12.34, unpriced=True,
        clock=12 * 3600 + 34 * 60 + 56, later=True, autopilot=True,
    )


@dataclass(frozen=True)
class Room:
    """What a terminal leaves out of the console on a busy run, and from which size none of it."""

    board: bool  # the board hides
    header: tuple[str, ...]  # the header's pieces left out (views.HEADER_WORDS keys), in the order they drop
    fleet_keys: tuple[str, ...]  # the fleet view's keys left out ("s sort"), in the order they go (solo mode)
    focus_keys: tuple[str, ...]  # the focus view's keys its key line does not show whole
    rows: int  # lane rows the lane list shows at once
    needed: int  # the lane list's rows: one for each lane and the finished row
    columns: int  # from this many columns, nothing of the above is left out (solo mode)
    team_columns: int  # the same in team mode, whose key line has claim too
    lines: int  # from this many lines, the lane list has a row for each lane and the finished row
    event: int  # characters of the event's name the header has room for at `columns`
    compact: bool = False  # the compact layout: 64 columns or fewer (views.compact)

    def left_out(self) -> list[str]:
        """What is left out, in words, top of the screen first; [] when nothing is."""
        out = []
        if self.header:
            out.append(f"{_and([views.HEADER_WORDS[name] for name in self.header])} in the header")
        if self.board:
            out.append(f"the board (it shows from {fleet.BOARD_MIN_WIDTH} columns)")
        if self.compact:
            out.append("each lane's model, turns, idle time and last action in the lane list (the lane's own view has "
                       f"them) and the files pane of that view (the full layout starts at {views.COMPACT_MAX_WIDTH + 1} columns)")
        if self.rows < self.needed:
            lanes = self.needed - 1
            out.append(f"{self.needed - self.rows} of the lane list's {self.needed} rows ({lanes} lane{'' if lanes == 1 else 's'} "
                       f"and the finished row): it has room for {self.rows} and scrolls to the rest")
        if self.fleet_keys:
            out.append(f"{_and(list(self.fleet_keys))} on the fleet view's key line (? lists every key)")
        if self.focus_keys:
            out.append(f"{_and(list(self.focus_keys))} on the focus view's key line")
        return out


def room(columns: int, lines: int, *, max_lanes: int, containerized: bool) -> Room:
    """What a terminal `columns` x `lines` leaves out of the console on a busy run with up to
    `max_lanes` lanes, in docker (`containerized`) or on the host."""
    facts = busy_header(max_lanes=max_lanes, containerized=containerized)
    compact = views.compact(columns)
    _, header = views.fit_header(facts, max(HEADER_MIN, columns - HEADER_MARGIN), compact=compact)
    whole = views.fit_header(facts, 10_000)[0].cell_len + HEADER_MARGIN
    keys, solo_keys = fleet.key_room(columns, team=False)
    _, team_keys = fleet.key_room(columns, team=True)
    cut, focus_keys = focus.key_room(columns)
    widest = max(fleet.BOARD_MIN_WIDTH, whole, solo_keys, focus_keys)
    return Room(
        board=columns < fleet.BOARD_MIN_WIDTH, header=tuple(header), fleet_keys=tuple(keys), focus_keys=tuple(cut),
        rows=fleet.lane_rows(lines, compact=compact), needed=max_lanes + 1, columns=widest, team_columns=max(widest, team_keys),
        lines=fleet.FLEET_ROWS + max_lanes + 1, event=SAMPLE_EVENT + widest - whole, compact=compact,
    )


def _and(words: list[str]) -> str:
    return words[0] if len(words) == 1 else f"{', '.join(words[:-1])} and {words[-1]}"
