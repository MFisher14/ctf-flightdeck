"""The lane's transcript in the focus view: one Static for each entry, scrolled as one.

The focus view hands over the lane's whole log as rows (show), calm or in detail (views.entries,
views.transcript_lines); the log mounts the newest of them and keeps what is mounted while it
still fits: a row whose token is the same is left alone, the last row is drawn again when it
grew (a run of tool calls), new rows are mounted under it. Anything else (another lane, details
switched, another theme) empties it and mounts the rows again.

What is mounted is a window of the rows, never more than WINDOW of them, however long the
lane runs and wherever the player reads: every row mounted is laid out again with each
redraw, so the time a redraw takes grows with them. At the lane's end the window is its
newest rows. Reading back, it stays where the player is: the rows that come after it fills
are counted in a last row, and the rows before it in a first one; a page down at the
window's end, or a page up at its start, moves it MOUNTED rows that way.

It follows the lane while the player is at its end, and stays where they are reading
otherwise: the first entry in view keeps its row, also when the rows are mounted again.
Following is Textual's anchor (Widget.anchor), which puts the view at the end as it lays the
rows out, so no frame is drawn anywhere else. An anchored view shorter than its room would
sit at the bottom of it, so the rows are in a box that is never shorter than the view. A
place to go back to (_place) waits until the rows are laid out and the log's own size is that
layout's (laid_out). It is looked at when a row is first shown and when the log's size
changes: a call asked for after the next refresh is not enough, because a refresh can come
before the layout that has the rows, or with the rows in it and the log's old size.

A row is text, never markup: what a row draws went through views.lane_text and text.untrusted
before it came here.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Callable, Hashable, Sequence
from dataclasses import dataclass

from rich.text import Text
from textual import events
from textual.containers import Vertical, VerticalScroll
from textual.errors import NoWidget
from textual.geometry import Size
from textual.widgets import Static

from . import theme

MOUNTED = 300  # entries mounted when a lane opens, and with each page past what is mounted: a Static each
WINDOW = 2 * MOUNTED  # the most mounted at once: a redraw lays every one out (one that adds a row, 600 mounted: 0.05 to 0.1 s; 6000: 0.6 s)


@dataclass(frozen=True)
class Row:
    """One entry of the transcript, as the focus view hands it over."""

    key: int  # the index of its first action in the lane's log: rows come in the log's order
    token: Hashable  # changes when what the row draws does
    draw: Callable[[], Text]  # its text, asked for only when the row is mounted or drawn again
    one_row: bool = False  # each line of it is one row, cut at the edge; otherwise it wraps


@dataclass
class _Shown:
    """A row that is mounted."""

    key: int
    token: Hashable
    widget: RowText
    plain: str


class RowText(Static):
    """One row of the log. When it is first shown, the layout that has it is the screen's:
    the log puts the view where it belongs."""

    def on_show(self) -> None:
        log = self.parent.parent if self.parent is not None else None
        if isinstance(log, LaneLog):
            log.laid_out()


def earlier_text(count: int) -> Text:
    """The first row while earlier entries are not mounted."""
    return Text(f"· {count} earlier {_entries(count)}: pgup here shows {_them(count)}", theme.MUTED)


def later_text(count: int) -> Text:
    """The last row while later entries are not mounted: the player reads back, and the lane went on."""
    return Text(f"· {count} later {_entries(count)}: pgdn here shows {_them(count)}", theme.MUTED)


def _entries(count: int) -> str:
    return "entry" if count == 1 else "entries"


def _them(count: int) -> str:
    return "it" if count == 1 else "them"


class LaneLog(VerticalScroll, can_focus=False):
    # the gutter is always kept: without it the scroll bar takes two columns when the transcript first outgrows the
    # view, and nothing says the width changed
    DEFAULT_CSS = """
    LaneLog { background: transparent; scrollbar-gutter: stable; }
    LaneLog > Vertical { height: auto; min-height: 100%; }
    LaneLog > Vertical > Static { height: auto; }
    LaneLog > Vertical > .-row { text-wrap: nowrap; text-overflow: ellipsis; }
    """

    def __init__(self, *, id: str | None = None) -> None:
        self._box = Vertical()  # the rows: never shorter than the view (the module's text says why)
        super().__init__(self._box, id=id)
        self._rows: Sequence[Row] = ()  # every row of the lane, as last shown
        self._start = 0  # the index in _rows of the first one mounted
        self._shown: list[_Shown] = []  # the window: the rows mounted, WINDOW of them at most
        self._earlier: RowText | None = None  # the row that counts the rows before the window
        self._later: RowText | None = None  # the row that counts the rows after it
        self._told = 0  # the count the later row shows
        self._follow = True  # the view follows the lane: the player left it at its end
        self._held = False  # a mouse button is down in the log: the view does not move under a selection
        self._place: tuple[int, int] | None = None  # (an entry's key, the row of the view its first row goes to), once laid out

    def on_mount(self) -> None:
        self.anchor()

    # ------------------------------------------------------------------ what is shown

    def texts(self) -> list[str]:
        """The text of each row that is mounted, in order: one string for each entry (its
        lines parted by a newline), whole, also what the edge cuts or the view has scrolled away."""
        earlier = [earlier_text(self._start).plain] if self._earlier is not None else []
        later = [later_text(self._told).plain] if self._later is not None else []
        return earlier + [shown.plain for shown in self._shown] + later

    @property
    def earlier(self) -> int:
        """How many earlier entries are not mounted."""
        return self._start

    @property
    def later(self) -> int:
        """How many later entries are not mounted."""
        return len(self._rows) - self._start - len(self._shown)

    def clear(self) -> None:
        """Empty the log for another lane: the next rows are shown from their end."""
        self._empty()
        self._rows, self._start, self._follow, self._place = (), 0, True, None

    def show(self, rows: Sequence[Row]) -> None:
        """Show `rows`, the lane's whole log in order. What is mounted stays while the rows
        still have it (only its last row may have changed), and the new rows are mounted
        under it: all of them at the lane's end, as far as the window goes when the player
        is reading back. Otherwise the rows are mounted again: the newest MOUNTED of them,
        or a window from the first entry in view on when the player is reading back, and
        that entry stays where it is."""
        follow = self._place is None and (self._follow or self._at_end())  # a place that waits is not the end
        if not self._grown(rows):
            place = None if follow else self._place or self._first_in_view()
            start = max(0, len(rows) - MOUNTED)
            if place is not None:
                start = min(start, self._index(rows, place[0]))
                place = (place[0], max(0, place[1]))  # an entry partly above the view goes to its top: its rows changed
            self._mount(rows, start, start + WINDOW, place)
        elif follow and len(rows) - self._start > WINDOW:  # at the end, the oldest go once the window is full
            self._mount(rows, len(rows) - MOUNTED, len(rows), None)
        else:
            self._append(rows, len(rows) if follow else self._start + WINDOW)
        self._follow = follow
        if follow and not self._held and self._place is None:
            self.anchor()

    def page(self, direction: int) -> None:
        """Scroll a page up (-1) or down (1). A page up at the top while earlier entries are
        not mounted, or a page down at the end of what is mounted while later ones are not,
        moves the window MOUNTED entries that way; the row the player was on stays where it
        is. Not while the window's rows are still to be laid out (_place): the row the player
        is on is not known until they are."""
        start, stop, laid_out = self._start, self._start + len(self._shown), self._place is None
        if direction > 0 and laid_out and self._later is not None and self.scroll_y >= self.max_scroll_y:
            stop = min(len(self._rows), stop + MOUNTED)
            self._mount(self._rows, max(start, stop - WINDOW), stop, self._first_in_view())
        elif direction > 0:
            self.scroll_page_down(animate=False)
        elif laid_out and start > 0 and self.scroll_y <= 0:
            start = max(0, start - MOUNTED)
            self._mount(self._rows, start, min(stop, start + WINDOW), self._first_in_view())
        else:
            self.scroll_page_up(animate=False)

    # ------------------------------------------------------------------ mounting

    def _grown(self, rows: Sequence[Row]) -> bool:
        """Whether `rows` have what is mounted where it was, with at most its last row changed
        (it was the lane's last when it was mounted) and more after it."""
        shown, new = self._shown, rows[self._start:]
        if not shown or len(new) < len(shown):
            return False
        last = len(shown) - 1
        return all(row.key == was.key and (row.token == was.token or i == last) for i, (row, was) in enumerate(zip(new, shown)))

    def _append(self, rows: Sequence[Row], stop: int) -> None:
        """`rows` have what is mounted (_grown): mount those after it, as far as the row at
        `stop`, and count the rest in the later row."""
        shown = self._shown
        at = self._start + len(shown) - 1
        last, row = shown[-1], rows[at]
        if row.token != last.token:  # the last entry grew: drawn again where it is
            text = row.draw()
            last.token, last.plain = row.token, text.plain
            last.widget.set_class(row.one_row, "-row")
            last.widget.update(text)
        self._rows = rows
        self._add(rows[at + 1:stop])
        self._tell_later()

    def _add(self, rows: Sequence[Row]) -> None:
        widgets = []
        for row in rows:
            text = row.draw()
            widget = RowText(text, classes="-row" if row.one_row else None)
            self._shown.append(_Shown(row.key, row.token, widget, text.plain))
            widgets.append(widget)
        if widgets:
            self._box.mount(*widgets, before=self._later)  # the later row stays the last

    def _tell_later(self) -> None:
        """The last row says how many later entries are not mounted; no row when all are."""
        count = self.later
        if count and self._later is None:
            self._later = RowText(later_text(count), classes="-row")
            self._box.mount(self._later)
        elif count and count != self._told:
            self._later.update(later_text(count))
        elif not count and self._later is not None:
            self._later.remove()
            self._later = None
        self._told = count

    def _empty(self) -> None:
        if self._shown or self._earlier is not None or self._later is not None:
            self._box.remove_children()
            self.screen.clear_selection()  # a selection in a row that is gone selects nothing
        self._shown, self._earlier, self._later, self._told = [], None, None, 0

    def _mount(self, rows: Sequence[Row], start: int, stop: int, place: tuple[int, int] | None) -> None:
        """Empty the log and mount `rows` from `start` to `stop`. `place` is where the view
        goes once they are laid out; None: it stays as it is, at the end if it follows the lane."""
        self._empty()
        self._rows, self._start, self._place = rows, start, place
        if start:
            self._earlier = RowText(earlier_text(start), classes="-row")
            self._box.mount(self._earlier)
        self._add(rows[start:stop])
        self._tell_later()
        if self._later is not None:
            self._follow = False  # the end of what is mounted is not the lane's
        if place is not None:
            self.anchor(False)  # not to the end, not even for a frame

    @staticmethod
    def _index(rows: Sequence[Row], key: int) -> int:
        """The index of the row that holds the action `key`: the last one that starts at or before it."""
        return max(0, bisect_right([row.key for row in rows], key) - 1)

    # ------------------------------------------------------------------ the view's place

    def _at_end(self) -> bool:
        """Whether the view is at the lane's end: at the end of what is mounted, with no later entry left out."""
        return self._later is None and self.scroll_y >= self.max_scroll_y

    def _first_in_view(self) -> tuple[int, int] | None:
        """The first entry in view and the row of the view its first row is on (negative: that
        many of its rows are above the view). None when nothing is laid out."""
        top = round(self.scroll_y)
        for shown in self._shown:
            region = shown.widget.virtual_region
            if region.bottom > top:
                return shown.key, region.y - top
        return None

    def laid_out(self) -> None:
        """A row was shown for the first time, or the log's size changed: if the rows are laid
        out now, put the view at the place that waited for it. They are when the log's size
        is the one its rows come to: Textual can lay the new rows out in a box that still
        has the size of the old ones, and a scroll then would stop at the old end."""
        if self._place is None or not self._shown:
            return
        key, row = self._place
        shown = self._shown[max(0, bisect_right([one.key for one in self._shown], key) - 1)]
        try:
            region = self.screen.find_widget(shown.widget).virtual_region
            bottom = self.screen.find_widget(self._later or self._shown[-1].widget).virtual_region.bottom
        except NoWidget:  # not in a layout yet
            return
        if self.virtual_size.height != max(bottom, self.scrollable_content_region.height):
            return
        self._place = None
        self.scroll_to(y=max(0, region.y - row), animate=False, force=True, immediate=True)
        self._follow = self._at_end()
        if self._follow and not self._held:
            self.anchor()

    def watch_virtual_size(self, size: Size) -> None:
        self.laid_out()

    def watch_scroll_y(self, old_value: float, new_value: float) -> None:
        super().watch_scroll_y(old_value, new_value)
        if self._place is None:  # while a place waits, the scroll is not the player's
            self._follow = self._later is None and new_value >= self.max_scroll_y  # at the lane's end it follows; anywhere else it stays
            if self._follow and not self._held and not self.is_anchored:
                self.anchor()

    def on_resize(self, event: events.Resize) -> None:
        # the rows wrap again at the new width. An anchored view is at its new end already, unless a scroll at the
        # end let go of the anchor (Textual does, and takes it back only when the view moves)
        if self._follow and not self._held and self._place is None:
            self.anchor()

    def on_mouse_down(self, event: events.MouseDown) -> None:
        self._held = True
        self.anchor(False)

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if not event.button:  # the button came up where nothing said so (over a scroll bar, which keeps the event)
            self.released()

    def released(self) -> None:
        """The mouse button is up (the screen says so: it may come up outside the log)."""
        if self._held:
            self._held = False
            if self._follow and self._place is None:
                self.anchor()
