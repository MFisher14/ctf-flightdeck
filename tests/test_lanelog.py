"""The lane's transcript in the focus view: the calm one (details off) and the details switch.

The pure tests read what views.entries and views.entry_text make of a lane's log; the app
tests read the transcript's rows (LaneLog.texts) and the screen as a player sees it. Every
lane here is synthetic: its commands and outputs are written in this file and nothing is run.
"""

from __future__ import annotations

from ctf_flightdeck import themes
from ctf_flightdeck.agent import tools
from ctf_flightdeck.console import focus, room, theme, views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.lanelog import MOUNTED, WINDOW, LaneLog, RowText
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Alert, AlertKind, Call, Challenge, DeckConfig, Lane, Pending, PendingKind
from ctf_flightdeck.detect.base import suggestions
from ctf_flightdeck.text import NEWLINE
from test_console import (
    JWT,
    OPENROUTER,
    OSC,
    VALUES,
    assert_warning,
    bar,
    color_of,
    drive,
    footer_line,
    open_focus,
    osc,
    press,
    quiet_deck,
    region_text,
    screen_lines,
    send,
    shown,
    status_line,
    terminal_frame,
)

BIG = (254, 71)  # the terminal of the report this view answers
FOLD = NEWLINE.strip()  # how a folded newline shows: no calm row has one


def one_lane(layout: str = "simple") -> tuple[Deck, FlightdeckApp, Lane]:
    """A console in `layout` with one lane, L01, that has done nothing yet."""
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), max_lanes=4))
    app = FlightdeckApp(deck, refresh_seconds=None, layout=layout)
    deck.release([Challenge("crackme", "Crack Me Maybe", "rev", 300)], [QueueEntry("crackme", "glm")])
    return deck, app, deck.lanes["L01"]


def shell(deck: Deck, command: str, out: str = "", code: int = 0) -> None:
    """A shell call the way flightdeck's own loop reports it (agent/tools.py: Toolbox._ran):
    the same helpers and limits, one call in the step."""
    failed = code != 0
    action = tools._one_line(f"$ {command}")
    deck.report("L01", TurnReport(action=action, output=tools._brief(out, f"exit {code}" if failed else "", tail=failed),
                                  calls=(Call(action, tools._excerpt(out, f"exit {code}" if failed else "", tail=failed)),), tokens=4200))


def says(deck: Deck, text: str) -> None:
    deck.report("L01", TurnReport(turn=False, action=f"says: {text}"))


def calm(deck: Deck, lane: Lane) -> list[str]:
    """Every row of the calm transcript, in order."""
    return [row for entry in views.entries(lane.actions) for row in views.entry_text(deck, lane, entry).plain.split("\n")]


def details(deck: Deck, lane: Lane) -> list[str]:
    """Every line of the transcript in detail: what the console drew before it had a calm one."""
    return [line.plain for action in lane.actions for line in views.transcript_lines(deck, lane, action)]


def log_of(app: FlightdeckApp) -> LaneLog:
    return app.screen.query_one("#transcript", LaneLog)


def lines(app: FlightdeckApp) -> list[str]:
    """Every line of every mounted row, in view or not."""
    return [line for text in log_of(app).texts() for line in text.split("\n")]


def drawn(app: FlightdeckApp) -> list[str]:
    """The transcript's rows on the screen that have text, without the scroll bar's two columns."""
    region = log_of(app).region
    rows = [row[region.x:region.right - 2].rstrip() for row in screen_lines(app)[region.y:region.bottom]]
    return [row for row in rows if row]


# ---------------------------------------------------------------------- the lane of the report

TRIAGE = "\n".join(
    ["handout: 3 file(s), 41 unpacked member(s) (17 ELF, 9 text, 6 zip, 5 png, 4 data); engines run: strings_sweep=none, "
     "zip_walk=none, png_chunks=none, elf_symbols=none, xor_single=none, base_ladder=none, exif=none, binwalk_lite=none and 6 more; "
     "engines that fit but need a person's arguments: angr_find, z3_keygen, uncompyle, frida_trace"]
    + [f"## routed engine {i:02d}: rev/{name} score {0.9 - i * 0.03:.2f} (matched: ELF 64-bit LSB pie executable, stripped; "
       f"imports strcmp, ptrace; section .rodata holds {40 + i} printable runs over 8 chars) -> ran in {0.2 + i / 10:.1f}s, status none, "
       f"evidence: none; next: needs --find/--avoid addresses"
       for i, name in enumerate(["strings_sweep", "zip_walk", "png_chunks", "elf_symbols", "xor_single", "base_ladder", "exif",
                                 "binwalk_lite", "rot_all", "upx_probe", "pyc_probe", "apk_probe", "pcap_probe", "stego_lsb"])]
)
RODATA = "\n".join(f" {0x2000 + 16 * i:04x} 01000200 00000000 456e7465 72206b65  ........Enter ke" for i in range(30)) + "\n"
HEREDOC = ("python3 - <<'EOF'\nimport struct\nblob = open('work/crackme','rb').read()[0x2010:0x2030]\nkey = bytes(b ^ 0x42 for b in blob)\n"
           "print(key)\nprint(key.hex())\nEOF")
COMMANDS = [
    ("unzip -l rev.zip", "Archive:  rev.zip\n  Length      Date    Time    Name\n---------  ---------- -----   ----\n"
                         "    14480  2026-01-02 10:00   crackme\n      212  2026-01-02 10:00   README.txt\n", 0),
    ("unzip -o rev.zip -d work && file work/*", "Archive:  rev.zip\n  inflating: work/crackme\n  inflating: work/README.txt\n", 0),
    ("cat work/README.txt", "The key is checked one byte at a time.\nNo network is needed.\n", 0),
    ("strings -n 8 work/crackme | head -40", "\n".join(f"/lib64/ld-linux-x86-64.so.{i}" for i in range(40)) + "\n", 0),
    ("objdump -d work/crackme \\\n  --no-show-raw-insn \\\n  -M intel | \\\n  grep -n -A12 '<main>' | head -60",
     "\n".join(f"  {0x1139 + 4 * i:x}:\tmov    eax,DWORD PTR [rbp-0x{i:x}]" for i in range(60)) + "\n", 0),
    ("for i in $(seq 0 31); do\n  printf '%02x ' $(dd if=work/crackme bs=1 skip=$((0x2010+i)) count=1 2>/dev/null | xxd -p)\ndone; echo",
     "13 37 c0 de 42 42 42 42 9a 0b 11 5e 7f 20 31 c4 55 66 77 88 99 aa bb cc dd ee ff 00 12 34 56 78 \n", 0),
    (HEREDOC, "b'Qu\\x82\\x9c'\n5175829c00000000d849531c3d627386172435cadbe8f98e9facbd425076143a\n", 0),
    ("gdb -q -batch -ex 'info functions' work/crackme 2>&1 | tail -20", "bash: gdb: command not found\n", 127),
    ("r2 -q -c 'aaa; afl' work/crackme 2>&1 | tail -20", "bash: r2: command not found\n", 127),
    ("objdump -s -j .rodata work/crackme | head -30", RODATA, 0),
    ("python3 - <<'EOF'\nfrom itertools import cycle\nblob = bytes.fromhex('1337c0de424242429a0b115e7f2031c4')\n"
     "for k in (b'key', b'flag', b'ctf'):\n    print(k, bytes(a ^ b for a, b in zip(blob, cycle(k))))\nEOF", "b'key' b'xR'\nb'flag' b'u['\nb'ctf' b'pC'\n", 0),
    ("objdump -s -j .rodata work/crackme | head -30", RODATA, 0),
]
SAID = ("The 32 bytes at 0x2010 are not the key XOR 0x42. I think main compares against a table built at run time, so the next step "
        "is to read the loop that fills it.")


def busy_lane(layout: str) -> tuple[Deck, FlightdeckApp, Lane]:
    """The lane of the report: a 6000-character L1 intake note, twelve shell calls (some of
    many lines, two that failed), a turn of three tool calls, the model's words, four alerts
    and an approval waiting. 23 actions."""
    deck, app, lane = one_lane(layout)
    lane.token_cap = 60000
    deck.record_route("crackme", family="rev-native", by="haiku", lane_id="L01")
    deck.record_l1("crackme", "intake", "unsure", seconds=14.2, notes=TRIAGE[:6000], lane_id="L01")
    for i, (command, out, code) in enumerate(COMMANDS):
        shell(deck, command, out, code)
        if i == 2:  # one turn of three tool calls: one step, whose line says "(+2 more)"
            calls = (Call("read work/README.txt", "The key is checked one byte at a time."),
                     Call("$ ls -la work", "total 32\n-rwxr-xr-x 1 u u 14480 crackme\n-rw-r--r-- 1 u u 212 README.txt"),
                     Call("plan: find the compare loop in main", ""))
            deck.report("L01", TurnReport(action=calls[0].text + "  (+2 more)", output=calls[0].output, calls=calls, tokens=3000,
                                          plan="find the compare loop in main"))
        if i == 6:
            says(deck, SAID)
        if i == 9:
            deck.report("L01", TurnReport(turn=False, alerts=(Alert(
                AlertKind.STALL, "No new file, artifact, plan or candidate flag for 8 turns (now turn 11; the last new finding was at turn 3).",
                suggestions(("e", "Escalate to a stronger model with a summary"), ("r", "Redirect with a new approach"))),)))
    deck.report("L01", TurnReport(turn=False, alerts=(
        Alert(AlertKind.LOOP, "The same command ran 2 times in the last 6 turns: objdump -s -j .rodata work/crackme | head -30.",
              suggestions(("h", "Hint", "You are repeating objdump -s -j .rodata work/crackme | head -30: try something else."),
                          ("k", "Kill and re-queue fresh"))),
        Alert(AlertKind.EFFORT, "13 turns (budget 9) on a 300-point challenge with 41 solves. The budget shrinks as points fall and solves rise.",
              suggestions(("h", "Hint: it is simpler than this", "Look for the simple path first."), ("k", "Kill and re-queue fresh"))),
    )))
    deck.note("L01", "tokens are at 96% of this lane's cap")
    deck.report("L01", TurnReport(action="says: I have the table now; computing the key.", tokens=9000))
    assert len(lane.actions) == 23 and lane.pending is not None and lane.pending.kind is PendingKind.BUDGET
    return deck, app, lane


# ---------------------------------------------------------------------- entries and their rows


def test_a_run_of_tool_calls_is_one_entry_of_two_rows_how_many_and_the_last_one():
    deck, _, lane = one_lane()
    for i in range(12):
        shell(deck, f"xxd -s {i * 16} -l 16 work/crackme", f"{i * 16:08x}: 7f45 4c46 0201 0100\n")
    (entry,) = views.entries(lane.actions)
    assert (entry.first, entry.kind, len(entry.actions)) == (0, "calls", 12)
    assert calm(deck, lane) == ["⏺ 12 tool calls", "  ⎿ $ xxd -s 176 -l 16 work/crackme → 000000b0: 7f45 4c46 0201 0100"]
    shell(deck, "xxd -s 192 -l 16 work/crackme", "000000c0: 0300 3e00 0100 0000\n")
    (entry,) = views.entries(lane.actions)
    assert (entry.first, len(entry.actions)) == (0, 13)  # the same entry, by the same key: the view draws it again in place
    assert calm(deck, lane) == ["⏺ 13 tool calls", "  ⎿ $ xxd -s 192 -l 16 work/crackme → 000000c0: 0300 3e00 0100 0000"]


def test_anything_that_is_not_a_tool_call_ends_a_run_and_a_run_of_one_is_one_plain_row():
    deck, _, lane = one_lane()
    shell(deck, "file a.bin", "a.bin: data\n")
    says(deck, "I will look at the header.")
    shell(deck, "xxd a.bin | head -1", "00000000: 7f45\n")
    shell(deck, "strings a.bin", "GNU\n")
    deck.note("L01", "the handout has one file")
    shell(deck, "ls", "a.bin\n")
    deck.report("L01", TurnReport(turn=False, alerts=(Alert(AlertKind.LOOP, "The same command ran 3 times."),)))
    shell(deck, "ls -la", "a.bin\n")
    assert deck.apply(iv.Hint("L01", "try the header")).ok
    shell(deck, "xxd -l 4 a.bin", "00000000: 7f45 4c46\n")
    deck.report("L01", TurnReport(turn=False, pending=Pending(PendingKind.LIVE_BOX, "connect to the live box")))
    shell(deck, "id", "uid=1000\n")
    found = views.entries(lane.actions)
    assert [entry.kind for entry in found] == ["calls", "says", "calls", "note", "calls", "alert", "calls", "message", "calls", "approval", "calls"]
    assert [len(entry.actions) for entry in found] == [1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1]
    assert [entry.first for entry in found] == [0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11]  # each entry's key: its first action
    assert calm(deck, lane) == [
        "⏺ $ file a.bin → a.bin: data",  # a run of one: no "tool calls" row
        "⏺ I will look at the header.",
        "⏺ 2 tool calls",
        "  ⎿ $ strings a.bin → GNU",
        "· the handout has one file",
        "⏺ $ ls → a.bin",
        "▲ Loop alert · turn 4",
        "⏺ $ ls -la → a.bin",
        "› you  try the header",
        "⏺ $ xxd -l 4 a.bin → 00000000: 7f45 4c46",
        "◆ asked you · turn 6: connect to the live box",
        "⏺ $ id → uid=1000",
    ]


def test_a_turn_of_three_tool_calls_counts_three_and_no_calm_row_says_more():
    deck, _, lane = one_lane()
    calls = (Call("read work/README.txt", "The key is checked one byte at a time."), Call("$ ls -la work", "total 32\ncrackme\nREADME.txt"),
             Call("plan: find the compare loop in main", ""))
    deck.report("L01", TurnReport(action="read work/README.txt  (+2 more)", output=calls[0].output, calls=calls))
    assert views.calls_of(lane.actions[0]) == calls
    assert calm(deck, lane) == ["⏺ 3 tool calls", "  ⎿ plan: find the compare loop in main"]
    assert "(+2 more)" in details(deck, lane)[0]  # the step's own line, which details still draws
    deck.report("L01", TurnReport(action="$ id", output="uid=1000"))  # a coding-agent CLI's step: no calls, so it is one call itself
    assert views.calls_of(lane.actions[1]) == (Call("$ id", "uid=1000"),)
    assert calm(deck, lane) == ["⏺ 4 tool calls", "  ⎿ $ id → uid=1000"]
    assert not [row for row in calm(deck, lane) if "more)" in row]


def test_a_long_l1_note_is_one_row_that_says_how_many_lines_more_it_has():
    deck, _, lane = one_lane()
    notes = "\n".join([TRIAGE, *(f"## engine {i:02d} that fits but was not run: it needs a person's arguments" for i in range(40))])[:6000]
    more = notes.count("\n")
    assert len(notes) == 6000 and more > 40
    deck.record_l1("crackme", "intake", "unsure", seconds=14.2, notes=notes, lane_id="L01")
    (row,) = calm(deck, lane)
    assert row.startswith("· L1 intake: unsure (handout: 3 file(s), 41 unpacked member(s)") and row.endswith(f"frida_trace …+{more} lines")
    assert FOLD not in row and "flightdeck" not in row and "routed engine" not in row
    assert len(details(deck, lane)[0]) > 5000  # details has all of it


def test_a_command_of_many_lines_shows_its_first_and_how_many_more_and_a_failed_call_its_status():
    deck, _, lane = one_lane()
    shell(deck, HEREDOC, "b'Qu'\n5175829c\n")
    assert calm(deck, lane) == ["⏺ $ python3 - <<'EOF' …+6 lines → b'Qu' …+1 line"]
    assert FOLD in details(deck, lane)[0]  # as the log keeps it, folded
    says(deck, "next")
    shell(deck, "gdb -q -batch work/crackme 2>&1 | tail -20", "bash: gdb: command not found\n", 127)
    assert calm(deck, lane)[-1] == "⏺ $ gdb -q -batch work/crackme 2>&1 | tail -20 → exit 127 …+1 line"  # the status leads the excerpt
    says(deck, "next")
    deck.report("L01", TurnReport(action="$ r2 -q work/crackme", output=tools._brief("bash: r2: command not found\n", "exit 127", tail=True)))
    assert calm(deck, lane)[-1] == "⏺ $ r2 -q work/crackme → exit 127 · bash: r2: command not found"  # a step with no calls: its own output
    says(deck, "next")
    deck.report("L01", TurnReport(action="$ true", output=""))
    assert calm(deck, lane)[-1] == "⏺ $ true"  # no output: no arrow


def test_an_alert_is_its_label_and_turn_and_an_approval_says_when_it_asked():
    deck, _, lane = one_lane()
    for _ in range(3):
        shell(deck, "ls", "a\n")
    reason = "The same command ran 3 times in the last 6 turns: ls."
    deck.report("L01", TurnReport(turn=False, alerts=(Alert(AlertKind.LOOP, reason),)))
    assert calm(deck, lane)[-1] == "▲ Loop alert · turn 3"
    assert not [row for row in calm(deck, lane) if "The same command" in row]  # the card has the reason, and details
    assert details(deck, lane)[-2:] == ["▲ Loop", f"  {reason}"]
    text = views.entry_text(deck, lane, views.entries(lane.actions)[-1])
    colours = {text.plain[span.start:span.end]: str(span.style) for span in text.spans}
    assert colours == {"▲ ": views.alert_style(AlertKind.LOOP), "Loop": views.alert_style(AlertKind.LOOP), " alert · turn 3": theme.MUTED}
    deck.report("L01", TurnReport(turn=False, pending=Pending(PendingKind.BUDGET, "raise the cap by 50% (now 424k of 400k tokens)")))
    assert calm(deck, lane)[-1] == "◆ asked you · turn 3: raise the cap by 50% (now 424k of 400k tokens)"
    assert details(deck, lane)[-1] == "◆ waiting for you: raise the cap by 50% (now 424k of 400k tokens)"


def test_an_intervention_is_its_line_and_how_many_lines_of_output_it_has():
    deck, _, lane = one_lane()
    shell(deck, "ls", "a\n")
    assert deck.apply(iv.Redirect("L01", "decode it as SSTV")).ok
    player = [action for action in lane.actions if action.kind.value == "player"]
    assert player, [action.kind for action in lane.actions]
    for entry in views.entries(lane.actions):
        if entry.kind != "player":
            continue
        whole = [line.plain for line in views.transcript_lines(deck, lane, entry.actions[0])]
        row = views.entry_text(deck, lane, entry).plain
        assert "\n" not in row and row.startswith(whole[0])
        assert row == whole[0] + (f" …+{len(whole) - 1} line{'' if len(whole) == 2 else 's'}" if len(whole) > 1 else "")


def test_credentials_are_out_of_every_calm_row_and_untrusted_text_is_drawn_as_it_is():
    deck, app, lane = one_lane("simple")
    click = "[@click=app.quit]x[/]"
    deck.report("L01", TurnReport(action=f"$ curl -H 'Authorization: Bearer {JWT}' 127.0.0.1 {osc('ac')} {click}",
                                  output=f"OPENROUTER_API_KEY={OPENROUTER} {osc('ou')}\nmore"))
    deck.note("L01", f"read OPENROUTER_API_KEY={OPENROUTER} {osc('nt')} {click}\nand more")
    says(deck, f"the key is OPENROUTER_API_KEY={OPENROUTER} {osc('sy')} {click}")
    rows = calm(deck, lane)
    assert rows == [
        f"⏺ $ curl -H 'Authorization: Bearer [redacted]' 127.0.0.1 {shown('ac')}^[\\ {click} → OPENROUTER_API_KEY=[redacted] {shown('ou')}^[\\ …+1 line",
        f"· read OPENROUTER_API_KEY=[redacted] {shown('nt')}^[\\ {click} …+1 line",
        f"⏺ the key is OPENROUTER_API_KEY=[redacted] {shown('sy')}^[\\ {click}",
    ]
    both = "\n".join(rows + details(deck, lane))
    assert not [value for value in VALUES if value in both] and OSC not in both and "\x1b" not in both
    assert OPENROUTER in lane.actions[0].output  # the deck keeps it as it was, for the lane's model

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        for switched in (False, True):  # calm, then with details on
            frame, text = terminal_frame(app), region_text(app, "#transcript")
            assert OSC not in frame and not [value for value in VALUES if value in frame], switched
            assert shown("ac") in text and shown("nt") in text and shown("sy") in text and click in text and "[redacted]" in text
            assert app.is_running and app.screen.query_one("#transcript", LaneLog).texts()  # the click in the text is text
            await press(pilot, "ctrl+o")

    drive(app, script, BIG)


# ---------------------------------------------------------------------- the view


def test_the_reported_lane_is_calm_in_the_simple_layout():
    deck, app, lane = busy_lane("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        rows = drawn(app)
        assert len(details(deck, lane)) >= 40 and len(rows) <= 18, rows  # what the console drew before, and now
        whole = calm(deck, lane)
        assert len(rows) == len(whole) == 16  # a row each, and two for a run
        assert all(row == full or (row.endswith("…") and full.startswith(row[:-1])) for row, full in zip(rows, whole)), rows
        assert len([row for row in rows if row.endswith("tool calls")]) == 2 and not [row for row in rows if FOLD in row]
        assert rows[1].startswith("· L1 intake: unsure (handout: 3 file(s)") and rows[1].endswith("…")  # cut at the edge, never wrapped
        assert rows[2:4] == ["⏺ 10 tool calls", "  ⎿ $ python3 - <<'EOF' …+6 lines → b'Qu\\x82\\x9c' …+1 line"]
        assert f"⏺ {SAID}" in rows and "▲ Loop alert · turn 13" in rows
        assert rows[-1] == "◆ asked you · turn 14: raise the cap by 50% (now 62k of 60k tokens)"
        assert not [row for row in rows if "more)" in row or "The same command" in row]
        assert lines(app) == calm(deck, lane)

    drive(app, script, BIG)


def test_the_deck_layout_draws_the_reported_lane_line_for_line_as_before():
    deck, app, lane = busy_lane("deck")

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        assert view.details
        assert lines(app) == details(deck, lane)
        assert log_of(app).texts() == ["\n".join(line.plain for line in views.transcript_lines(deck, lane, action)) for action in lane.actions]
        rows = drawn(app)  # the end of it, wrapped as it was
        assert rows[-1] == "◆ waiting for you: raise the cap by 50% (now 62k of 60k tokens)"
        assert "⏺ says: I have the table now; computing the key." in rows and "▲ Loop" in rows
        assert not [row for row in lines(app) if row.endswith("tool calls")]
        assert footer_line(app).strip().startswith("esc fleet  enter send  / commands") and "ctrl+o" not in footer_line(app)

    drive(app, script, BIG)


def test_ctrl_o_and_the_details_command_switch_the_transcript_and_say_which():
    deck, app, lane = busy_lane("simple")

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        assert not view.details and lines(app) == calm(deck, lane)
        await press(pilot, "ctrl+o")
        assert view.details and lines(app) == details(deck, lane)
        assert status_line(app).strip() == "● details on: every line and every alert (ctrl+o hides them)"
        await press(pilot, "ctrl+o")
        assert not view.details and lines(app) == calm(deck, lane)
        assert status_line(app).strip() == "● details off (ctrl+o shows every line)"
        await press(pilot, "t", "r", "y")  # with a message half written: the key is not typed, and the draft stays
        await press(pilot, "ctrl+o")
        assert view.details and lines(app) == details(deck, lane) and bar(app).field.value == "try"
        await press(pilot, "ctrl+o")
        assert lines(app) == calm(deck, lane) and bar(app).field.value == "try" and app.focused is bar(app).field
        assert not lane.hints  # nothing was sent
        bar(app).clear()
        await send(pilot, app, "/details")
        assert view.details and lines(app) == details(deck, lane)
        assert "details on: every line and every alert (ctrl+o hides them)" in status_line(app)
        await send(pilot, app, "/details")
        assert not view.details and lines(app) == calm(deck, lane) and "details off (ctrl+o shows every line)" in status_line(app)

    drive(app, script, BIG)


def test_the_details_command_in_the_lane_list_says_it_is_the_lane_views():
    deck, app, _ = busy_lane("simple")

    async def script(pilot):
        assert isinstance(app.screen, FleetScreen)
        await press(pilot, "slash")
        await send(pilot, app, "details")
        assert isinstance(app.screen, FleetScreen)
        assert_warning(app, "/details is for a lane's view (every line of its transcript, or the calm one): open a lane first")

    drive(app, script, BIG)


def test_the_transcript_follows_the_layout_until_the_player_sets_details_by_hand():
    deck, app, lane = busy_lane("simple")

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        assert lines(app) == calm(deck, lane)
        await send(pilot, app, "/layout deck")
        assert app.layout == "deck" and view.details and lines(app) == details(deck, lane)
        await send(pilot, app, "/layout simple")
        assert not view.details and lines(app) == calm(deck, lane)
        await press(pilot, "ctrl+o")  # by hand: on, in the simple layout
        assert lines(app) == details(deck, lane)
        await send(pilot, app, "/layout deck")
        assert lines(app) == details(deck, lane)
        await press(pilot, "ctrl+o")  # by hand: off, in the deck layout
        assert lines(app) == calm(deck, lane)
        await send(pilot, app, "/layout simple")
        assert lines(app) == calm(deck, lane)
        await send(pilot, app, "/layout deck")
        assert not view.details and lines(app) == calm(deck, lane)  # the layout no longer changes it
        await press(pilot, "escape")  # the switch is this view's: the next lane opened starts at the layout's
        view = await open_focus(pilot, app, "L01")
        assert view.details and lines(app) == details(deck, lane)

    drive(app, script, (160, 46))


def test_on_a_narrow_terminal_details_start_on_and_ctrl_o_turns_the_transcript_only():
    deck, app, lane = busy_lane("simple")

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        assert view.compact and view.details and lines(app) == details(deck, lane)  # the compact layout, in simple too
        card = region_text(app, "#now-scroll")  # the card's box: what of the card is in view
        assert "needs you now" in card and "/kill" in card
        await press(pilot, "ctrl+o")
        assert not view.details and lines(app) == calm(deck, lane)
        assert region_text(app, "#now-scroll") == card  # the card keeps its compact form: every number stays on it
        assert footer_line(app).strip() == "esc fleet  1-9 0 answer  / cmd  ctrl+n next"  # the compact key line, as it was
        await pilot.resize_terminal(120, 40)  # wide again: the switch stays as the player set it
        await pilot.pause()
        await pilot.pause()
        assert not view.compact and not view.details and lines(app) == calm(deck, lane)

    drive(app, script, (60, 40))


def test_the_transcript_follows_the_lane_at_its_end_and_stays_where_the_player_reads():
    deck, app, lane = one_lane("simple")
    says(deck, "the first words")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        log = log_of(app)
        assert log.max_scroll_y == 0
        for i in range(log.region.height + 4):  # the update that first outgrows the view: no scroll bar was there before it
            says(deck, f"words {i}")
        app.refresh_view()
        await pilot.pause()
        assert log.max_scroll_y > 0 and log.scroll_y == log.max_scroll_y and drawn(app)[-1] == f"⏺ words {log.region.height + 3}"
        for i in range(60):
            says(deck, f"more words {i}")
            if i % 20 == 0:  # as the lane streams: each redraw ends at the end
                app.refresh_view()
                await pilot.pause()
                assert log.scroll_y == log.max_scroll_y and drawn(app)[-1] == f"⏺ more words {i}"
        app.refresh_view()
        await pilot.pause()
        await press(pilot, "pageup")
        at, top = log.scroll_y, drawn(app)[0]
        assert at < log.max_scroll_y
        for i in range(30):
            says(deck, f"while reading back {i}")
        shell(deck, "ls", "a\n")
        app.refresh_view()
        await pilot.pause()
        assert log.scroll_y == at and drawn(app)[0] == top and at < log.max_scroll_y  # still where the player was reading
        await press(pilot, *["pagedown"] * 8)
        assert log.scroll_y == log.max_scroll_y and drawn(app)[-1] == "⏺ $ ls → a"
        shell(deck, "ls -la", "b\n")  # the last entry grows into a run: drawn again in place, and the view stays at the end
        app.refresh_view()
        await pilot.pause()
        assert log.scroll_y == log.max_scroll_y and drawn(app)[-2:] == ["⏺ 2 tool calls", "  ⎿ $ ls -la → b"]

    drive(app, script, (100, 24))


def test_switching_details_while_reading_back_keeps_the_entry_the_player_was_on():
    deck, app, lane = one_lane("simple")
    for i in range(40):
        says(deck, f"words {i}")
        shell(deck, f"xxd -s {i} a.bin", "one\ntwo\n")
        shell(deck, f"xxd -l {i} a.bin", "one\ntwo\n")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        log = log_of(app)
        assert log.scroll_y == log.max_scroll_y > 0
        await press(pilot, "pageup", "pageup")
        first = drawn(app)[0]
        assert first.startswith("⏺ words ") and log.scroll_y < log.max_scroll_y  # an entry's first row is the view's first
        await press(pilot, "ctrl+o")
        assert drawn(app)[0] == first.replace("⏺ ", "⏺ says: ") and log.scroll_y < log.max_scroll_y
        log.scroll_to(y=log.scroll_y + 3, animate=False)  # into the run that follows: its second call
        await pilot.pause()
        number = first.removeprefix("⏺ words ")
        assert drawn(app)[0] == f"⏺ $ xxd -l {number} a.bin"
        await press(pilot, "ctrl+o")
        assert drawn(app)[:2] == ["⏺ 2 tool calls", f"  ⎿ $ xxd -l {number} a.bin → one …+1 line"]  # the entry that holds that call
        await press(pilot, *["pagedown"] * 30)
        assert log.scroll_y == log.max_scroll_y
        await press(pilot, "ctrl+o")  # at the end, the end stays the end
        assert log.scroll_y == log.max_scroll_y and drawn(app)[-1] == "  ⎿  one ⏎ two"

    drive(app, script, (100, 24))


def test_a_narrower_terminal_wraps_the_details_again_and_cuts_no_row_under_the_scroll_bar():
    deck, app, lane = one_lane("simple")
    long = "the table at 0x2010 is filled by a loop that runs before main compares anything, " * 3
    says(deck, long.strip())
    shell(deck, "echo " + "abcdefghij " * 20, "abcdefghij " * 20)
    for i in range(50):
        says(deck, f"words {i}")
    says(deck, long.strip())

    def words_of(rows: list[str]) -> list[str]:
        return " ".join(rows).split()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        log = log_of(app)
        for size in ((160, 30), (100, 30)):
            await pilot.resize_terminal(*size)
            await pilot.pause()
            await pilot.pause()
            width = log.region.width - 2
            assert log.scroll_y == log.max_scroll_y  # it was at the end, and is at the new end
            tail = drawn(app)[-(-(len(long.strip()) + 2) // width + 1):]
            assert words_of(tail)[-len(long.split()):] == long.split() and all(len(row) <= width for row in drawn(app))
            log.scroll_home(animate=False)
            await pilot.pause()
            rows = drawn(app)
            assert words_of(rows)[: len(long.split()) + 1] == ["⏺", *long.split()]  # the model's words: wrapped, never cut
            call = next(row for row in rows if row.startswith("⏺ $ echo"))
            assert len(call) == width and call.endswith("…")  # a tool call: one row, cut at the edge
            await press(pilot, "ctrl+o")
            log.scroll_home(animate=False)
            await pilot.pause()
            rows = drawn(app)
            command = ["⏺", "$", "echo", *["abcdefghij"] * 20]
            assert words_of(rows)[len(long.split()) + 2:][: len(command)] == command and all(len(row) <= width for row in rows)
            await press(pilot, "ctrl+o")
            await press(pilot, *["pagedown"] * 10)

    drive(app, script, (160, 30))


def test_another_theme_draws_the_rows_again_in_its_colours_where_the_player_was():
    deck, app, lane = one_lane("simple")
    nord = themes.BUILTIN["nord"]
    for i in range(60):
        says(deck, f"words {i}")
    deck.note("L01", "a note from flightdeck")

    def colours() -> tuple[str, str]:
        region = log_of(app).region
        rows = screen_lines(app)
        words = next(y for y in range(region.y, region.bottom) if "⏺ words" in rows[y])
        return color_of(app, "words", words), color_of(app, "a note from flightdeck", region.bottom - 1)

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        log = log_of(app)
        assert colours() == (themes.DEFAULT.text, themes.DEFAULT.muted)
        before = lines(app)
        await send(pilot, app, "/theme nord")
        await pilot.pause()
        assert theme.active() is nord and colours() == (nord.text, nord.muted) != (themes.DEFAULT.text, themes.DEFAULT.muted)
        assert lines(app) == before and log.scroll_y == log.max_scroll_y  # every row again, none twice
        await press(pilot, "pageup")
        at, top = log.scroll_y, drawn(app)[0]
        await send(pilot, app, "/theme default")
        await pilot.pause()
        assert log.scroll_y == at and drawn(app)[0] == top and lines(app) == before

    drive(app, script, (100, 24))


def test_a_long_transcript_mounts_its_newest_entries_and_page_up_at_the_top_mounts_more():
    deck, app, lane = one_lane("simple")
    for i in range(MOUNTED + 100):
        says(deck, f"words {i}")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        log = log_of(app)
        assert MOUNTED == 300 and len(log.query(RowText)) == MOUNTED + 1 and log.earlier == 100
        assert log.texts()[:2] == ["· 100 earlier entries: pgup here shows them", "⏺ words 100"] and log.texts()[-1] == "⏺ words 399"
        assert log.scroll_y == log.max_scroll_y
        says(deck, "one more")  # a new entry: mounted under the rest, and the 100 stay 100
        app.refresh_view()
        await pilot.pause()
        assert log.texts()[0] == "· 100 earlier entries: pgup here shows them" and log.texts()[-1] == "⏺ one more"
        log.scroll_home(animate=False)
        await pilot.pause()
        assert drawn(app)[:3] == ["· 100 earlier entries: pgup here shows them", "⏺ words 100", "⏺ words 101"]
        await press(pilot, "pageup")
        assert log.earlier == 0 and len(log.query(RowText)) == MOUNTED + 101 and log.texts()[0] == "⏺ words 0"
        assert drawn(app)[:3] == ["⏺ words 99", "⏺ words 100", "⏺ words 101"]  # the row the player was on, where it was
        await press(pilot, "pageup")
        assert drawn(app)[1] == f"⏺ words {100 - log.region.height}"  # and the next page up is a page
        says(deck, "and another")
        app.refresh_view()
        await pilot.pause()
        assert drawn(app)[1] == f"⏺ words {100 - log.region.height}" and log.texts()[-1] == "⏺ and another"
        log.scroll_end(animate=False)  # at the end again, the log lets the oldest go once it holds twice what it mounts
        await pilot.pause()
        await press(pilot, "pagedown")
        assert log.scroll_y == log.max_scroll_y and drawn(app)[-1] == "⏺ and another"
        for i in range(WINDOW - len(lane.actions)):
            says(deck, f"later words {i}")
        app.refresh_view()
        await pilot.pause()
        assert log.earlier == 0 and len(log.query(RowText)) == len(lane.actions) == WINDOW == 2 * MOUNTED
        says(deck, "the last words")
        app.refresh_view()
        await pilot.pause()
        assert log.earlier == len(lane.actions) - MOUNTED and len(log.query(RowText)) == MOUNTED + 1
        assert log.scroll_y == log.max_scroll_y and drawn(app)[-1] == "⏺ the last words"

    drive(app, script, (100, 24))


def test_reading_back_while_the_lane_goes_on_keeps_a_window_mounted_and_page_down_at_its_end_shows_more():
    deck, app, lane = one_lane("simple")
    for i in range(100):
        says(deck, f"words {i}")

    def rows(log: LaneLog) -> int:
        return len(log.query(RowText))

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        log = log_of(app)
        await press(pilot, "pageup")  # one page back, and the lane goes on
        at, top = log.scroll_y, drawn(app)[0]
        assert at < log.max_scroll_y
        for i in range(2 * WINDOW):
            says(deck, f"later words {i}")
            if i % MOUNTED == 0:
                app.refresh_view()
                await pilot.pause()
                assert rows(log) <= WINDOW + 1
        app.refresh_view()
        await pilot.pause()
        left = len(lane.actions) - WINDOW
        assert WINDOW == 600 and left == 700 and rows(log) == WINDOW + 1  # the window's entries, and a row for the rest
        assert log.texts()[0] == "⏺ words 0" and log.texts()[-2:] == ["⏺ later words 499", "· 700 later entries: pgdn here shows them"]
        assert log.scroll_y == at and drawn(app)[0] == top  # nothing moved under the player
        says(deck, "one more")
        app.refresh_view()
        await pilot.pause()
        assert log.texts()[-2:] == ["⏺ later words 499", "· 701 later entries: pgdn here shows them"] and rows(log) == WINDOW + 1
        log.scroll_end(animate=False)  # the end of what is mounted is not the lane's end: the view does not follow from here
        await pilot.pause()
        assert drawn(app)[-2:] == ["⏺ later words 499", "· 701 later entries: pgdn here shows them"]
        says(deck, "and another")
        app.refresh_view()
        await pilot.pause()
        assert drawn(app)[-2:] == ["⏺ later words 499", "· 702 later entries: pgdn here shows them"]
        first = drawn(app)[0]
        await press(pilot, "pagedown")  # MOUNTED more under what is mounted, as many fewer above; the player's row stays
        assert log.texts()[:2] == ["· 300 earlier entries: pgup here shows them", "⏺ later words 200"]
        assert log.texts()[-2:] == ["⏺ later words 799", "· 402 later entries: pgdn here shows them"] and rows(log) == WINDOW + 2
        assert drawn(app)[0] == first and drawn(app)[-2:] == ["⏺ later words 499", "⏺ later words 500"]
        await press(pilot, "pagedown")  # and the next page down is a page
        assert drawn(app)[0] == "⏺ later words 501"
        log.scroll_end(animate=False)
        await pilot.pause()
        first = drawn(app)[0]
        log.page(1)
        log.page(1)  # a held key: the second comes before the rows are laid out, and moves the window no further
        await pilot.pause()
        assert log.later == 102 and rows(log) == WINDOW + 2 and drawn(app)[0] == first
        log.scroll_end(animate=False)
        await pilot.pause()
        await press(pilot, "pagedown")  # on to the last of them: nothing later is left out
        assert log.texts()[-1] == "⏺ and another" and rows(log) == WINDOW + 1 and log.earlier == len(lane.actions) - WINDOW
        assert log.scroll_y < log.max_scroll_y
        says(deck, "while still reading back")
        app.refresh_view()
        await pilot.pause()
        assert log.scroll_y < log.max_scroll_y and log.texts()[-1] == "· 1 later entry: pgdn here shows it"
        for _ in range(2):  # to the end of what is mounted, a page down for the one entry more, and to the lane's end
            log.scroll_end(animate=False)
            await pilot.pause()
            await press(pilot, "pagedown")
        assert log.later == 0 and log.scroll_y == log.max_scroll_y and drawn(app)[-1] == "⏺ while still reading back"
        says(deck, "the last words")
        app.refresh_view()
        await pilot.pause()
        assert log.scroll_y == log.max_scroll_y and drawn(app)[-1] == "⏺ the last words"
        assert log.earlier == len(lane.actions) - MOUNTED and rows(log) == MOUNTED + 1

    drive(app, script, (100, 24))


def test_paging_back_through_a_long_lane_and_switching_details_there_keep_a_window_mounted():
    deck, app, lane = one_lane("simple")
    for i in range(6 * MOUNTED):
        says(deck, f"words {i}")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        log = log_of(app)
        for start in (4 * MOUNTED, 3 * MOUNTED, 2 * MOUNTED):
            log.scroll_home(animate=False)
            await pilot.pause()
            assert drawn(app)[:2] == [f"· {start + MOUNTED} earlier entries: pgup here shows them", f"⏺ words {start + MOUNTED}"]
            if start == 2 * MOUNTED:  # a held key: the second comes before the rows are laid out, and moves the window no further
                log.page(-1)
                log.page(-1)
                await pilot.pause()
            else:
                await press(pilot, "pageup")  # MOUNTED more above what is mounted; past the window, as many fewer under it
            assert log.earlier == start and len(log.query(RowText)) <= WINDOW + 2
            assert drawn(app)[:2] == [f"⏺ words {start + MOUNTED - 1}", f"⏺ words {start + MOUNTED}"]  # the player's row stays
        assert log.texts()[:2] == ["· 600 earlier entries: pgup here shows them", "⏺ words 600"]
        assert log.texts()[-2:] == ["⏺ words 1199", "· 600 later entries: pgdn here shows them"] and len(log.query(RowText)) == WINDOW + 2
        await press(pilot, "ctrl+o")  # details there: a window from the player's row on, not every entry to the lane's end
        assert drawn(app)[0] == "⏺ says: words 899" and log.earlier == 899
        assert log.texts()[-2:] == ["⏺ says: words 1498", "· 301 later entries: pgdn here shows them"] and len(log.query(RowText)) == WINDOW + 2
        says(deck, "more words")
        app.refresh_view()
        await pilot.pause()
        assert drawn(app)[0] == "⏺ says: words 899" and log.texts()[-1] == "· 302 later entries: pgdn here shows them"

    drive(app, script, (100, 24))


def test_another_lane_opens_at_its_own_end_in_its_own_rows():
    deck, app, lane = one_lane("simple")
    deck.release([Challenge("other", "Other", "misc", 100)], [QueueEntry("other", "glm")])
    for i in range(60):
        says(deck, f"words {i}")
        deck.report("L02", TurnReport(turn=False, action=f"says: other words {i}"))

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        log = log_of(app)
        await press(pilot, "pageup")
        assert log.scroll_y < log.max_scroll_y
        view.show_lane("L02")
        await pilot.pause()
        assert lines(app) == [f"⏺ other words {i}" for i in range(60)]  # the same keys as L01's rows, and none of its text
        assert log.scroll_y == log.max_scroll_y and drawn(app)[-1] == "⏺ other words 59"

    drive(app, script, (100, 24))


def test_a_mouse_button_held_in_the_transcript_stops_it_following_until_it_is_up():
    deck, app, lane = one_lane("simple")
    app.copier = lambda text: ""  # the button comes up over other text: a selection, which is copied (test_clipboard.py)
    for i in range(60):
        says(deck, f"words {i}")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        log = log_of(app)
        at = log.scroll_y
        assert at == log.max_scroll_y
        await pilot.mouse_down(log, offset=(4, 2))
        for i in range(10):
            says(deck, f"under the mouse {i}")
        app.refresh_view()
        await pilot.pause()
        assert log.scroll_y == at < log.max_scroll_y  # nothing moves under a selection being made
        await pilot.mouse_up(app.screen.query_one("#keys"))  # wherever the button comes up
        await pilot.pause()
        assert log.scroll_y == log.max_scroll_y and drawn(app)[-1] == "⏺ under the mouse 9"
        assert app.focused is bar(app).field  # the chat box still has the keys

    drive(app, script, (100, 24))


# ---------------------------------------------------------------------- the key line, help, doctor's room


def test_the_simple_key_line_names_the_details_key_last_and_the_narrowest_simple_terminal_shows_it_whole():
    deck, app, lane = one_lane("simple")
    shell(deck, "ls", "a\n")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        assert footer_line(app).strip() == "esc lanes  / commands  ? help  ctrl+o details"
        deck.report("L01", TurnReport(turn=False, pending=Pending(PendingKind.LIVE_BOX, "connect to the live box")))
        app.refresh_view()
        await pilot.pause()
        assert footer_line(app).strip() == "1-9 answer  esc lanes  / commands  ? help  ctrl+o details"  # whole at the narrowest simple terminal

    drive(app, script, (65, 24))
    assert focus.SIMPLE_KEY_LABELS[-1] == ("ctrl+o", "details")
    assert focus.key_room(65, simple=True) == ([], 59)  # 59 columns at its longest: whole from the first width that is not compact
    assert focus.key_room(120, simple=False)[1] == focus.key_room(120)[1] and "ctrl+o" not in dict(focus.KEY_LABELS)  # the deck's line is as it was
    assert room.room(65, 40, max_lanes=4, containerized=True, layout="simple").focus_keys == ()
    assert room.room(64, 40, max_lanes=4, containerized=True, layout="simple").focus_keys == ("? help", "ctrl+o details")
    assert "ctrl+o details" not in room.room(65, 40, max_lanes=4, containerized=True, layout="deck").focus_keys


def test_help_lists_the_details_key_and_command():
    from ctf_flightdeck.console.commands import BY_NAME, complete, needs_lane, parse
    from ctf_flightdeck.console.screens import KEY_HELP, LANE_KEY_HELP

    assert dict(LANE_KEY_HELP)["ctrl+o"].startswith("Details on or off") and "ctrl+o" not in dict(KEY_HELP)  # a key of a lane's view
    parsed = parse("/details")
    assert parsed.command is BY_NAME["details"] and not needs_lane(parsed) and BY_NAME["details"].args == ""
    assert [c.text for c in complete("/det")] == ["/details "]
