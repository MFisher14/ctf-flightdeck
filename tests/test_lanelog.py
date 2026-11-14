"""The lane's calm transcript (details off): what views.entries and views.entry_text make of a
lane's log. Every lane here is synthetic: its commands and outputs are written in this file and
nothing is run.
"""

from __future__ import annotations

from ctf_flightdeck.agent import tools
from ctf_flightdeck.console import theme, views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Alert, AlertKind, Call, Challenge, DeckConfig, Lane, Pending, PendingKind
from ctf_flightdeck.detect.base import suggestions
from ctf_flightdeck.text import NEWLINE
from test_console import JWT, OPENROUTER, OSC, VALUES, osc, quiet_deck, shown

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
