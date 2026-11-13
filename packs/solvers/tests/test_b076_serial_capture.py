"""B-076: solvers/toolkits/serial_capture.py -- socat -v -x logs, XMODEM reassembly, the sweep re-entering on
the transfers (ctf/recover), the CLI and its [intake] table.

Logs are written here (tests/b076_fixtures.py) in socat's hexdump layout, rows ending after a 0x0a byte, with
an XMODEM sender and receiver: the shape of the Spooky Xenoglossophobia log (a JPEG then a short text).
"""
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import archive_expand
import b076_fixtures as fx
import serial_capture as sc
from ctf import event, sweep
from ctf.engines import manifest as M
from ctf.intake import engines as E
from ctf.intake.guard import Guard

REPO = Path(__file__).resolve().parent.parent
SPOOKY = event.load("spooky")
LATIN = (b'Ut clavem invenias ad plura de "loco" cognoscenda, intellegere debes quid imago tibi significet.\n'
         b'Est id quod "supermercado" vocant!\n')
MANIFEST = REPO / "solvers" / "toolkits" / "serial_capture.manifest.toml"


def onion_log(jpg=None, eot_ack=False, **kw) -> str:
    """The evidence's record sequence: NAK, the JPEG's blocks each ACKed, EOT that the receiver never
    ACKs, then a fresh NAK and the Latin note from block 1 (eot_ack=True: the idealised receiver)."""
    log = fx.SocatLog()
    fx.xmodem_send(log, jpg if jpg is not None else fx.fake_jpeg(300), eot_ack=eot_ack, **kw)
    fx.xmodem_send(log, LATIN)
    return log.text()


# ---------------------------------------------------------------- the log


def test_parse_reads_hex_columns_whatever_the_row_split():
    data = b"line one\nline two\n\n" + bytes(range(256))
    text = fx.socat_record(">", data, 0) + fx.socat_record("<", b"\x06", 0)
    assert any(ln.startswith(" 6c 69 6e 65 20 6f 6e 65 0a ") for ln in text.splitlines())   # a row cut after 0x0a
    log = sc.parse_socat(text)
    assert [r.direction for r in log.records] == [">", "<"]
    assert log.records[0].data == data and log.records[0].whole
    assert log.records[1].data == b"\x06"
    assert log.unparsed == 0 and log.notes == []


def test_an_ascii_column_that_looks_like_hex_is_not_read_as_bytes():
    data = b"ab cd ef 01"                        # the ASCII column then reads ' ab cd ef 01'-like text
    log = sc.parse_socat(fx.socat_record(">", data, 0))
    assert log.records[0].data == data


def test_a_record_whose_rows_disagree_with_its_length_is_named():
    text = fx.socat_record(">", b"\x01\x02\x03", 0, length=5)
    log = sc.parse_socat(text)
    assert not log.records[0].whole
    assert any("length=5" in n and "holds 3 byte(s)" in n for n in log.notes)


def test_stream_counts_a_gap_in_the_from_offsets():
    text = fx.socat_record(">", b"abc", 0) + fx.socat_record(">", b"xyz", 10)
    body, gaps = sc.stream(sc.parse_socat(text), ">")
    assert body == b"abcxyz" and gaps == 1


def test_looks_like_socat():
    assert sc.looks_like_socat(onion_log().encode())
    assert not sc.looks_like_socat(b"GET / HTTP/1.1\r\n")
    assert not sc.looks_like_socat(b"> quoted reply line in an email\n")


# ---------------------------------------------------------------- XMODEM


def test_xmodem_keeps_acked_blocks_only_and_trims_the_padding():
    jpg = fx.fake_jpeg(300)
    transfers, notes = sc.xmodem(sc.parse_socat(onion_log(jpg, nak_first=(2,), dup_after=(1,), eot_nak=True)))
    assert [t.name() for t in transfers] == ["xmodem-1.jpg", "xmodem-2.txt"]
    t1, t2 = transfers
    assert t1.payload == jpg                          # the corrupted block 2 and the resent block 1 left out
    assert (t1.blocks, t1.rejected, t1.duplicates, t1.eot, t1.mode) == (3, 1, 1, True, "checksum")
    assert t1.padding == 3 * 128 - len(jpg)
    assert t2.payload == LATIN and t2.eot
    assert (t1.eot_acked, t2.eot_acked) == (False, True)
    assert len(notes) == 1 and "transfer 1: the receiver never ACKed its EOT" in notes[0]


def test_an_acked_eot_then_a_fresh_nak_opens_the_second_transfer():
    jpg = fx.fake_jpeg(300)
    transfers, notes = sc.xmodem(sc.parse_socat(onion_log(jpg, eot_ack=True)))
    assert [(t.payload, t.eot, t.eot_acked) for t in transfers] == [(jpg, True, True), (LATIN, True, True)]
    assert notes == []


def test_an_unacked_eot_then_a_nak_restart_at_block_1_is_a_second_transfer():
    """The Xenoglossophobia record sequence: ... EOT (never ACKed), NAK, block 1, ACK, block 2, ACK, EOT, ACK.
    The NAK is no NAK of the EOT (the sender does not re-send EOT): block 1 starts the Latin note."""
    for first in (fx.fake_jpeg(300), b"one block only\n"):         # last block 3, and last block 1 (a 'duplicate')
        log = fx.SocatLog()
        fx.xmodem_send(log, first, eot_ack=False)
        fx.xmodem_send(log, LATIN)
        transfers, notes = sc.xmodem(sc.parse_socat(log.text()))
        assert [t.payload for t in transfers] == [first, LATIN]
        t1, t2 = transfers
        assert (t1.eot, t1.eot_acked, t1.out_of_sequence, t1.duplicates) == (True, False, 0, 0)
        assert (t2.index, t2.blocks, t2.eot_acked, t2.mode, t2.rejected) == (2, 2, True, "checksum", 0)
        assert any("never ACKed its EOT" in n for n in notes)


def test_a_block_1_right_after_an_unanswered_eot_starts_a_new_transfer_even_without_a_nak():
    log = fx.SocatLog()
    fx.xmodem_send(log, b"A" * 200, eot_ack=False)
    fx.xmodem_send(log, b"B" * 100, start=False)
    t1, t2 = sc.xmodem(sc.parse_socat(log.text()))[0]
    assert (t1.payload, t2.payload) == (b"A" * 200, b"B" * 100)


def test_a_restart_in_crc_mode_after_a_checksum_transfer_is_read_with_crcs():
    log = fx.SocatLog()
    fx.xmodem_send(log, b"first file\n" * 20, eot_ack=False)
    fx.xmodem_send(log, b"second, crc\n" * 30, crc=True)
    t1, t2 = sc.xmodem(sc.parse_socat(log.text()))[0]
    assert (t1.mode, t2.mode) == ("checksum", "crc")
    assert t2.payload == b"second, crc\n" * 30 and t2.rejected == 0


def test_a_crc_restart_whose_first_block_also_passes_the_checksum_is_read_by_the_receivers_c():
    """A CRC block whose 8-bit sum equals its CRC's high byte reads as a checksum block too (1 in 256): after
    an unanswered EOT the receiver's 'C' decides, so the new transfer is CRC and its later blocks are kept."""
    import binascii
    body = next(b for b in (bytes([i, j]) + b"crc restart " * 10 for i in range(256) for j in range(256))
                if sum(b.ljust(128, b"\x1a")) & 0xFF == binascii.crc_hqx(b.ljust(128, b"\x1a"), 0) >> 8)
    second = body.ljust(128, b"\x1a") + b"block two " * 10
    log = fx.SocatLog()
    fx.xmodem_send(log, b"first file\n" * 20, eot_ack=False)
    fx.xmodem_send(log, second, crc=True)
    t1, t2 = sc.xmodem(sc.parse_socat(log.text()))[0]
    assert (t1.mode, t2.mode, t2.blocks, t2.rejected) == ("checksum", "crc", 2, 0)
    assert t2.payload == second


def test_a_naked_eot_resent_and_acked_stays_one_transfer():
    log = fx.SocatLog()
    fx.xmodem_send(log, b"Z" * 300, eot_nak=True)
    [t], notes = sc.xmodem(sc.parse_socat(log.text()))
    assert t.payload == b"Z" * 300 and t.eot and t.eot_acked and notes == []


def test_a_log_that_ends_on_an_unacked_eot_says_so():
    log = fx.SocatLog()
    fx.xmodem_send(log, b"tail" * 40, eot_ack=False)
    [t], notes = sc.xmodem(sc.parse_socat(log.text()))
    assert t.payload == b"tail" * 40 and t.eot and not t.eot_acked
    assert notes == ["transfer 1: the log ends with its EOT never ACKed"]


def test_a_valid_block_the_receiver_naks_and_the_sender_never_resends_is_not_kept():
    log = fx.SocatLog()
    log.add("<", bytes([fx.NAK]))
    log.add(">", fx.xmodem_block(1, b"A" * 128))
    log.add("<", bytes([fx.ACK]))
    log.add(">", fx.xmodem_block(2, b"B" * 128))
    log.add("<", bytes([fx.NAK]))                      # refused: the receiver never kept these bytes
    log.add(">", bytes([fx.EOT]))
    log.add("<", bytes([fx.ACK]))
    [t], _ = sc.xmodem(sc.parse_socat(log.text()))
    assert t.payload == b"A" * 128 and t.rejected == 1


def test_crc_mode_and_1k_blocks():
    payload = bytes((i * 7) % 251 for i in range(2500))
    log = fx.SocatLog()
    fx.xmodem_send(log, payload, crc=True, size=1024, sender="<")
    [t], _ = sc.xmodem(sc.parse_socat(log.text()))
    assert t.mode == "crc" and t.blocks == 3 and t.payload == payload and t.padding == 3 * 1024 - 2500


def test_a_crc_block_with_a_bad_crc_is_rejected():
    log = fx.SocatLog()
    log.add("<", b"C")
    log.add(">", fx.xmodem_block(1, b"x" * 128, crc=True, corrupt=True))
    log.add("<", bytes([fx.NAK]))
    log.add(">", fx.xmodem_block(1, b"y" * 128, crc=True))
    log.add("<", bytes([fx.ACK]))
    log.add(">", bytes([fx.EOT]))
    log.add("<", bytes([fx.ACK]))
    [t], _ = sc.xmodem(sc.parse_socat(log.text()))
    assert t.payload == b"y" * 128 and t.rejected == 1


def test_a_log_with_no_receiver_side_keeps_blocks_by_their_checks_and_says_so():
    log = fx.SocatLog()
    fx.xmodem_send(log, b"hello serial world\n" * 10, receiver=False)
    [t], notes = sc.xmodem(sc.parse_socat(log.text()))
    assert t.payload == b"hello serial world\n" * 10 and not t.acked
    assert any("no receiver side" in n for n in notes)


def test_a_cancelled_transfer_is_marked():
    log = fx.SocatLog()
    log.add("<", bytes([fx.NAK]))
    log.add(">", fx.xmodem_block(1, b"A" * 128))
    log.add("<", bytes([fx.ACK]))
    log.add("<", bytes([fx.CAN, fx.CAN]))
    [t], _ = sc.xmodem(sc.parse_socat(log.text()))
    assert t.cancelled and not t.eot and t.payload == b"A" * 128


def test_a_log_without_xmodem_has_no_transfer():
    text = fx.socat_record(">", b"login: root\n", 0) + fx.socat_record("<", b"Password: \n", 0)
    assert sc.xmodem(sc.parse_socat(text)) == ([], [])


# ---------------------------------------------------------------- members and the sweep


def test_members_gives_the_transfers_or_else_the_streams():
    got, notes = sc.members(onion_log().encode())
    assert [(n, o) for n, _, o in got] == [("socat/xmodem-1.jpg", True), ("socat/xmodem-2.txt", True)]
    assert any("XMODEM transfer 1 (checksum): 3 block(s)" in n for n in notes)
    text = fx.socat_record(">", b"echo spooky{a_flag_cut_across_hexdump_rows}\n", 0) + fx.socat_record("<", b"ok\n", 0)
    got, _ = sc.members(text.encode())
    assert dict((n, b) for n, b, _ in got) == {"socat/stream-gt.bin": b"echo spooky{a_flag_cut_across_hexdump_rows}\n",
                                               "socat/stream-lt.bin": b"ok\n"}
    assert sc.members(b"plain text\n") == ([], [])


@pytest.fixture
def workdir(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.setattr(archive_expand.pw, "candidates", lambda: [])


def pulled(tmp_path, files: dict, description=""):
    ch = tmp_path / "wd" / "7-serial"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps({"id": 7, "name": "serial", "category": "Forensics",
                                                   "description": description}))
    for name, data in files.items():
        (ch / "files" / name).write_bytes(data)
    return ch


def test_the_sweep_reenters_on_an_xmodem_transfer_and_opens_the_archive_it_carried(tmp_path, workdir):
    flag = b"spooky{xmodem_carried_a_zip}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inner/flag.txt", flag + b"\n" + b"padding " * 40)
    log = fx.SocatLog()
    fx.xmodem_send(log, buf.getvalue())
    raw = log.text().encode()
    assert flag not in raw
    ch = pulled(tmp_path, {"serial-capture.log": raw})
    rep = sweep.sweep(ch, SPOOKY)
    assert rep.result.status == "solved" and rep.result.flags == (flag.decode(),)
    chains = {" -> ".join(e.chain) for e in rep.manifest}
    assert "serial-capture.log -> socat/xmodem-1.zip" in chains
    assert "serial-capture.log -> socat/xmodem-1.zip -> inner/flag.txt" in chains
    assert (ch / "unpacked" / "serial-capture.log.unpacked" / "socat" / "xmodem-1.zip").read_bytes() == buf.getvalue()
    assert any("XMODEM transfer 1" in n for n in rep.notes)


def test_the_sweep_finds_a_text_flag_the_hexdump_rows_cut(tmp_path, workdir):
    flag = b"spooky{rows_cut_me_into_pieces_0a}"
    text = fx.socat_record(">", b"cat /flag\n", 0) + fx.socat_record("<", flag + b"\n", 0)
    assert flag not in text.encode()
    ch = pulled(tmp_path, {"console.log": text.encode()})
    rep = sweep.sweep(ch, SPOOKY)
    assert flag.decode() in rep.result.flags


# ---------------------------------------------------------------- the command and intake


def _cli(path: Path, *args):
    env = {k: v for k, v in os.environ.items() if k != "CTF_EVENT"}
    env["CTF_EVENT"] = "spooky"
    return subprocess.run([sys.executable, str(REPO / "solvers" / "toolkits" / "serial_capture.py"), *args, str(path)],
                          capture_output=True, text=True, env=env, cwd=str(path.parent), timeout=300)


def test_cli_writes_the_transfers_and_names_the_passphrase_step(tmp_path):
    log = tmp_path / "serial-capture.log"
    jpg = fx.fake_jpeg(500)
    log.write_text(onion_log(jpg))
    out = _cli(log, "--out", str(tmp_path / "out"))
    assert out.returncode == 0, out.stderr
    lines = out.stdout.strip().splitlines()
    assert (tmp_path / "out" / "xmodem-1.jpg").read_bytes() == jpg
    assert (tmp_path / "out" / "xmodem-2.txt").read_bytes() == LATIN
    assert "passphrases = ['loco', 'supermercado']" in lines
    assert any(ln.startswith("next = python solvers/toolkits/passphrase_harvest.py --steghide") for ln in lines)
    res = json.loads(lines[-1])
    assert res["status"] == "unsure" and "passphrase" in res["notes"]


def test_cli_reports_a_flag_in_a_transfer(tmp_path):
    log = fx.SocatLog()
    fx.xmodem_send(log, b"the flag is spooky{serial_text_transfer}\n")
    f = tmp_path / "s.log"
    f.write_text(log.text())
    res = json.loads(_cli(f).stdout.strip().splitlines()[-1])
    assert res["status"] == "solved" and res["flags"] == ["spooky{serial_text_transfer}"]


def test_cli_on_a_file_that_is_no_socat_log_is_blocked(tmp_path):
    f = tmp_path / "x.log"
    f.write_text("127.0.0.1 - - GET /\n")
    res = json.loads(_cli(f).stdout.strip().splitlines()[-1])
    assert res["status"] == "blocked" and "not a socat" in res["notes"]


def test_intake_plans_serial_capture_on_a_socat_log(tmp_path):
    (tmp_path / "serial-capture.log").write_text(onion_log())
    (tmp_path / "access.log").write_text("127.0.0.1 - - GET /\n")
    m = M.load(MANIFEST)
    plan = E.plan([m], "misc", "", tmp_path, guard=Guard(mode="hook", reason="test"))
    jobs = [j for j in plan.jobs if j.engine == "toolkits.serial_capture"]
    assert [j.files[0].name for j in jobs] == ["serial-capture.log"]
    assert list(m.intake.args) == ["--out", "{out}", "{file}"]


def test_a_receiver_that_falls_back_from_crc_to_checksum_before_any_block_is_read_in_checksum():
    log = fx.SocatLog()
    for _ in range(3):
        log.add("<", b"C")                              # the sender answers no 'C': the receiver falls back
    log.add("<", bytes([fx.NAK]))
    log.add(">", fx.xmodem_block(1, b"checksum mode" * 4))
    log.add("<", bytes([fx.ACK]))
    log.add(">", bytes([fx.EOT]))
    log.add("<", bytes([fx.ACK]))
    [t], _ = sc.xmodem(sc.parse_socat(log.text()))
    assert t.mode == "checksum" and t.payload == b"checksum mode" * 4


def test_a_ymodem_header_block_names_the_file_and_is_not_file_data():
    log = fx.SocatLog()
    log.add("<", b"C")
    log.add(">", fx.xmodem_block(0, b"secret.txt\x0012\x00", crc=True))
    log.add("<", bytes([fx.ACK]))
    log.add(">", fx.xmodem_block(1, b"hello ymodem", crc=True))
    log.add("<", bytes([fx.ACK]))
    log.add(">", bytes([fx.EOT]))
    log.add("<", bytes([fx.ACK]))
    [t], _ = sc.xmodem(sc.parse_socat(log.text()))
    assert t.ymodem_name == "secret.txt" and t.payload == b"hello ymodem" and t.blocks == 1
