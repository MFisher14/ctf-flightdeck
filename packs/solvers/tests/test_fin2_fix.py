"""FIX wire oracles are simplefix, plus hand-specified session traces.

No engine encoder exists. Independently generated frames cover FIX Session
Layer June 2020 sequence semantics and length/data rules from FIX dictionaries.
"""
import random

import pytest
import simplefix

import fin2_fix as fix


def frame(seq=1, kind="0", extra=(), version="FIX.4.4", sender="BUY", target="SELL"):
    oracle = simplefix.FixMessage()
    for tag, value in [(8, version), (35, kind), (49, sender), (56, target),
                       (34, seq), (52, "20261105-12:30:00.100"), *extra]:
        oracle.append_pair(tag, value)
    return oracle.encode()


def codes(result):
    return [finding["code"] for finding in result["findings"]]


@pytest.mark.parametrize("version", ["FIX.4.2", "FIX.4.4", "FIXT.1.1"])
def test_reference_encoder_and_parser(version):
    raw = frame(kind="D", version=version, extra=[(11, "ORDER-42"), (55, "BANK"),
                (54, "1"), (38, "123"), (40, "2"), (44, "1.25")])
    parsed = fix.parse_message(raw)
    oracle = simplefix.FixParser()
    oracle.append_buffer(raw)
    external = oracle.get_message()
    assert [(str(f["tag"]).encode(), f["value"].encode("latin-1"))
            for f in parsed["fields"]] == external.pairs
    assert parsed["type_name"] == "NewOrderSingle"
    assert parsed["version"] == version
    assert parsed["length"] == len(raw)


def test_binary_length_fields_contain_fake_framing_and_soh():
    data = b"CSCTF{in_binary}\x0010=000\x018=FIX.4.2\x01\xff"
    raw = frame(kind="A", extra=[(98, 0), (108, 30), (95, len(data)), (96, data)])
    fields = fix.parse_message(raw)["fields"]
    assert next(f["value"] for f in fields if f["tag"] == 96).encode("latin-1") == data
    assert fix.analyze(raw)["flags"] == ["CSCTF{in_binary}"]


@pytest.mark.parametrize("length_tag,data_tag", [(90, 91), (93, 89), (95, 96), (212, 213),
    (348, 349), (350, 351), (352, 353), (354, 355), (356, 357), (358, 359),
    (360, 361), (362, 363), (364, 365), (445, 446), (618, 619), (621, 622)])
def test_all_supported_length_pairs(length_tag, data_tag):
    # FIX 4.2/4.4 dictionary Length/Data pairs, stated independently of engine;
    # simplefix constructs delimiters/framing and expected bytes are literal.
    raw = frame(extra=[(length_tag, 3), (data_tag, b"A\x01B")])
    assert next(f["value"] for f in fix.parse_message(raw)["fields"]
                if f["tag"] == data_tag) == "A\x01B"


def test_repeating_groups_are_lossless_not_overwritten():
    raw = frame(kind="8", extra=[(453, 2), (448, "BANK-A"), (447, "D"), (452, 1),
                                (448, "BANK-B"), (447, "D"), (452, 3)])
    parties = [f["value"] for f in fix.parse_message(raw)["fields"] if f["tag"] == 448]
    assert parties == ["BANK-A", "BANK-B"]


def test_pipe_is_explicit_and_checksum_uses_soh():
    raw = frame()
    with pytest.raises(fix.FixError):
        fix.parse_message(raw.replace(b"\x01", b"|"))
    assert fix.parse_message(raw.replace(b"\x01", b"|"), pipe=True) == fix.parse_message(raw)


def test_gap_recovery_does_not_advance_across_missing_messages():
    result = fix.analyze(frame(1) + frame(3) + frame(2), initial_sequence=1)
    assert codes(result) == ["sequence_gap"]
    assert result["sessions"][0]["next_expected"] == 4
    assert result["sessions"][0]["buffered_sequences"] == []


def test_gaps_are_per_direction_and_partial_capture_anchors():
    result = fix.analyze(frame(40) + frame(6, sender="SELL", target="BUY") + frame(41))
    assert codes(result) == []
    assert [s["next_expected"] for s in result["sessions"]] == [42, 7]
    result = fix.analyze(frame(40), initial_sequence=1)
    assert codes(result) == ["sequence_gap"]
    assert result["sessions"][0]["next_expected"] == 1


def test_replay_requires_orig_time_and_does_not_rewind():
    good = [(43, "Y"), (122, "20261105-12:29:00")]
    result = fix.analyze(frame(1) + frame(1, extra=good) + frame(2), initial_sequence=1)
    assert codes(result) == ["possible_duplicate"]
    assert result["sessions"][0]["next_expected"] == 3
    assert codes(fix.analyze(frame(1) + frame(1))) == ["sequence_too_low"]
    assert "missing_orig_sending_time" in codes(fix.analyze(frame(extra=[(43, "Y")])))
    assert "future_orig_sending_time" in codes(fix.analyze(frame(extra=[
        (43, "Y"), (122, "20261105-12:31:00")])))


def test_gapfill_and_duplicate_gapfill_and_reset_mode():
    gap = frame(2, "4", [(123, "Y"), (36, 5)])
    result = fix.analyze(frame(1) + gap + frame(5), initial_sequence=1)
    assert codes(result) == []
    assert result["sessions"][0]["next_expected"] == 6
    stale = fix.analyze(frame(1) + gap + gap)
    assert "duplicate_gap_fill" in codes(stale)
    reset = fix.analyze(frame(1) + frame(999, "4", [(36, 20)]) + frame(20))
    assert codes(reset) == ["sequence_reset"]
    assert reset["sessions"][0]["next_expected"] == 21


def test_out_of_order_gapfill_retains_jump():
    raw = frame(1) + frame(3, "4", [(123, "Y"), (36, 10)]) + frame(2) + frame(10)
    result = fix.analyze(raw)
    assert codes(result) == ["sequence_gap", "deferred_gap_fill"]
    assert result["sessions"][0]["next_expected"] == 11


def test_trader_subids_share_session_sequences():
    result = fix.analyze(frame(1, extra=[(50, "TRADER-A")]) +
                         frame(2, extra=[(50, "TRADER-B")]), initial_sequence=1)
    assert codes(result) == []
    assert len(result["sessions"]) == 1
    assert result["sessions"][0]["next_expected"] == 3


def test_application_before_logon_and_after_logout():
    assert codes(fix.analyze(frame(kind="D"), initial_sequence=1)) == ["application_outside_session"]
    raw = frame(1, "A", [(98, 0), (108, 30)]) + frame(2, "5") + frame(3, "D")
    assert codes(fix.analyze(raw)) == ["application_outside_session"]


def test_buffered_logout_applies_after_missing_application():
    # Capture arrives 1,3,2,4; application 2 is before Logout 3 in session order.
    raw = (frame(1, "A", [(98, 0), (108, 30)]) + frame(3, "5") +
           frame(2, "D") + frame(4, "D"))
    result = fix.analyze(raw, initial_sequence=1)
    outside = [f["message"] for f in result["findings"] if f["code"] == "application_outside_session"]
    assert outside == [3]
    assert all(m["session_applied"] for m in result["messages"])
    assert result["sessions"][0]["next_expected"] == 5


def test_invalid_duplicate_does_not_overwrite_buffered_gapfill():
    raw = (frame(1, "A", [(98, 0), (108, 30)]) +
           frame(3, "4", [(123, "Y"), (36, 10)]) +
           frame(3, "4", [(123, "Y"), (36, 2)]) + frame(2))
    result = fix.analyze(raw, initial_sequence=1)
    assert "invalid_sequence_reset" in codes(result)
    assert result["sessions"][0]["next_expected"] == 10
    assert result["messages"][1]["session_applied"] is True
    assert result["messages"][2]["session_applied"] is False


def test_conflicting_valid_duplicate_preserves_first_buffered_message():
    raw = (frame(1) + frame(3, "4", [(123, "Y"), (36, 10)]) +
           frame(3, "4", [(123, "Y"), (36, 5)]) + frame(2))
    result = fix.analyze(raw)
    assert "conflicting_buffered_sequence" in codes(result)
    assert result["sessions"][0]["next_expected"] == 10


def test_buffered_application_uses_logon_version_in_session_order():
    raw = (frame(2, "D", version="FIXT.1.1") +
           frame(1, "A", [(98, 0), (108, 30), (1137, "7")], "FIXT.1.1"))
    result = fix.analyze(raw, initial_sequence=1)
    assert codes(result) == ["sequence_gap"]
    assert result["messages"][0]["application_version"] == "FIX.5.0"
    assert result["messages"][0]["session_applied"] is True


def test_many_flag_values_preserve_first_seen_order_and_deduplicate():
    flags = [f"CSCTF{{flag_{i}}}" for i in range(1000)]
    result = fix.analyze(frame(extra=[(58, " ".join(flags + flags))]))
    assert result["flags"] == flags


def test_fixt_logon_reset_ack_and_app_version_override():
    a = [(98, 0), (108, 30), (141, "Y"), (1137, "7")]
    raw = frame(1, "A", a, "FIXT.1.1")
    raw += frame(1, "A", a, "FIXT.1.1", "SELL", "BUY")
    raw += frame(2, "D", [(11, "ID"), (55, "BANK")], "FIXT.1.1")
    raw += frame(3, "D", [(1128, "9")], "FIXT.1.1")
    result = fix.analyze(raw, initial_sequence=1)
    assert codes(result) == ["logon_reset", "logon_reset"]
    assert result["messages"][2]["application_version"] == "FIX.5.0"
    assert result["messages"][3]["application_version"] == "FIX.5.0SP2"


def test_testrequest_response_and_unanswered():
    req = frame(1, "1", [(112, "probe")])
    reply = frame(1, "0", [(112, "probe")], sender="SELL", target="BUY")
    assert codes(fix.analyze(req + reply)) == []
    assert codes(fix.analyze(req)) == ["unanswered_test_request"]
    assert codes(fix.analyze(reply)) == ["unmatched_heartbeat"]
    assert codes(fix.analyze(frame(kind="1"))) == ["missing_test_req_id"]


def test_resend_range_semantics():
    result = fix.analyze(frame(kind="2", extra=[(7, 42), (16, 0)]))
    assert result["messages"][0]["resend_range"] == {"begin": 42, "end": 0, "through_latest": True}
    assert codes(fix.analyze(frame(kind="2", extra=[(7, 42), (16, 10)]))) == ["invalid_resend_range"]


def test_text_fragment_recovery_has_provenance():
    result = fix.analyze(frame(1, extra=[(58, "CSCTF{split_")]) + frame(2, extra=[(58, "text}")]))
    assert result["flags"] == []
    assert result["joined_text_candidates"] == ["CSCTF{split_text}"]
    assert result["text_fragments"] == [{"message": 0, "tag": 58, "value": "CSCTF{split_"},
                                         {"message": 1, "tag": 58, "value": "text}"}]


@pytest.mark.parametrize("extra", [[(95, 4), (96, b"abc")], [(96, b"abc")], [(95, 3)],
                                  [(95, 3), (58, "abc")], [(49, "DUP")], [(52, "invalid")]])
def test_structurally_invalid_frames(extra):
    with pytest.raises(fix.FixError):
        fix.parse_message(frame(extra=extra))


def test_checksum_length_and_trailing_bytes_rejected():
    raw = frame()
    for malformed in [raw[:-4] + b"999\x01", raw.replace(b"9=", b"9=1", 1),
                      raw[:-1], raw + b"junk", raw[1:], raw + raw[:-1]]:
        with pytest.raises(fix.FixError):
            fix.parse_stream(malformed)
    with pytest.raises(fix.FixError):
        fix.parse_message(raw + raw)
    assert len(fix.parse_stream(raw + b"\r\n" + raw)) == 2


@pytest.mark.parametrize("bad", [None, 1, {}, [], object(), "\U0001f600", b"", b"\x00", b"9=2\x01"])
def test_fail_closed_public_entrypoints(bad):
    for function in [fix.parse_message, fix.parse_stream, fix.analyze]:
        with pytest.raises(fix.FixError):
            function(bad)


def test_bounded_options_and_numeric_fields(monkeypatch):
    for value in [0, -1, 2**100, 1.0, True, "1", object()]:
        with pytest.raises(fix.FixError):
            fix.analyze(frame(), initial_sequence=value)
    with pytest.raises(fix.FixError):
        fix.parse_message(frame(), pipe="yes")
    for seq in [0, -1, "9" * 100, "abc", 2**31]:
        with pytest.raises(fix.FixError):
            fix.parse_message(frame(seq))
    monkeypatch.setattr(fix, "MAX_BYTES", 1)
    with pytest.raises(fix.FixError):
        fix.parse_stream(frame())


def test_seeded_malformed_inputs_do_not_leak_exceptions():
    rng = random.Random(742)
    valid = frame(extra=[(58, "flag carrier")])
    for _ in range(250):
        data = bytearray(valid)
        if rng.randrange(2):
            del data[rng.randrange(len(data)):]
        else:
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            fix.analyze(data)
        except fix.FixError:
            pass


def test_cli(tmp_path, capsys):
    path = tmp_path / "messages.fix"
    path.write_bytes(frame())
    assert fix.main([str(path)]) == 0
    assert '"format": "FIX"' in capsys.readouterr().out
    assert fix.main(["--help"]) == 0
    assert fix.main([]) == 2
    assert fix.main([str(path) + ".missing"]) == 2
    assert fix.main([str(path), "--initial-sequence", "0"]) == 2
    assert fix.main(123) == 2
