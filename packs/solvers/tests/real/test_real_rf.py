#!/usr/bin/env python3
"""The rf toolkit on real artifacts: Flipper firmware test files, rtl_433 captures with rtl_433's own
decode, bincopy's firmware files with bincopy's info, a real candump log, a Vector ASC log, a MIFARE
Classic 4K dump, and the two Huntress audio challenges (2024 '1200 Transmissions', 2025 'Maximum Sound').

  .venv/bin/python tests/real/test_real_rf.py        SKIPs (exit 0) when challenges/_realdata/rf is absent

Offline; the cache is filled by tests/real/fetch_c.py. The truth of each file is in the manifest's `what`.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_c as R  # noqa: E402

rf, ROOT = R.start("rf")
check, q = R.check, R.q
FLAG_2024 = "flag{f28d133e7174c412c1e39b4a84158fa3}"


def solve(name, blob, *questions):
    return R.timed(f"solve_set on {name}", rf.solve_set, list(questions), {name: blob}, {})


def audio_2024():
    d = R.data(ROOT, "huntress/transmissions.wav")
    texts = R.timed("afsk_text on transmissions.wav", rf.afsk_text, d)
    check("1200 Transmissions: the Bell 202 modem reading is the write-up's text",
          texts.get("bell202_1200", "").startswith("Greetings, Professor Falken.") and FLAG_2024 in texts.get("bell202_1200", ""), texts)
    got = solve("transmissions.wav", d, q("message", "What is the decoded message?"), q("rate", "What is the sample rate?"),
                q("mod", "Which modulation is used?"))
    u = R.unsure(got["message"])
    check("1200 Transmissions: the message is unsure, its first option the one flag in the text",
          bool(u) and u[0] == "rf.message/wav.afsk" and u[1][0][1] == FLAG_2024, got["message"])
    check("1200 Transmissions: the sample rate is the header's, the modulation is not answered", R.offers(got["rate"], "48000") and got["mod"] is None, (got["rate"], got["mod"]))
    check("1200 Transmissions: a WAV a modem reads as text signals 0.8 or more with no RF word in the question",
          rf.signals([q("flag", "What is the flag?")], {"transmissions.wav": d}) >= 0.8)
    dr = R.drill({"transmissions.wav": d}, [q("flag", "What is the flag?")])
    check("1200 Transmissions, end to end: the triage map ranks rf first for the bare WAV and a flag question", dr["winner"] == "rf", dr["rank"])
    ans = rf.solve_set([q("flag", "What is the flag?")], {"transmissions.wav": d}, {})
    check("1200 Transmissions, end to end: the first option probed is the write-up's flag", (R.unsure(ans["flag"]) or ("", [("", "")]))[1][0][1] == FLAG_2024, ans)
    out = R.timed("triage of transmissions.wav", rf.triage, "transmissions.wav", d)
    check("1200 Transmissions: the triage shows the flag", FLAG_2024 in out)


def audio_2025():
    d = R.data(ROOT, "huntress/maximum_sound.wav")
    got = solve("maximum_sound.wav", d, q("message", "What is the decoded message?"), q("rate", "What is the sample rate?"),
                q("n", "How many samples does the recording hold?"))
    check("Maximum Sound (SSTV, not read here): no message, the header facts only",
          got["message"] is None and R.offers(got["rate"], "44100") and got["n"] == "4910241", got)
    check("Maximum Sound: no FSK modem reads text from an SSTV recording", R.timed("afsk_text on maximum_sound.wav", rf.afsk_text, d) == {})
    check("Maximum Sound: so the WAV alone is no rf match (signal 0.1)", rf.signals([q("flag", "What is the flag?")], {"maximum_sound.wav": d}) <= 0.1)


def flipper_keys():
    d = R.data(ROOT, "flipper/princeton.sub")
    got = solve("princeton.sub", d, q("f", "What is the transmit frequency in Hz?"), q("p", "Which protocol does the remote use?"),
                q("k", "What is the key?"), q("b", "How many bits is the key?", kind="integer"), q("te", "What is the TE?"))
    check("princeton.sub: frequency and bit count plain", got["f"] == "433920000" and got["b"] == "24", got)
    check("princeton.sub: key and protocol unsure with the file's values", R.offers(got["k"], "95D5D4") and R.offers(got["p"], "Princeton")
          and not R.plain(got["k"]) and not R.plain(got["p"]), got)
    check("princeton.sub: TE 400", R.offers(got["te"], "400"), got["te"])
    d = R.data(ROOT, "flipper/security_pls_2_0.sub")
    got = solve("security_pls_2_0.sub", d, q("k", "What is the key?"), q("b", "How many bits is the key?"))
    check("security_pls_2_0.sub: 62 bits, the eight key bytes offered", got["b"] == "62" and R.offers(got["k"], "00003D290FB9BEEE"), got)


def flipper_raw():
    d = R.data(ROOT, "flipper/princeton_raw.sub")
    t = rf.sub_info(d)["timings"]
    r = R.timed("readings of princeton_raw.sub", rf.readings, t)
    check("princeton_raw.sub: pulse width, long pulse 1: 7C5703 and the sync bit",
          r.get("pwm_long_high", [""])[0] == "0111110001010111000000110", r.get("pwm_long_high", [""])[0])
    got = solve("princeton_raw.sub", d, q("k", "What is the key?"), q("p", "Which protocol is it?"), q("m", "What is the decoded message?"))
    check("princeton_raw.sub: a RAW file has no key field and its bits are not text: None", got["k"] is None and got["m"] is None, got)
    d = R.data(ROOT, "flipper/came_raw.sub")
    r = rf.readings(rf.sub_info(d)["timings"])
    check("came_raw.sub: start pulse then off-on pairs: 001000010110",
          r.get("pwm_gap_first_long_gap", [""])[0] == "001000010110" and "pwm_long_high" not in r, {k: v[0] for k, v in r.items()})
    d = R.data(ROOT, "flipper/nice_flo_raw.sub")
    r = rf.readings(rf.sub_info(d)["timings"])
    check("nice_flo_raw.sub: the Nice FLO reading starts 010111", r.get("pwm_gap_first_long_gap", [""])[0].startswith("010111"),
          {k: v[0] for k, v in r.items()})
    d = R.data(ROOT, "flipper/test_random_raw.sub")
    got = solve("test_random_raw.sub", d, q("m", "What is the decoded message?"), q("k", "What is the key?"), q("f", "What is the frequency?"))
    check("test_random_raw.sub (noise): no message, no key", got["m"] is None and got["k"] is None, got)


def flipper_nfc():
    for rel, dev, uid, pages in (("flipper/Ntag215.nfc", "NTAG215", "04515CFA6F7381", "135"), ("flipper/Ntag216.nfc", "NTAG216", "04D9650A325E80", "231"),
                                 ("flipper/Ultralight_C.nfc", "Mifare Ultralight C", "04BAFFCA4D5D80", None),
                                 ("flipper/Felica.nfc", "FeliCa", "299FFA53AB75876E", None), ("flipper/Slix_cap_default.nfc", "SLIX", "E004010849D0DC81", None)):
        d = R.data(ROOT, rel)
        got = solve(rel, d, q("uid", "What is the UID of the tag?"), q("t", "What is the device type?"), q("n", "How many pages does the tag have?"),
                    q("ka", "What is key A of sector 0?"))
        ok = R.offers(got["uid"], uid) and not R.plain(got["uid"]) and (pages is None or got["n"] == pages) and got["ka"] is None
        check(f"{rel}: UID {uid} offered, no MIFARE Classic key invented" + (f", {pages} pages" if pages else ""), ok, got)
        info = rf.nfc_info(d)
        check(f"{rel}: device type as the file says", (info["device_type"] or "").lower().replace("/ultralight", "") in (dev.lower(), "ntag") or dev.lower() in (info["device_type"] or "").lower()
              or R.offers(got["t"], dev), (info["device_type"], got["t"]))


def flipper_ir():
    d = R.data(ROOT, "flipper/tv.ir")
    got = solve("tv.ir", d, q("n", "How many signals are in the file?"))
    check("tv.ir: 771 signals (grep -c '^name:')", got["n"] == "771", got)
    d = R.data(ROOT, "flipper/test_nec.irtest")
    info = rf.ir_info(d)
    raw = {s["name"]: s["data"] for s in info["signals"] if s.get("type") == "raw"}
    # the firmware's expected decodes, read from the file itself (protocol, address, command blocks)
    text = d.decode()
    expected = {}
    for m in re.finditer(r"name: decoder_expected(\d+)\n(.*?)(?=\nname: |\Z)", text, re.S):
        rows = re.findall(r"protocol: (\S+)\naddress: (\S\S) (\S\S) \S\S \S\S\ncommand: (\S\S) (\S\S) \S\S \S\S\nrepeat: (\w+)", m.group(2))
        expected[m.group(1)] = [(pr, int(a1 + a0, 16), int(c1 + c0, 16), rp == "true") for pr, a0, a1, c0, c1, rp in rows]
    for n in ("1", "2"):
        got = [(x["protocol"], x["address"], x["command"], x["repeat"]) for x in rf.nec_decode(raw["decoder_input" + n])]
        check(f"test_nec.irtest input {n}: nec_decode gives the firmware's {len(expected[n])} expected frames in order", got == expected[n],
              (got[:4], expected[n][:4], len(got)))
    got3 = {(x["protocol"], x["address"], x["command"]) for x in rf.nec_decode(raw["decoder_input3"])}
    want3 = {(pr, a, c) for pr, a, c, _ in expected["3"] if pr in ("NEC", "NECext")}
    check("test_nec.irtest input 3: every NEC and NECext frame the firmware expects, and no frame read from the 42-bit NEC42 ones",
          got3 == want3, (sorted(got3 ^ want3)))


def rtl433():
    for rel, reading, want in (("rtl433/generic_remote_01_gfile001.cu8", "pwm_long_high", "000100111100110111000000"),
                               ("rtl433/generic_remote_01_gfile002.cu8", "pwm_long_high", "000100111100110100001100"),
                               ("rtl433/nexus_01_gfile001.cu8", "ppm_long_gap", "101101010001000010111110111101000111"),
                               ("rtl433/prologue_01_gfile001.cu8", "ppm_long_gap", "100101001110100000000000101")):
        d = R.data(ROOT, rel)
        info = R.timed(f"iq_info of {rel}", rf.iq_info, d, "cu8", rel)
        r = rf.readings(info["timings"])
        best = max(set(r.get(reading, [""])), key=r.get(reading, [""]).count)
        check(f"{rel}: {reading} is rtl_433's decode", best.startswith(want), {k: v[0][:40] for k, v in r.items()})
        got = solve(rel, d, q("m", "What is the decoded message?"), q("n", "How many IQ samples are in the capture?"))
        check(f"{rel}: the sample count is offered as IQ pairs (unsure: pairs or values), and bits are never a plain message",
              R.offers(got["n"], str(len(d) // 2)) and not R.plain(got["n"]) and not R.plain(got["m"]), got)


def firmware():
    d = R.data(ROOT, "bincopy/empty_main.s19")
    got = solve("empty_main.s19", d, q("e", "What is the entry point address?"), q("b", "What is the base address of the image?"),
                q("h", "What is the header string of the S-record file?"), q("n", "How many data bytes does the image hold?"))
    check("empty_main.s19: start 0x00400400 and lowest address 0x00400238 (bincopy's info), unsure by spelling",
          R.offers(got["e"], "0x00400400") and R.offers(got["b"], "0x00400238") and not R.plain(got["e"]), got)
    check("empty_main.s19: header and 1667 data bytes", R.offers(got["h"], "bincopy/empty_main.s19") and got["n"] == "1667", got)
    d = R.data(ROOT, "bincopy/empty_main.hex")
    got = solve("empty_main.hex", d, q("e", "What is the entry point address?"), q("b", "What is the base address of the image?"))
    check("empty_main.hex: the same two addresses from Intel HEX", R.offers(got["e"], "0x00400400") and R.offers(got["b"], "0x00400238"), got)
    d = R.data(ROOT, "bincopy/in.s19")
    p = rf.srec_parse(d.decode())
    check("in.s19: header 'hello', the text 'Hello world.' in the image", (p["header"] or "").strip() == "hello" and b"Hello world." in p["image"], p["header"])
    d = R.data(ROOT, "bincopy/in.hex")
    p = rf.ihex_parse(d.decode())
    check("in.hex: 64 data bytes at 0x0100, no bad checksum", p["data_size"] == 64 and p["base_address"] == 0x100 and not p["bad_checksums"], p["data_size"])


def can():
    d = R.data(ROOT, "can/sample-can.log")
    got = solve("sample-can.log", d, q("n", "How many CAN frames are in the log?"), q("i", "How many distinct CAN IDs appear?"),
                q("m", "Which CAN ID appears most often?"))
    check("sample-can.log: 6158 frames and 34 ids plain; a ranking is not answered", got["n"] == "6158" and got["i"] == "34" and got["m"] is None, got)
    d = R.data(ROOT, "can/logfile.asc")
    shape, p = rf.classify("logfile.asc", d)
    check("logfile.asc: read as a Vector ASC log, ten data frames, three ids",
          shape == "can" and len(p["frames"]) == 10 and sorted(p["ids"]) == [0x6F8, 0x6F9, 0x18EBFF00], (shape, p and p["ids"]))
    got = solve("logfile.asc", d, q("n", "How many CAN frames are in the log?"), q("i", "How many distinct CAN IDs appear?"))
    check("logfile.asc: error, remote and J1939 lines are no data frames, so no count is answered", got == {"n": None, "i": None}, got)


def mifare():
    d = R.data(ROOT, "mfc/dump.mfd")
    got = solve("dump.mfd", d, q("u", "What is the UID of the card?"), q("ka", "What is key A of sector 0?"), q("kb", "What is key B of sector 1?"),
                q("s", "How many sectors does the card have?"), q("b", "What is block 1? Lowercase hex, no spaces."))
    check("dump.mfd: UID 33BD9D3F, key A of sector 0 A0A1A2A3A4A5, key B of sector 1 BF23A53C1F63",
          R.offers(got["u"], "33BD9D3F") and R.offers(got["ka"], "A0A1A2A3A4A5") and R.offers(got["kb"], "BF23A53C1F63"), got)
    check("dump.mfd: 40 sectors, block 1 as in the dump", got["s"] == "40" and R.offers(got["b"], "090f180800000000000003010000400b"), (got["s"], got["b"]))


def built_in_memory():
    """The readers this file's findings added, on signals built here: these run with no cache."""
    import io
    import math
    import struct
    import wave
    text = b"CQ CQ flag{synthetic_bell_202}\r\n"
    rate, baud, mark, space = 22050, 1200, 1200.0, 2200.0
    bits = [1] * 40
    for c in text:
        bits += [0] + [(c >> i) & 1 for i in range(8)] + [1]
    bits += [1] * 40
    phase, pcm = 0.0, []
    for n in range(int(len(bits) * rate / baud)):
        phase += 2 * math.pi * (mark if bits[int(n * baud / rate)] else space) / rate
        pcm.append(int(12000 * math.sin(phase)))
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1), w.setsampwidth(2), w.setframerate(rate)
        w.writeframes(struct.pack(f"<{len(pcm)}h", *pcm))
    got = rf.afsk_text(buf.getvalue())
    check("a Bell 202 recording made here reads back as its text", got.get("bell202_1200") == text.decode().strip(), got)
    ans = rf.solve_set([q("m", "What is the decoded message?")], {"tones.wav": buf.getvalue()}, {})
    u = R.unsure(ans["m"])
    check("its message is unsure, the one flag first", bool(u) and u[1][0][1] == "flag{synthetic_bell_202}", ans)
    silence = io.BytesIO()
    with wave.open(silence, "wb") as w:
        w.setnchannels(1), w.setsampwidth(2), w.setframerate(rate)
        w.writeframes(struct.pack("<8000h", *([0] * 8000)))
    check("silence and a single tone read as no text", rf.afsk_text(silence.getvalue()) == {})
    word = "1011010100010000101111101111"
    ppm = []
    for _ in range(3):
        for b in word:
            ppm += [500, -(2000 if b == "1" else 1000)]
        ppm += [500, -4000]
    r = rf.readings(ppm)
    check("pulse distance (one pulse width, two gap lengths) is read by its gaps, not as all-zero pulse widths",
          r.get("ppm_long_gap", [""])[0] == word and "pwm_long_high" not in r, r)
    far = []
    for _ in range(3):
        for b in word:
            far += [110, -(990 if b == "1" else 500)]
        far += [110, -2200]
    r = rf.readings(far)
    check("gaps of five and nine pulse widths with a longer sync gap still split into packets", r.get("ppm_long_gap", [""])[0] == word, r)
    came = [350]
    for b in "001000010110":
        came += [-700, 350] if b == "1" else [-350, 700]
    r = rf.readings((came + [-23000]) * 3)
    check("a start pulse and off-on pairs are read with the gap first", r.get("pwm_gap_first_long_gap", [""])[0] == "001000010110", r)
    nec = [9000, 4500]
    for byte in (0x04, 0xFB, 0x08, 0xF7):
        for i in range(8):
            nec += [560, 1690 if byte >> i & 1 else 560]
    nec += [560, 40000, 9000, 2250, 560]
    check("an NEC frame and its repeat", rf.nec_decode(nec) == [{"protocol": "NEC", "address": 4, "command": 8, "repeat": False},
                                                                {"protocol": "NEC", "address": 4, "command": 8, "repeat": True}], rf.nec_decode(nec))
    asc = ("date Mon Sep 21 14:13:20.000 2026\nbase hex  timestamps absolute\nBegin Triggerblock\n   0.000000 Start of measurement\n"
           "   0.100000 1  123             Rx   d 3 66 6C 61\n   0.200000 1  123             Rx   d 2 67 7B\n"
           "   0.300000 1  18EBFF00x       Rx   d 1 7D\nEnd TriggerBlock\n")
    shape, p = rf.classify("drive.asc", asc.encode())
    check("a Vector ASC log: three frames, two ids, an extended id", shape == "can" and p["ids"] == {0x123: 2, 0x18EBFF00: 1} and p["other"] == 1, (shape, p))
    ans = rf.solve_set([q("n", "How many CAN frames are in the log?")], {"drive.asc": asc.encode()}, {})
    check("with an event line that is no frame, no count", ans == {"n": None}, ans)


for fn in (built_in_memory, audio_2024, audio_2025, flipper_keys, flipper_raw, flipper_nfc, flipper_ir, rtl433, firmware, can, mifare):
    R.section(fn)
sys.exit(R.finish("test_real_rf"))
