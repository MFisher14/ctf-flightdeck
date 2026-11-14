#!/usr/bin/env python3
"""solvers/toolkits/transport.py: the transport / automotive telemetry decoder.

Offline, synthetic, spec-derived. Every input below is BUILT here from the published field layout
(SAE J1939 / J1979 for CAN & OBD-II, ICAO Doc 9871 for Mode S / ADS-B, ITU-R M.1371 for AIS, and
NMEA-0183 for GPS) with KNOWN field values, then read back and asserted. Where scapy ships a
dissector (scapy.layers.can CandumpReader + CAN pcap, scapy.contrib.automotive.obd OBD) the result
is cross-checked against it. No real vessel/aircraft/patient data and no real flags are used.

    CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_transport.py

  can/candump   29-bit id -> J1939 priority/PGN/SA/DA; DLC & data; scapy CandumpReader id cross-check
  can/obd       ISO-TP single-frame mode-01 PID decode (RPM/speed/coolant); scapy OBD cross-check
  can/socketcan raw struct can_frame (LE id + EFF/RTR flags) round-trip
  can/pcap      CAN frames pulled from a scapy-written .pcap through analyze_bytes
  adsb          DF17 extended squitter: DF/ICAO/TC, TC1-4 callsign, 24-bit CRC; synthetic + canonical
  ais           AIVDM type 1 position (MMSI/lat/lon) and type 5 static (name/callsign/dest), with
                multi-fragment reassembly and 6-bit ASCII round-trip
  nmea          GGA + RMC: fix, lat/lon, time, checksum
  flags         a flag hidden in CAN payload ASCII and in the raw file is highlighted
  cli           the command decodes a mixed file and surfaces the flag candidate
  degrade       empty / random / truncated input never crashes
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.dont_write_bytecode = True

import transport as T                                        # noqa: E402

PY = sys.executable
FAILED = []
TMP = Path(tempfile.mkdtemp(prefix="test_transport_"))

try:
    from scapy.layers.can import CAN, CandumpReader          # noqa: E402
    from scapy.all import wrpcap                              # noqa: E402
    HAVE_SCAPY = True
except Exception:  # noqa: BLE001
    HAVE_SCAPY = False


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


# --------------------------------------------------------------------------- synthetic encoders
def _u(v, n):
    return f"{v & ((1 << n) - 1):0{n}b}"


def ais_armor(bits):
    """Bitstring -> ASCII-armored AIS payload + fill-bit count (inverse of transport.ais_unarmor)."""
    fill = (6 - len(bits) % 6) % 6
    bits2 = bits + "0" * fill
    out = []
    for i in range(0, len(bits2), 6):
        v = int(bits2[i:i + 6], 2)
        out.append(chr(v + 48 if v < 40 else v + 56))
    return "".join(out), fill


def ais_enc_text(text, nchars):
    """Text -> AIS 6-bit character bits, padded with '@' to nchars (inverse of transport.ais_text)."""
    r = ""
    for c in text[:nchars]:
        v = ord(c)
        r += _u((v - 64) if v >= 64 else v, 6)
    while len(r) < nchars * 6:
        r += "000000"
    return r


def nmea_cs(body):
    c = 0
    for ch in body:
        c ^= ord(ch)
    return f"{c:02X}"


def aivdm(total, frag, msgid, chan, payload, fill):
    body = f"AIVDM,{total},{frag},{msgid},{chan},{payload},{fill}"
    return "!" + body + "*" + nmea_cs(body)


def modes_frame(df_ca, icao_hex, me):
    """Build a Mode S 112-bit frame (11 header/ME bytes + 24-bit computed parity)."""
    frame11 = bytes([df_ca]) + bytes.fromhex(icao_hex) + me
    par = T.modes_crc_remainder(frame11 + b"\x00\x00\x00")   # remainder over 88 bits = the parity
    return frame11 + par.to_bytes(3, "big")


# =========================================================================== CAN: candump / J1939
def test_can_candump():
    # 29-bit J1939 id 0x18FEF100: prio 6, PF 0xFE(=254,PDU2) PS 0xF1 -> PGN 0xFEF1=65265, SA 0, DA global.
    fr = T.parse_candump_line("(1529487759.000000) can0 18FEF100#0102030405060708")
    j = fr["decode"]["j1939"]
    check("candump: 29-bit extended id parsed", fr["extended"] and fr["decode"]["id_hex"] == "18FEF100", fr["decode"])
    check("candump: J1939 priority 6", j["priority"] == 6, j)
    check("candump: J1939 PGN 65265 (CCVS)", j["pgn"] == 65265 and j["pgn_hex"] == "0FEF1", j)
    check("candump: J1939 source address 0", j["source_address"] == 0, j)
    check("candump: J1939 broadcast dest (PDU2)", j["dest_address"] == 0xFF, j)
    check("candump: DLC 8 and data read back", fr["dlc"] == 8 and fr["data_hex"] == "0102030405060708", fr)

    # PDU1 (destination-specific): id 0x0C EA FF 00 -> PF 0xEA(=234<240), PS=0xFF is the dest addr.
    fr2 = T.parse_candump_line("can0 0CEAFF00 [3] 00 EE 00")
    j2 = fr2["decode"]["j1939"]
    check("candump: PDU1 dest-specific (PF<240)", j2["pdu_format"] == 0xEA and j2["dest_address"] == 0xFF, j2)
    check("candump: PDU1 PGN excludes PS byte", j2["pgn"] == (0xEA << 8), j2)

    # PDU1 with a SPECIFIC (non-global) destination: id 0x0CEA21F0 -> PF 0xEA, PS=0x21 is the dest
    # (33), SA 0xF0. 0x21 != 0xFF proves PS is read as the destination, not the broadcast sentinel.
    fr3 = T.parse_candump_line("(0.0) can1 0CEA21F0#00EE00")
    j3 = fr3["decode"]["j1939"]
    check("candump: PDU1 reads PS as destination (0x21)", j3["dest_address"] == 0x21, j3)
    check("candump: PDU1 source address 0xF0", j3["source_address"] == 0xF0, j3)
    check("candump: PDU1 PGN still 0xEA00 (dest not in PGN)", j3["pgn"] == 0xEA00 and j3["priority"] == 3, j3)

    # bare and space forms parse too
    frb = T.parse_candump_line("123#DEADBEEF")
    check("candump: bare 11-bit id", frb is not None and not frb["extended"] and frb["data_hex"] == "deadbeef", frb)

    # scapy CandumpReader cross-check on the arbitration ids
    if HAVE_SCAPY:
        cf = TMP / "dump.log"
        cf.write_text("(1529487759.000000) can0 18FEF100#0102030405060708\n"
                      "(1529487759.100000) can0 123#DEADBEEF\n")
        sc_ids = [int(p.identifier) for p in CandumpReader(str(cf))]
        my_ids = [f["id_raw"] for f in T.parse_candump_text(cf.read_text())]
        check("candump: ids match scapy CandumpReader", sc_ids == my_ids, (sc_ids, my_ids))
    else:
        check("candump: scapy cross-check (skipped, no scapy)", True)


def test_can_obd():
    # OBD-II mode-01 responses on 0x7E8. ISO-TP single frame: PCI len, 0x41 svc, PID, data.
    rpm = T.parse_candump_line("7E8#04410C1AF8000000")          # (0x1AF8)/4 = 1726 rpm
    check("obd: RPM PID 0x0C decode", rpm["obd"]["pid_name"] == "Engine RPM"
          and rpm["obd"]["value"] == 1726.0 and rpm["obd"]["unit"] == "rpm", rpm.get("obd"))
    spd = T.parse_candump_line("7E8#03410D4B")                  # 0x4B = 75 km/h
    check("obd: speed PID 0x0D decode", spd["obd"]["value"] == 75 and spd["obd"]["unit"] == "km/h", spd.get("obd"))
    cool = T.parse_candump_line("7E8#0341056E0000")             # 0x6E-40 = 70 degC
    check("obd: coolant temp PID 0x05 decode", cool["obd"]["value"] == 70 and cool["obd"]["unit"] == "degC", cool.get("obd"))
    check("obd: response flag set (0x41)", rpm["obd"]["is_response"] and rpm["obd"]["mode"] == 0x01, rpm.get("obd"))
    req = T.parse_candump_line("7DF#02010C0000000000")          # a mode-01 RPM request (no value)
    check("obd: request recognised, no value", req["obd"]["is_response"] is False
          and req["obd"].get("value") is None, req.get("obd"))

    if HAVE_SCAPY:
        from scapy.contrib.automotive.obd.obd import OBD
        o = OBD(bytes.fromhex("410C1AF8"))                      # the OBD message body (post ISO-TP)
        scapy_rpm = o.data_records[0].payload.data
        check("obd: RPM matches scapy OBD dissector", abs(float(scapy_rpm) - 1726.0) < 1e-6, scapy_rpm)
    else:
        check("obd: scapy OBD cross-check (skipped)", True)


def test_can_socketcan_raw():
    import struct
    raw_id = 0x18FEF100 | T.CAN_EFF_FLAG                        # set the extended-frame flag bit
    rec = struct.pack("<IB3s8s", raw_id, 8, b"\x00\x00\x00", bytes.fromhex("0102030405060708"))
    frames = T.parse_socketcan_struct(rec)
    check("socketcan: one 16-byte record parsed", len(frames) == 1, len(frames))
    f = frames[0]
    check("socketcan: EFF flag -> extended id", f["extended"] and f["decode"]["id_hex"] == "18FEF100", f["decode"])
    check("socketcan: J1939 PGN read from raw struct", f["decode"]["j1939"]["pgn"] == 65265, f["decode"])
    check("socketcan: data and DLC", f["dlc"] == 8 and f["data_hex"] == "0102030405060708", f)
    # a standard (11-bit) frame with the RTR flag
    rec2 = struct.pack("<IB3s8s", 0x123 | T.CAN_RTR_FLAG, 0, b"\x00\x00\x00", b"\x00" * 8)
    f2 = T.parse_socketcan_struct(rec2)[0]
    check("socketcan: RTR flag + 11-bit id", f2["remote"] and not f2["extended"] and f2["decode"]["id"] == 0x123, f2)
    check("socketcan: non-16-multiple rejected", T.parse_socketcan_struct(b"\x00" * 15) == [], "should be []")


def test_can_pcap():
    if not HAVE_SCAPY:
        check("pcap: CAN (skipped, no scapy)", True)
        return
    pf = TMP / "can.pcap"
    wrpcap(str(pf), [CAN(identifier=0x18FEF100, data=bytes.fromhex("0102030405060708")),
                     CAN(identifier=0x7E8, data=bytes.fromhex("04410C1AF8000000"))])
    rep = T.analyze_bytes(pf.read_bytes(), str(pf))
    check("pcap: detected as CAN pcap", "pcap:can" in rep["kinds"], rep["kinds"])
    check("pcap: two CAN frames extracted", len(rep["can"]) == 2, len(rep["can"]))
    ids = [f["decode"]["id_hex"] for f in rep["can"]]
    check("pcap: ids 18FEF100 and 7E8", ids == ["18FEF100", "7E8"], ids)
    check("pcap: OBD RPM decoded from pcap frame", rep["can"][1].get("obd", {}).get("value") == 1726.0, rep["can"][1].get("obd"))


# =========================================================================== ADS-B / Mode S
def test_adsb_df17():
    # Canonical published DF17 aircraft-identification example (ICAO Doc 9871): callsign KLM1023.
    d = T.decode_modes(bytes.fromhex("8D4840D6202CC371C32CE0576098"))
    check("adsb: DF17 recognised", d["df"] == 17, d)
    check("adsb: ICAO address 4840D6", d["icao"] == "4840D6", d)
    check("adsb: type code 4 (aircraft id)", d["type_code"] == 4 and d["msg"] == "aircraft_identification", d)
    check("adsb: callsign KLM1023", d["callsign"] == "KLM1023", d)
    check("adsb: canonical CRC validates", d["crc_ok"] is True, d)

    # Synthetic DF17 with our OWN encoded callsign + computed parity (full spec round-trip).
    cs = "CHRONOS1"
    csbits = "".join(f"{T._ADSB_CS.index(c):06b}" for c in cs)
    me = bytes([(1 << 3) | 4]) + int(csbits, 2).to_bytes(6, "big")   # TC=1, category=4
    frame = modes_frame(0x8D, "ABCDEF", me)
    d2 = T.decode_modes(frame)
    check("adsb: synthetic ICAO ABCDEF", d2["icao"] == "ABCDEF", d2)
    check("adsb: synthetic callsign round-trip", d2["callsign"] == "CHRONOS1", d2)
    check("adsb: synthetic CRC validates", d2["crc_ok"] is True, d2)
    # a corrupted frame fails CRC
    bad = bytearray(frame); bad[5] ^= 0xFF
    check("adsb: corrupted frame fails CRC", T.decode_modes(bytes(bad))["crc_ok"] is False, "crc should fail")


def test_adsb_position():
    # A TC=11 airborne-position frame is noted as position (needs even+odd CPR to resolve lat/lon).
    me = bytes([(11 << 3)]) + b"\x00\x00\x00\x00\x00\x00"
    frame = modes_frame(0x8D, "ABCDEF", me)
    d = T.decode_modes(frame)
    check("adsb: TC11 flagged airborne position", d["type_code"] == 11 and d["msg"] == "airborne_position", d)
    check("adsb: CPR fields present", "cpr_lat" in d and "cpr_lon" in d, d)


# =========================================================================== AIS
def test_ais_type1():
    # Type 1 position report: MMSI 227006760, lon 4.5, lat 51.0, SOG 7.4 kn, heading 79.
    lon_raw = round(4.5 * 600000); lat_raw = round(51.0 * 600000)
    bits = (_u(1, 6) + _u(0, 2) + _u(227006760, 30) + _u(0, 4) + _u(0, 8) + _u(74, 10) + _u(0, 1)
            + _u(lon_raw, 28) + _u(lat_raw, 27) + _u(1234, 12) + _u(79, 9) + _u(30, 6)
            + _u(0, 2) + _u(0, 3) + _u(0, 1) + _u(0, 19))
    payload, fill = ais_armor(bits)
    rec = T.parse_aivdm(aivdm(1, 1, "", "A", payload, fill))[0]
    d = rec["decoded"]
    check("ais: type 1 position report", d["type"] == 1 and d["msg"] == "position_report_class_a", d)
    check("ais: MMSI 227006760", d["mmsi"] == 227006760, d)
    check("ais: latitude 51.0", d["lat"] == 51.0, d)
    check("ais: longitude 4.5", d["lon"] == 4.5, d)
    check("ais: SOG 7.4 kn", d["sog_knots"] == 7.4, d)
    check("ais: heading 79", d["heading"] == 79, d)

    # Southern/western hemisphere: lon/lat are signed (two's complement) before the 1/600000 scale.
    # A sign bug would flip the hemisphere, so assert a negative lon AND lat round-trip exactly.
    nlon = round(-73.9876 * 600000); nlat = round(-40.1234 * 600000)
    nbits = (_u(1, 6) + _u(0, 2) + _u(366123456, 30) + _u(0, 4) + _u(0, 8) + _u(123, 10) + _u(0, 1)
             + _u(nlon, 28) + _u(nlat, 27) + _u(0, 12) + _u(200, 9) + _u(0, 6)
             + _u(0, 2) + _u(0, 3) + _u(0, 1) + _u(0, 19))
    npayload, nfill = ais_armor(nbits)
    nd = T.parse_aivdm(aivdm(1, 1, "", "B", npayload, nfill))[0]["decoded"]
    check("ais: negative longitude -73.9876 (two's complement)", nd["lon"] == -73.9876, nd)
    check("ais: negative latitude -40.1234 (two's complement)", nd["lat"] == -40.1234, nd)
    check("ais: MMSI/SOG/heading on neg-coord msg", nd["mmsi"] == 366123456
          and nd["sog_knots"] == 12.3 and nd["heading"] == 200, nd)

    # Known public sentence (MMSI 244670316) as an independent cross-check of the armor decode.
    pub = T.parse_aivdm("!AIVDM,1,1,,A,13aEOK?P00PD2wVMdLDRhgvL289?,0*26")[0]["decoded"]
    check("ais: public example MMSI 244670316", pub["mmsi"] == 244670316, pub)


def test_ais_type5():
    # Type 5 static & voyage (424 bits, 2 fragments): name/callsign/destination 6-bit text decode.
    name = "CHRONOS WARSHIP"; dest = "PORT ODESA"; callsign = "CALL123"
    bits = (_u(5, 6) + _u(0, 2) + _u(227006760, 30) + _u(0, 2) + _u(9876543, 30)
            + ais_enc_text(callsign, 7) + ais_enc_text(name, 20) + _u(70, 8)
            + _u(100, 9) + _u(30, 9) + _u(10, 6) + _u(10, 6) + _u(1, 4)
            + _u(6, 4) + _u(15, 5) + _u(12, 5) + _u(30, 6) + _u(55, 8)
            + ais_enc_text(dest, 20) + _u(0, 1) + _u(0, 1))
    check("ais: type 5 is 424 bits", len(bits) == 424, len(bits))
    payload, fill = ais_armor(bits)
    half = 40
    s1 = aivdm(2, 1, "7", "A", payload[:half], 0)
    s2 = aivdm(2, 2, "7", "A", payload[half:], fill)
    recs = T.parse_aivdm(s1 + "\n" + s2)
    check("ais: 2 fragments reassembled into 1 message", len(recs) == 1 and recs[0]["fragments"] == 2
          and recs[0]["complete"], recs)
    d = recs[0]["decoded"]
    check("ais: type 5 static data", d["type"] == 5 and d["msg"] == "static_and_voyage_data", d)
    check("ais: MMSI + IMO", d["mmsi"] == 227006760 and d["imo"] == 9876543, d)
    check("ais: vessel name decoded", d["shipname"] == "CHRONOS WARSHIP", d)
    check("ais: callsign decoded", d["callsign"] == "CALL123", d)
    check("ais: destination decoded", d["destination"] == "PORT ODESA", d)


# =========================================================================== NMEA / GPS
def test_nmea():
    gga = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47"
    g = T.parse_nmea_line(gga)
    check("nmea: GGA parsed", g["type"] == "GGA" and g["talker"] == "GP", g)
    check("nmea: GGA lat 48.1173", g["lat"] == 48.1173, g)
    check("nmea: GGA lon 11.516667", abs(g["lon"] - 11.516667) < 1e-5, g)
    check("nmea: GGA fix quality + sats", g["fix_text"] == "GPS fix" and g["num_sats"] == 8, g)
    check("nmea: GGA altitude 545.4 m", g["altitude_m"] == 545.4, g)
    check("nmea: GGA checksum validates", g["checksum_ok"] is True, g)

    rmc = "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A"
    r = T.parse_nmea_line(rmc)
    check("nmea: RMC parsed, status valid", r["type"] == "RMC" and r["status_text"] == "valid/active", r)
    check("nmea: RMC lat/lon", r["lat"] == 48.1173 and abs(r["lon"] - 11.516667) < 1e-5, r)
    check("nmea: RMC SOG 22.4 kn, date 230394", r["sog_knots"] == 22.4 and r["date"] == "230394", r)
    check("nmea: RMC checksum validates", r["checksum_ok"] is True, r)

    # GN talker id (multi-constellation) is accepted too (checksum 69 is the true XOR of the body)
    gn = T.parse_nmea_line("$GNGGA,000000,0000.000,N,00000.000,E,1,04,1.0,0.0,M,0.0,M,,*69")
    check("nmea: GN talker accepted", gn is not None and gn["talker"] == "GN", gn)
    check("nmea: GN checksum validates", gn["checksum_ok"] is True, gn)

    # A sentence whose stated checksum does NOT match the body must be flagged (not silently trusted).
    bad = T.parse_nmea_line("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*00")
    check("nmea: wrong checksum rejected", bad is not None and bad["checksum_ok"] is False, bad)


# =========================================================================== flag highlighting
def test_flag_highlight():
    # A flag hidden across CAN payload ASCII: data bytes "CTF{W4R}" on a frame.
    line = "can0 100 [8] 43 54 46 7B 57 34 52 7D"              # CTF{W4R}
    data = (line + "\n").encode()
    rep = T.analyze_bytes(data, "flag.log")
    check("flag: CAN payload ASCII decoded", rep["can"][0]["ascii"] == "CTF{W4R}", rep["can"][0]["ascii"])
    check("flag: flag detected in report", "CTF{W4R}" in rep["flags"], rep["flags"])

    # A flag in a raw comment line of an AIS/NMEA log is caught by the raw-file scan.
    mixed = (b"# note: chronos{m4r1t1me_b34con} seen on channel A\n"
             b"!AIVDM,1,1,,A,13aEOK?P00PD2wVMdLDRhgvL289?,0*26\n")
    rep2 = T.analyze_bytes(mixed, "mix.log")
    check("flag: raw-file flag caught", "chronos{m4r1t1me_b34con}" in rep2["flags"], rep2["flags"])
    check("flag: AIS still decoded alongside flag", rep2["ais"] and rep2["ais"][0]["decoded"]["mmsi"] == 244670316, rep2["ais"])


# =========================================================================== CLI
def test_cli():
    f = TMP / "mixed.log"
    f.write_text(
        "(1529487759.000000) can0 18FEF100#0102030405060708\n"
        "can0 100 [8] 43 54 46 7B 57 34 52 7D\n"              # CTF{W4R}
        "7E8#04410C1AF8000000\n"
        "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\n"
        "!AIVDM,1,1,,A,13aEOK?P00PD2wVMdLDRhgvL289?,0*26\n"
        "*8D4840D6202CC371C32CE0576098;\n")
    r = subprocess.run([PY, str(REPO / "solvers" / "toolkits" / "transport.py"), str(f)],
                       capture_output=True, text=True, timeout=120)
    out = r.stdout
    check("cli: exits 0", r.returncode == 0, (r.stdout + r.stderr)[-300:])
    check("cli: reports J1939 PGN", "PGN 65265" in out, out[-500:])
    check("cli: reports OBD RPM", "Engine RPM" in out and "1726" in out, out[-500:])
    check("cli: reports GGA fix", "GGA" in out and "GPS fix" in out, out[-500:])
    check("cli: reports AIS MMSI", "244670316" in out, out[-500:])
    check("cli: reports ADS-B callsign", "KLM1023" in out, out[-500:])
    check("cli: highlights the flag", "CTF{W4R}" in out and "FLAG" in out, out[-500:])

    rj = subprocess.run([PY, str(REPO / "solvers" / "toolkits" / "transport.py"), str(f), "--json"],
                        capture_output=True, text=True, timeout=120)
    import json as _json
    try:
        parsed = _json.loads(rj.stdout)
        ok_json = isinstance(parsed, list) and parsed and "CTF{W4R}" in parsed[0]["flags"]
    except Exception as e:  # noqa: BLE001
        ok_json = False
        parsed = str(e)
    check("cli: --json emits valid structured output with flags", ok_json, str(parsed)[:200])


# =========================================================================== graceful degradation
def test_degrade():
    for name, blob in [("empty", b""), ("random", bytes(range(256)) * 4), ("text", b"hello world\n"),
                       ("truncated-pcap", b"\xd4\xc3\xb2\xa1\x00\x00")]:
        try:
            rep = T.analyze_bytes(blob, name)
            ok = isinstance(rep, dict) and "kinds" in rep
        except Exception as e:  # noqa: BLE001
            ok = False
            rep = str(e)
        check(f"degrade: {name} does not crash", ok, rep)
    # a line that is not candump returns None, not an exception
    check("degrade: non-candump line -> None", T.parse_candump_line("this is not a can frame") is None)
    check("degrade: short Mode S -> None", T.decode_modes(b"\x00\x01\x02") is None)


def main() -> int:
    test_can_candump()
    test_can_obd()
    test_can_socketcan_raw()
    test_can_pcap()
    test_adsb_df17()
    test_adsb_position()
    test_ais_type1()
    test_ais_type5()
    test_nmea()
    test_flag_highlight()
    test_cli()
    test_degrade()
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
