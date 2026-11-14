# ICS playbook

CSCTF's "Total Warfare" theme leans on critical-infrastructure framing, so ICS artifacts cluster
around: **Modbus (and other OT) traffic in a pcap**, **serial/field-bus captures** (CAN, UART, I2C,
SPI), **RF/radio telemetry** (ISM-band, SubGHz, FSK/POCSAG), and **device firmware**. Every engine
here is an offline reader. Firmware blobs and radio captures are untrusted input — static reads
only; anything that *runs* goes through the Docker sandbox.

Run every command from the ctf-tools checkout root with `.venv/bin/python` (or `.venv/bin/python -m ctf run <engine>`), with `CTF_EVENT` set to the event slug (`events/<slug>/event.toml`). The workdir comes from `ctf.paths`: `$CTF_WORKDIR`, else `~/ctf-work/<event>`; `.venv/bin/python -m ctf workdir` prints it, and `workspace/` on this page means it.

## First moves

1. `./csctf check <id>` — skip if a teammate solved it.
2. `file workspace/<id>-<slug>/*` — identify the artifact shape (pcap? `.cu8`/`.wav`? `.sub`? CSV?
   `candump` log? `.hex`/`.srec`? a firmware blob?).
3. Route by shape:
   - **pcap/pcapng** → `network.py` (Modbus is a first-class section).
   - **radio / bus / Flipper / firmware-hex** → `rf.py` (auto-classifies the file).
   - **firmware image** (SquashFS/JFFS2/UBI/DTB/U-Boot) → `firmware_walk.py`.
   - **serialized config blob** → `wire_decode.py` / `serial_decode.py`.
4. For a live PLC/HMI instance: read the scope rules at the bottom first.

## Engines (verified CLIs)

### OT traffic in a capture — `solvers/toolkits/network.py`
Modbus/TCP is parsed natively. Triage renders a `modbus` section (src, dst, function, address,
registers) and a `modbus_series` section (write sequences with distinct-value counts and any ASCII
`reading` the register writes spell — a classic "registers spell the flag" trick).

```
.venv/bin/python solvers/toolkits/network.py <capture>
... solvers/toolkits/network.py --json --all <capture>       # full, machine-readable
... solvers/toolkits/network.py --attempt workspace/<id>-<slug>/   # answer questions.json
```
For deeper OT dissectors tshark knows (Modbus function detail, DNP3, S7comm, ENIP/CIP, IEC-104)
use tshark in the sandbox — see **Docker tools**. (The `network.py` Python reader covers Modbus;
other OT protocols read best through tshark.)

### Radio, RFID, and field-bus captures — `solvers/toolkits/rf.py`
One CLI, auto-classifies each file by content/extension:
```
.venv/bin/python solvers/toolkits/rf.py <file>... [--json]
```
What it recognizes and prints (the `shape:` is on the first line):
- **CAN** (`candump` log or Vector `.asc`): `candump: N frames, M ids: ...`, and `id XXX payloads
  as text: '...'` when a stream of frame payloads is printable.
- **Logic-analyzer CSV** (named columns): `UART 8N1: baud ..., bytes ...`, `I2C <rw> 0x..: <hex>
  acks ...`, `SPI mosi <hex> miso <hex>`. This is your **serial-bus / UART** decoder.
- **IQ** (`.cu8 .cs8 .cs16 .cf32 .cfile`): samples, frequency/rate from the filename, OOK envelope
  floor/peak, pulse count, and a bit/timing dump.
- **Audio** (`.wav`): channels/rate/frames + FSK-modem text decode when present.
- **Flipper SubGHz** (`.sub`): frequency, preset/modulation, protocol, TE, raw timings + printable
  readings. Also `.nfc`, `.rfid`, `.ir`.
- **MIFARE Classic** dumps, **NDEF**, **EM4100 / H10301 / Wiegand** ids, **magstripe** tracks.
- **Firmware text**: Intel HEX (`.hex`) and Motorola S-record (`.srec/.s19`) → record counts, base/
  start address, bad checksums, and extracted strings from the reconstructed image.

A raw timing/bit string on stdin-style files is dumped as bits; polarity-ambiguous decodes are
shown as *readings*, not answers — pick the one that is printable.

### Firmware images — `solvers/toolkits/firmware_walk.py`
Walks containers the generic lanes don't: **SquashFS 4.0** (gzip/xz content extract), **JFFS2**,
**UBI/UBIFS** (names + sizes), **DTB/FDT** device trees (node paths + property values), **U-Boot
env** (CRC-validated key=value).
```
.venv/bin/python solvers/toolkits/firmware_walk.py <image>...
```
Prints the image list and per-container entries (paths, sizes, device-tree props, env vars). Use
`binwalk` in the sandbox first if the blob is an unknown concatenation (see below).

### Serialized payloads / configs — `wire_decode.py` and `serial_decode.py`
IoT/OT payloads are often structured blobs. Both are schema-less structural readers; neither
executes anything.
```
# protobuf / CBOR / MessagePack / BSON (common in MQTT/telemetry bodies)
.venv/bin/python solvers/toolkits/wire_decode.py <blob> --json
# language-native serialization (Java AC ED / PHP serialize() / Ruby Marshal 04 08) in a config dump
.venv/bin/python solvers/toolkits/serial_decode.py <blob> --json
```
Each prints the decoded structure (field numbers/keys, class/property names, primitive values).

## Docker tools (csctf-sandbox:2)

Radio demod and firmware-carving tools run only in the sandbox. `{in}` is your file mounted
read-only at `/drop`; `{out}` is the one writable dir. Check any tool's flags with
`python3 tools/sandbox.py run <tool> --help`.

```
# ISM-band devices (433/868/915 MHz) from an IQ capture — filename encodes rate, e.g. dev_433.92M_250k.cu8
python3 tools/sandbox.py run --in capture.cu8 rtl_433 -r {in}

# POCSAG / AFSK / FSK / DTMF from audio (multimon-ng reads wav with -t; convert with sox if it refuses)
python3 tools/sandbox.py run --in tones.wav multimon-ng -t wav -a POCSAG1200 -a AFSK1200 -a DTMF {in}
python3 tools/sandbox.py run --in tones.wav sox {in} -t raw -r 22050 -e signed -b 16 -c 1 {out}/raw.s16

# generic FSK/AFSK modem receive from audio
python3 tools/sandbox.py run --in signal.wav minimodem -r -f {in} 1200

# OT pcap dissection tshark won't do in Python (DNP3, S7comm, ENIP/CIP, IEC-104, modbus detail)
python3 tools/sandbox.py run --in capture.pcap tshark -r {in} -Y 'modbus' -T fields -e modbus.func_code -e modbus.data
python3 tools/sandbox.py run --in capture.pcap tshark -r {in} -q -z io,phs

# carve/inspect an unknown firmware blob before firmware_walk.py
python3 tools/sandbox.py run --in fw.bin binwalk -e {in}
```
The sandbox is `--network none`, read-only root, caps dropped — nothing touches the Mac, and any
tool not on the image's list is refused.

## Techniques → engines

- **Modbus registers spell the flag / "what value was written to coil X"** → `network.py`
  `modbus` + `modbus_series` sections (the ASCII `reading`), or `--attempt`.
- **CAN bus dump → payload text / target id** → `rf.py` on the `candump` log.
- **Serial console / sensor on a logic capture** → `rf.py` logic-CSV UART/I2C/SPI decode.
- **SubGHz remote / garage / sensor** (`.sub`) → `rf.py` sub reading; **ISM telemetry** (`.cu8`) →
  `rtl_433` in the sandbox; **pager/POCSAG, AFSK, DTMF** (audio) → `multimon-ng`.
- **Firmware extraction** → `binwalk -e` in the sandbox, then `firmware_walk.py` for SquashFS/JFFS2/
  UBI/DTB/U-Boot-env, then triage extracted files back through the normal lanes.
- **HMI/PLC config as protobuf/CBOR/Java-serialized blob** → `wire_decode.py` / `serial_decode.py`.
- **Access card / badge** (MIFARE, EM4100, Wiegand, magstripe) → `rf.py` dumps the ids/tracks.
- **Layered-encoded blob after you carve it** → `solvers/warmups/layered_decode.py`.

## Get the flag out and submit

Reason to the one flag (`csctf{...}` / `chronos{...}` / `flag{...}`) from the engine output and
submit it **once** through the guard:
```
./csctf submit <id> 'csctf{...}'          # == .venv/bin/python -m ctf submit <id> 'csctf{...}'
```
From a solver: `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="modbus register writes")`.
The guard enforces format/dedupe/pacing/skip-solved and **stops to ask after 3 wrong** — never loop
candidates. Rotating per-team flag → `ctf.dynamic.solve_dynamic`.

### Scope & rate (hard boundary — AGENTS.md)
ICS artifacts are usually offline files. If a challenge gives a **live** OT target (a PLC/HMI
instance, an MQTT broker, a serial-over-TCP bridge):
- Interact **only with the instance assigned to our squad** — never the platform, scoreboard, other
  teams, or unassigned ICS hosts.
- **No mass scanning, no flooding, no DoS**, and treat OT gently — no write storms against a PLC.
  Keep the engines' request caps.
- **Never brute-force flags.** Reason to one, submit through the guard.
- Platform/infra bug → report to CSCTF staff, don't weaponize it.

## ICS protocol parsers (added 2026-11-03)

Dedicated schema-less dissectors — parse a raw payload **or** a `.pcap`/`.pcapng` (they pull the relevant
packets with scapy, then dissect), and highlight any flag-format hit in string data.

- **`ics_scada.py`** — S7comm (Siemens, TCP 102 TPKT/COTP/S7), DNP3 (TCP/UDP 20000, with CRC), IEC 60870-5-104
  (TCP 2404, I/S/U frames, ASDU types/IOA).  
  `.venv/bin/python solvers/toolkits/ics_scada.py <file|pcap> [--json]`
- **`ics_fieldbus.py`** — BACnet/IP (UDP 47808, pure stdlib), plus readable wrappers over scapy for
  EtherNet/IP + CIP (TCP 44818), Profinet (pnio/pnio_dcp/pnio_rpc), OPC-DA.  
  `.venv/bin/python solvers/toolkits/ics_fieldbus.py <file|pcap> [--json]`

Modbus/TCP is already handled by `solvers/toolkits/network.py` (`modbus` reader). For unknown serial/field-bus
framing fall back to `serial_decode.py` / `wire_decode.py` / `rf.py`.

## Round-3 hardware and industrial depth

`solvers/toolkits/hardware_depth.py` decodes bounded SPI NOR and I2C EEPROM transactions, UART
bootloader text, candump frames against supplied DBC definitions, U-Boot environments, and common
firmware signatures (SquashFS/JFFS2/UBI). It also produces JTAG/SWD boundary-scan checklists; these are
notes for the player's bench, never automated probing. `rf.py` exposes the shared SPI transaction
decoder for Sigrok-style exports.

`solvers/toolkits/network_ics_depth.py` adds static IEC-61850 GOOSE/MMS, OPC-UA, and Profinet-RT
parsing plus TLS 1.3/QUIC key-log decryption helpers and Kerberos/NTLM/SMB artifact extraction. The
`covert` operation ranks timing, size, DNS-label, TCP-field, ICMP, and protocol-value channels from a
saved capture. All commands consume files/hex fixtures only; they never open an interface.

## Round-4 automotive, radio, and secure-OT depth

The earlier transport and fieldbus readers remain the first pass for J1939/OBD, DNP3, S7comm,
Modbus, BACnet and EtherNet/IP. These additions fill stateful or encrypted seams rather than
duplicating those dissectors:

- `automotive_depth.py <candump.log> --json` reassembles ISO-TP single/first/consecutive frames per
  CAN id (including CAN-FD extended lengths), then decodes UDS requests, positive/negative replies,
  DIDs, SecurityAccess seed/key material, routine controls, transfer blocks and DTCs. It reads a
  saved log only and never opens SocketCAN.
- `radio_capture.py <file> --kind auto --json` reads BLE advertising structures, btsnoop/H:4
  ACL→L2CAP→ATT/SMP, and IEEE 802.15.4→Zigbee NWK/APS/ZCL. A supplied `--zigbee-key` is used only for
  authenticated AES-CCM decryption; a bad MIC yields no plaintext. No HCI/radio device is opened.
- `network_ics_depth.py` now understands QUIC v2 labels and packet types, authenticates v1/v2 Retry,
  parses the common QUIC frame grammar, verifies/decrypts caller-keyed OPC-UA symmetric chunks,
  dissects PNIO-CM connectionless RPC blocks, and retains a bounded BER tree for MMS service data.

All three consume saved artifacts; none discovers, scans, writes to, or negotiates with an OT device.

## Round-5 authenticated secure-channel and RPC depth

`network_ics_depth.py` keeps these operations entirely on saved bytes and caller-supplied key
artifacts:

- `opcua-opn <chunk> <receiver-private-key> --sender-public-key ...
  [--receiver-certificate ...]` decrypts RSA-encrypted asymmetric `OPN` chunks for the OPC-UA
  Basic128Rsa15, Basic256, Basic256Sha256, Aes128-Sha256-RsaOaep and
  Aes256-Sha256-RsaPss policies. It returns service bytes only after every RSA block, OPC-UA
  padding, the sender signature, and any supplied receiver-certificate thumbprint validate.
- `pnio-rpc <payload>` exposes PNIO interface UUIDs, NDR hints, AR/IOCR blocks, and the correct
  ARUUID/API/slot/subslot/index/record-data fields for IOD read/write blocks.
- `mms <payload>` names confirmed services through tag 30 and the unconfirmed information-report,
  status, and event services. Typed context values are deliberately marked `candidate_only` and
  `schema_verified=false`: the same context tag can mean something else under another MMS schema.
- QUIC frame parsing includes RFC 9221 DATAGRAM and RFC 9368 IMMEDIATE_ACK/ACK_FREQUENCY, with
  exact varint consumption and rejection of invalid zero packet tolerance.

Conservative limits are explicit: OPC-UA ECC policies and RSA keys needing `ExtraPaddingSize`
(above 2048 bits) decline; PNIO NDR pointers/unions are surfaced as bounded hints rather than
guessed schema values; MMS high-tag-number services (31+) and full ACSE/presentation negotiation
remain for a schema-aware decoder. None of these commands reassembles or initiates a live session.

## Round-5 saved RF and firmware evidence

`mobile_rf_depth.py` complements `rf.py`, `transport.py`, and `radio_capture.py` with bounded readers:

- `uf2` validates every 512-byte UF2 block and reconstructs bytes only when numbering, family IDs,
  target ranges, and completeness agree. Partial/conflicting containers never emit an image.
- `pocsag` BCH/parity-checks already-demodulated 32-bit pager codewords. A pristine word can expose
  its raw address/message fields; a one/two-bit BCH correction remains a candidate because POCSAG has
  no enclosing payload CRC. Text interpretation is deliberately not asserted.
- `fsk --samples-per-symbol N` slices a saved discriminator trace and returns both unresolved
  polarities. `glitch` reports robust-MAD outlier runs in a saved voltage/clock trace without claiming
  that an event caused a fault or reveals a key.

ADS-B and AIS frame decoding remains in `transport.py`; captured BLE/Zigbee is in
`radio_capture.py`; OOK/AFSK and sandboxed `multimon-ng` plans remain in `rf.py`/`stego_tools.py`.
Full LoRa PHY/FEC, GFSK clock recovery, POCSAG audio demodulation, and causal fault/key recovery are
honest remaining gaps. None of these tools opens an SDR, serial port, CAN interface, or debug probe.
