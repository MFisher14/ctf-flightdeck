# Networking playbook

Mostly **offline pcap/pcapng analysis**. A challenge drops a capture (`.pcap`, `.pcapng`, `.cap`)
and maybe a key log; you read it, find the one fact/flag, submit once. All engines here are pure
Python readers — nothing in this lane sends a packet. The only process any of them starts is
`tshark`, and that runs **only in the Docker sandbox** (`--network none`), never on the Mac.

Run every command from the ctf-tools checkout root with `.venv/bin/python` (or `.venv/bin/python -m ctf run <engine>`), with `CTF_EVENT` set to the event slug (`events/<slug>/event.toml`). The workdir comes from `ctf.paths`: `$CTF_WORKDIR`, else `~/ctf-work/<event>`; `.venv/bin/python -m ctf workdir` prints it, and `workspace/` on this page means it.

## First moves (the moment you open a capture)

1. `./csctf check <id>` — skip if a teammate already solved it.
2. `file workspace/<id>-<slug>/*` and note the extensions / sizes.
3. Full triage in one shot:
   `.venv/bin/python solvers/toolkits/network.py workspace/<id>-<slug>/<capture>`
   Read the rendered sections top to bottom: protocols, conversations, endpoints, credentials,
   DNS, HTTP, TLS/certs, carved objects, beacons, scans, USB-HID, Modbus.
4. If the prompt names a protocol the triage doesn't surface (SMB2, Kerberos, SNMP, IRC, SIP/RTP,
   MQTT, Redis, MySQL/PostgreSQL, LDAP, syslog), jump to **tshark in the sandbox** (below) — those
   live in the question-answering readers, not the default render.
5. If creds/hashes are the point: `pcap_creds.py`. If a TLS session needs decrypting and a key log
   shipped with the files: `network.py --tls-decrypt`.

## Engines (verified CLIs)

### Capture triage — `solvers/toolkits/network.py`
Reads pcap (µs + ns, both byte orders) and pcapng; Ethernet/VLAN/SLL/raw-IP, IPv4/IPv6, TCP/UDP/
ICMP/ARP, USB. Parses DNS, DHCP, HTTP (de-chunk + gzip/deflate/br), TLS (SNI/ALPN/JA3/JA4, certs),
plaintext creds (FTP/POP3/IMAP/SMTP/Telnet/HTTP-Basic/form), NTLMSSP + HTTP-Digest, TFTP, covert
channels (ICMP/DNS-tunnel), beacons, SYN scans/open ports, USB-HID keystrokes, and **Modbus/TCP**.

```
# human-readable triage (15 rows/section)
.venv/bin/python solvers/toolkits/network.py <capture>
# full JSON, no row cap
... solvers/toolkits/network.py --json --all <capture>
# carve every reconstructed object (HTTP bodies/uploads, FTP data, SMTP attachments, TFTP, covert blobs) to DIR
... solvers/toolkits/network.py --carve "$(.venv/bin/python -m ctf workdir)/obj" <capture>
# answer a challenge's questions.json (full readers: adds SMB2/Kerberos/SNMP/IRC, SIP/RTP, MQTT/Redis/MySQL/PG/LDAP/syslog)
... solvers/toolkits/network.py --attempt workspace/<id>-<slug>/
```
Prints: per-section tables; `--carve` prints `CARVED <path> <size> sha256 <hash> source ...` per
object (and `INCOMPLETE` when a transfer was cut). `--attempt` prints per-question field/shape and
the candidate answer(s) with a `why`.

The sibling readers **net_auth** (SMB2/Kerberos/SNMP/IRC), **net_voip** (SIP/RTP incl. digest-auth
fields + G.711/G.722 stream duration), and **net_dbproto** (MQTT/Redis-RESP/MySQL/PostgreSQL/LDAP
bind/syslog) have **no CLI of their own** — `network.py` consults them automatically in `--attempt`.
To read those protocols by hand, use tshark.

### Credential / hash material — `solvers/toolkits/pcap_creds.py`
Assembles **hashcat-format** lines from the wire: WPA/WPA2 EAPOL → mode 22000; NTLMSSP → NetNTLMv1
(5500) / NetNTLMv2 (5600); Kerberos etype-23 → krb5pa (7500) / krb5asrep (18200) / krb5tgs (13100).

```
.venv/bin/python solvers/toolkits/pcap_creds.py <capture>
... solvers/toolkits/pcap_creds.py --json <capture>
```
Prints the ready-to-crack hash string(s). It **never cracks** — feed the line to your own
offline hashcat/john; the recovered password is the flag source, not the hash.

### TLS/QUIC decryption with a shipped key log — `network.py --tls-decrypt`
Only when an `SSLKEYLOG`/`keylog` file (or a pcapng decryption-secrets block) came with the files.
```
... solvers/toolkits/network.py --tls-decrypt <capture> <keylog> [more files...]
```
Prints `# <capture>: decrypted=... keylog=...` then the decrypted `HTTP`/`OBJECT` lines (runs
tshark with `tls.keylog_file` in the sandbox).

### Serialized payloads inside a body — `solvers/toolkits/wire_decode.py`
When a carved HTTP/MQTT/custom body is protobuf, CBOR, MessagePack, or BSON (schema-less):
```
.venv/bin/python solvers/toolkits/wire_decode.py "$(.venv/bin/python -m ctf workdir)/obj/<carved>" --json
```
Prints the structural tree (protobuf field#/wiretype/value; CBOR/msgpack/BSON value tree). Carve
first with `network.py --carve`, then point this at the file.

## Docker tools (csctf-sandbox:2)

`tshark` is the one network tool in the sandbox. Use it for dissection the Python reader doesn't do
(SMB2, Kerberos, SIP/RTP, MQTT, follow-stream, stats). Two ways:

```
# via network.py (it supplies -r <capture>; put tshark args after --)
.venv/bin/python solvers/toolkits/network.py --tshark <capture> -- -q -z conv,tcp
... network.py --tshark <capture> -- -Y 'smb2' -T fields -e smb2.filename
... network.py --tshark <capture> -- -Y 'sip || rtp' -T fields -e sip.Method -e sip.Call-ID

# or sandbox direct (you pass the full tshark line; {in} is the capture at /drop)
python3 tools/sandbox.py run --in <capture> tshark -r {in} -q -z io,phs
python3 tools/sandbox.py run --in <capture> tshark -r {in} -Y 'mqtt' -T fields -e mqtt.topic -e mqtt.msg
python3 tools/sandbox.py run --in <capture> tshark -r {in} -z follow,tcp,ascii,0 -q
```
Check flags you're unsure of: `python3 tools/sandbox.py run tshark --help`. The sandbox refuses any
tool not on its list and never runs anything on the host.

## Techniques → engines

- **"How many packets / which host / what port"** → `network.py` triage (protocols, endpoints,
  conversations). Count facts are exact.
- **Plaintext creds** (FTP/Telnet/HTTP-Basic/SMTP-AUTH/form post) → `network.py` `credentials`
  section. **Hashed auth** (WPA/NetNTLM/Kerberos) → `pcap_creds.py`, crack offline.
- **Exfil / covert channel** → `network.py` `icmp_payloads`, `dns_tunnel`, `hidden`, `beacons`;
  carve with `--carve` and decode the blob (try `solvers/warmups/layered_decode.py`).
- **File transfer / "recover the uploaded file"** → `network.py --carve`, then hash/triage the
  carved object; `wire_decode.py` if it's a serialized body.
- **TLS traffic + a key log in the bundle** → `network.py --tls-decrypt`.
- **SMB2 / Kerberos / SNMP / IRC / SIP / RTP / MQTT / DB protocols** → `network.py --attempt` for
  the answer, or `--tshark`/sandbox `tshark` to read fields directly.
- **Fingerprinting a client/server** → JA3/JA4/JA3S and cert fields in the `tls`/`certs` sections.
- **USB capture** → `network.py` `usb_keystrokes` turns HID boot-keyboard reports into typed text.

## Get the flag out and submit

The flag is a value you read or reconstruct (`csctf{...}` / `chronos{...}` / `flag{...}`). Submit
**once**, through the guard:

```
./csctf submit <id> 'csctf{...}'          # == .venv/bin/python -m ctf submit <id> 'csctf{...}'
```
From a solver: `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="xor-decode of carved body")`.
The guard checks the flag format, dedupes, paces, skips already-solved, and **stops to ask after 3
wrong** on one challenge — do not hand-roll a submit loop. Rotating per-team flag →
`ctf.dynamic.solve_dynamic`.

### Scope & rate (hard boundary — AGENTS.md)
This lane is normally offline. If a challenge exposes a **live** host/port:
- Touch **only the instance assigned to our squad** — never the platform, scoreboard, other teams,
  or unassigned hosts.
- **No mass scanning, no flooding, no DoS.** No `nmap` sweeps; keep to the one target. Any capture
  you make is of your own assigned traffic.
- **Never brute-force flags** — reason to the one flag, submit through the guard.
- Found a platform bug? Report to CSCTF staff; don't use it.

## Carrier-telecom & transport parsers (added 2026-11-03)

- **`telecom.py`** — GTP-C/GTP-U (scapy), Diameter (scapy, AVPs), SS7 over SIGTRAN (M3UA/SCCP, custom).
  `.venv/bin/python solvers/toolkits/telecom.py <file|pcap> [--json]` — surfaces IMSI/MSISDN-adjacent strings + flag hits.
- **`transport.py`** — CAN bus / J1939 / OBD-II (candump logs + SocketCAN), ADS-B (Mode S DF17), AIS
  (`!AIVDM` 6-bit), NMEA-0183/GPS (GGA/RMC).  `.venv/bin/python solvers/toolkits/transport.py <file|pcap> [--json]`

## Encrypted-session artifacts and covert-channel classification

`solvers/toolkits/network_ics_depth.py` consumes saved bytes/captures and local secrets. Its `tls13`
and `quic` modes cover traffic-secret updates, nonce reconstruction, header protection, and packet
number candidates; `auth` extracts Kerberos, NTLM, and SMB negotiation/session artifacts without
attempting credentials; `ics` recognizes IEC-61850, OPC-UA, and Profinet-RT; `covert` ranks likely
timing/size/header/DNS/ICMP covert channels with evidence. Use `--json` on the selected subcommand.
No mode captures traffic or contacts a host.

## Round-4 framed and short-range captures

- gRPC was the remaining framing gap above the existing blind protobuf/CBOR/MessagePack/BSON reader.
  Use `wire_decode.py body.bin --grpc --json` or `--grpc-web [--base64]`; add
  `--compression=gzip|deflate` only when that encoding was captured. Every frame is consumed exactly,
  trailers are parsed separately, and uncompressed messages feed the schema-less protobuf tree.
- `radio_capture.py` handles saved BLE advertising PDUs, H:4/btsnoop ACL traffic with ATT/GATT
  decoding, and Zigbee/802.15.4 captures. It never opens a Bluetooth or capture interface.
- `automotive_depth.py` is the stateful companion to `transport.py`: feed it candump text for
  ISO-TP reassembly and UDS decoding. Sequence gaps remain explicit incomplete/error rows.
- `network_ics_depth.py` adds QUIC v2 traffic labels/types, v1/v2 Retry integrity, frame grammar,
  authenticated OPC-UA symmetric chunks and PNIO-RPC. Plaintext appears only after AEAD/HMAC success.

Round 5 extends that same saved-artifact path with RFC 9368 IMMEDIATE_ACK/ACK_FREQUENCY frames and
authenticated asymmetric OPC-UA `OPN` decryption (`opcua-opn`). The latter requires an explicit
receiver private key and a sender certificate/public key; it emits plaintext only after signature,
padding, block, and optional receiver-thumbprint checks. See the ICS playbook for the supported
SecurityPolicy allowlist and the deliberately conservative PNIO/MMS schema limits.
