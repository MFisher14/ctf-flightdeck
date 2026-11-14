# Network toolkit: quick reference (backlog row 83, toolkit key `network`)

`solvers/toolkits/network.py`. Packet captures (pcap, pcapng, a gzip around either) read in plain Python:
no tshark, no scapy and no separate process. Offline, no token.

## What to run first (a delivery with a capture in it)

```bash
PY=.venv/bin/python
$PY solvers/toolkits/network.py workspace/<id>/capture.pcap                         # the triage, 15 rows a section
$PY solvers/toolkits/network.py --all capture.pcap | less                          # every row
$PY solvers/toolkits/network.py --attempt workspace/<id>                            # per question: field, candidates, answer, why None
$PY solvers/toolkits/network.py --carve <scratch dir> capture.pcap                 # write the carved files (untrusted: do not run them)
$PY solvers/toolkits/network.py --json capture.pcap > <scratch>/net.json
```

It never guesses; read the candidates it emits, reason to the one flag, then submit it once via
`ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`); an OSINT/templated answer uses
`allow_nonstandard=True`.

`--attempt` is the page to read before writing anything: every question with the field it was taken to
ask, the candidates the capture holds, and the reason for each `None`.

## What the triage shows

Format, link type, packet count, first and last time, protocol counts, endpoints with hardware addresses,
conversations, server banners, DNS queries and answers, DHCP host names, HTTP requests with status and user
agent, TLS SNI with JA3, JA3S and JA4, certificates sent in the clear, credentials (FTP, POP3, IMAP, SMTP
AUTH, Telnet, HTTP Basic, form posts) with the server's yes or no, FTP commands, SMTP messages and
attachments, Telnet typing, carved files with SHA-256 and MD5 (HTTP bodies and uploads, FTP data, SMTP
attachments, TFTP), ICMP echo payloads, DNS-tunnel labels with their decodings, periodic events (beacons),
SYN scans and open ports, USB keyboard text, Modbus writes, pcapng comments and embedded TLS key logs.
Since the real captures (2026-10-08) also: `modbus_series` (the values written to ONE register or coil, read
as bytes or as bits), `hidden_blobs` (a file a covert channel spells: kind by its first bytes, SHA-256, a zip's
members and comment, a member opened with the password the zip's own comment states) and `flags` (every
flag-shaped text in what the capture carries, with where it was read). `--carve` writes the blobs too.

## By hand, in Python

```python
import sys; sys.path.insert(0, "solvers/toolkits"); import network as nw
cap = nw.read("capture.pcap")            # or bytes; limit=N stops early (cap.truncated)
cap.dns(); cap.http(); cap.tls(); cap.certs(); cap.credentials(); cap.objects(); cap.beacons()
cap.ftp(); cap.smtp(); cap.telnet(); cap.tftp(); cap.dhcp(); cap.conns(); cap.streams(); cap.banners()
cap.hidden("icmp"); cap.hidden("dns"); cap.dns_tunnel(); cap.icmp_payloads()
cap.usb_keystrokes(); cap.modbus(); cap.syn_scan(); cap.open_ports(); cap.macs_of("10.0.0.5")
cap.modbus_series(); cap.hidden_blobs(); cap.flags()                    # what the writes spell, files in covert channels, flag-shaped texts
nw.as_text(nw.field(cap, "ip_id"))                                     # one byte per packet in a header field
nw.bitstream(nw.field(cap, "ttl", lambda p: p.dst == "10.0.0.9"), bits=1)    # one bit per packet
nw.decodings(b"...")                                                    # strict hex / base32 / base64 of a text
nw.dns_sequences([(src, qname), ...])     # numbered <data>.<NN>.<zone> exfil per source+zone, sorted, repeats dropped (B-079)
nw.dns_seq_readings(qname)                # every (layout, seq, data, zone) reading of one name, preferred first
```

`field` names: `ip_id ttl tos tcp_urg tcp_win tcp_seq tcp_ack tcp_flags sport dport icmp_id icmp_seq
icmp_code length payload_length first_byte last_byte time_gap_ms`. Every record is a dict with attribute
access; times are nanoseconds since the epoch (`nw.time_options(ns)` writes one in every form).

## tshark (sandbox only)

The sandbox has tshark (`tools/sandbox.py status`; down means not read, never a native run).

```bash
$PY solvers/toolkits/network.py --tshark capture.pcap -- -q -z conv,tcp
$PY solvers/toolkits/network.py --tshark capture.pcap -- -q -z io,phs
$PY solvers/toolkits/network.py --tshark capture.pcap -- -Y 'smb2 || kerberos || ntlmssp' -T fields -e frame.number -e _ws.col.Info
```

```python
nw.tshark_fields(data, ["kerberos.CNameString", "ntlmssp.auth.username"], "kerberos || ntlmssp")
nw.tshark_objects(data, "smb")           # http, smb, tftp, imf, dicom, ftp-data
```

Use it for what this file does not read: SMB, Kerberos, NTLM, RDP, QUIC, HTTP/2 and 802.11. For manual
comparison, tshark can also decrypt a capture with a key log (`cap.secrets` holds one embedded in a pcapng;
`-o tls.keylog_file:` needs it as a second input, so write it beside the capture with
`tools/sandbox.py run`).

## Native TLS on the production solve path

`solve_set` now reads HTTPS without tshark only when the delivery itself proves the exact contract: a TCP
TLS ClientHello and an NSS TLS 1.2/1.3 key-log entry with that same 32-byte ClientHello random, either in a
sibling member or a pcapng `TLSK` Decryption Secrets Block. A generic secret-looking file, a key log for a
different connection, or QUIC-only key material does not load the decryptor. An ordinary capture therefore
keeps the old cheap path.

The in-process reader verifies every record tag/MAC and rejects a cut capture, TCP gap/conflict, wrong or
conflicting key, malformed record, incomplete direction, or ambiguous HTTP framing. It reconstructs only
fully consumed HTTP/1.0 or HTTP/1.1 streams. `100`, `102` and `103` are interim and do not consume a request;
`HEAD`, every informational response, `101`, `204` and `304` have no response body. Conflicting duplicate
`Content-Length`, `Transfer-Encoding` or `Content-Encoding`, `Transfer-Encoding` plus `Content-Length`, an
unsupported transfer coding, close-delimited response or truncated chunk/length withdraws the connection.
Other repeated headers remain available in the evidence as separate values.

Content codings (`gzip`, wrapped/raw `deflate`, Brotli and size-declared Zstandard) are removed in reverse order
(for example `Content-Encoding: gzip, deflate` means deflate, then gzip while decoding), with at most eight
layers and 64 MiB at each decoded layer. Each compressed stream must reach its own end with no trailing bytes;
a Zstandard frame whose output size is not declared is left unanswered. Only a fully framed `200` response
becomes a plain-answer object (`206`, redirects and error bodies do not). Such an object records the body after transfer framing in
two forms: `wire_*` is still content-encoded; `decoded_*` is after all supported content codings. An ordinary
hash/size question means the decoded object. A question explicitly saying `wire`, `compressed`, `encoded`,
`as sent` or `before decoding` selects `wire_sha256` / `wire_size`; a question that asks for both is `None`.
HTTP/2 is detected only—there is no HPACK/frame or object reconstruction—and QUIC is not decrypted by this
production path.

The non-fake production gate is:

```bash
$PY tests/test_day30_network_native_tls.py
```

It builds real OpenSSL TLS 1.2/1.3 ciphertext, an independent pcapng `TLSK` fixture, wrong/conflicting-key and
truncation controls, exercises `network.solve_set`, and measures both a fresh interpreter and the keyless gate.

## How solve_set answers

| Answer | When |
| --- | --- |
| plain | The number of packets in the capture, only when the question has no other word that could narrow it (`send`, `contain`, `dropped`: None) and the file is not cut (cut: unsure). The SHA-256, SHA-1, MD5 or size of a carved file, only when the question asks it OF that file by a name with an extension (`the SHA-256 of tool.exe`; `the archive containing tool.exe` is unsure), the file is whole and carries no coding. Whole means: a 200 response (a 206, 3xx or 4xx body is unsure) on a connection captured from both SYNs with no hole and no bytes sent twice with different content; an upload that meets its Content-Length; an FTP transfer in TYPE I from SYN to FIN with no REST or APPE (ASCII mode: unsure); a TFTP transfer in octet mode with no options; a mail attachment on a client stream with no hole. The native TLS reader also returns the exact hash/size of one named, fully framed HTTP/1 object at the requested wire or decoded layer. The body of a posted form is never the file its URI names. Whatever `solvers/common/triage.py` proves of a delivered file the question names. |
| unsure `network.<field>/<shape>` | A fact the capture establishes: the only value of its kind (or among the packets of the address, port or name the question gives), or the first, last or most frequent one when the question says so. Options are (method, value) pairs, best first. |
| `None` | Two candidates and no word to choose by; two readings that differ (three queries for two names and no "unique"); an event's time or length; "the attacker", "the victim", a malware family; a file the question names that was not carved; a capture longer than 400,000 packets; two captures and none named. |

Question shapes and their keys (the shape is the selector, then `+ip`, `+port`, the protocol the question
names, `+ok` for "successful"):

| Asked | Field | Methods offered |
| --- | --- | --- |
| domain queried, looked up | `dns_query` | `raw` (lowercase, no trailing dot) |
| what a name resolved to; which name resolves to an address | `dns_address`, `dns_name_of_address` | `raw` |
| DNS server, web/FTP/SMTP/Telnet/TLS/SSH server, client of one | `server_address`, `client_address` | `raw` |
| Host header, website | `http_host` | `raw` (with `:port` when the header has it) |
| URI, URL, path | `http_uri`, `http_url` | `uri`, `url`, `path` |
| User-Agent, status code, Server header, method, referer, cookie | `http_user_agent`, `http_status`, `http_server`, `http_method`, `http_referer`, `http_cookie` | `raw` |
| SNI; JA3, JA3S, JA4 | `tls_sni`, `tls_ja3`, `tls_ja3s`, `tls_ja4` | `raw`; `ja3_md5` or `ja3_string`; `ja3s_md5`; `ja4` |
| certificate subject, issuer, common name, serial, fingerprint | `certificate_*` | `rfc4514`, `hex_lower`, `hex_upper`, `decimal`, `leaf_der_sha256` |
| password, user name, credentials | `password`, `username`, `credentials` | `raw`; `user_colon_password`, `user_slash_password` |
| hash, size, name, count of a transferred file | `object_hash`, `object_size`, `object_name`, `object_count` | `carved_http_response`, `carved_ftp_retr`, ... |
| message in ICMP payloads or DNS labels | `hidden_icmp`, `hidden_dns` | `joined_hex`, `joined_base64`, `each_hex`, `joined`, `repeated_byte`, `<method>_flag` |
| message or flag in Modbus writes | `hidden_modbus` | `modbus_bytes`, `modbus_bits_msb`, `modbus_bits_lsb`, `modbus_writes_flag` |
| "the flag", no channel named | `flag` | `only_flag_shaped_text` (one flag-shaped text in the whole capture, else None) |
| command typed in a Telnet session (first, last) | `telnet_command` | `typed_line` |
| SSH server banner | `ssh_banner` | `server_first_line` |
| address a DHCP server assigned; a DHCP client's hardware address | `dhcp_address`, `mac_of_address` | `dhcp_ack_yiaddr`; the MAC forms |
| beacon interval, destination, port | `beacon_interval`, `beacon_destination`, `beacon_port` | `seconds_int`, `seconds_1dp`, `seconds_unit`, `minutes_int` |
| first/last packet time; duration | `capture_time`, `capture_duration` | `iso_z_seconds`, `iso_z_micros`, `iso_z_millis`, `iso_space_seconds`, `iso_offset_seconds`, `epoch_seconds`, `epoch_micros` |
| MAC address of an address | `mac_of_address` | `colon_lower`, `colon_upper`, `dash_upper`, `dash_lower`, `plain_lower` |
| open ports; scanner or target of a SYN scan; top talker | `open_ports`, `scanner_address`, `scan_target_address`, `top_talker` | `comma`, `comma_space`, `json`, `space`; `syn_scan_source` |
| host name (DHCP option 12); mail subject, sender, recipient | `dhcp_hostname`, `smtp_subject`, `smtp_mail_from`, `smtp_rcpt_to` | `dhcp_option_12`, `raw` |
| what was typed on a USB keyboard | `usb_keystrokes` | `hid_boot_edited`; `hid_boot_flag` first when the question says flag and one is typed |
| "how many": packets of a protocol, addresses, queries, names, requests, logins (failed, successful), TCP connections | `packet_count`, `address_count`, `dns_query`, `http_request`, `login_count`, `tcp_connection_count` | `packets`, `distinct_addresses`, `count`, `distinct`, `server_replies`, `tcp_handshakes` |
| "list all ..." (or kind `ordered_tokens`, `json`) | the field's key with `all` | `comma`, `comma_space`, `json`, `space`, `arrow` |

## Label vocabularies likely for this category (spellings, best-first)

The event's labels are lowercase snake_case and descriptive. When a question asks for a name rather than a
value, return `labels.pick('network.<field>/<shape>', [...])` with spellings of ONE fact, snake_case first:

- protocol: `dns`, `http`, `https`, `tls`, `ftp`, `ftp_data`, `smtp`, `telnet`, `ssh`, `icmp`, `smb`, `rdp`, `tftp`, `dhcp`, `ntp`, `modbus_tcp`, `kerberos`
- transport: `tcp`, `udp`, `icmp`; direction: `inbound`, `outbound`, `internal`, `egress`
- activity: `port_scan`, `syn_scan`, `brute_force`, `password_spray`, `beaconing`, `c2_beacon`, `dns_tunneling`, `icmp_tunneling`, `data_exfiltration`, `file_download`, `file_upload`, `cleartext_credentials`, `arp_spoofing`, `dns_exfiltration`, `lateral_movement`, `domain_generation_algorithm`
- channel or encoding: `dns_txt`, `dns_subdomain`, `icmp_payload`, `http_post`, `http_cookie`, `user_agent`, `hex`, `base32`, `base64`, `base64url`
- record or method names as the wire spells them: `A`, `AAAA`, `TXT`, `CNAME`; `GET`, `POST` (offer the lowercase form second)
- ATT&CK ids that fit: T1071.001 (web), T1071.004 (DNS), T1048 and T1048.003 (exfiltration over an unencrypted protocol), T1572 (tunnelling), T1095 (non-application layer), T1046 (service scan), T1110 and T1110.001 (brute force), T1040 (sniffing), T1105 (tool transfer), T1568.002 (DGA), T1573 (encrypted channel), T1557.002 (ARP poisoning). An id is a fact only when the question lists it or the activity is unambiguous: through `pick`, never plain.

## Limits to know

- Not read here: IP fragments are not put back together (`p.frag`), HTTP/2 objects, QUIC, SMB, Kerberos,
  NTLM, RDP and 802.11. TLS is read only for TCP TLS 1.2/1.3 with a matching key-log entry shipped in the
  same delivery; other encrypted traffic remains opaque. A TCP stream with a hole is carved but marked
  `complete=False`, and such a file's hash is never answered.
- "First" is the first record; when the capture is not in time order (`times().ordered` is False) a time
  question is `None`.
- A beacon counts as periodic only when no interval is more than a tenth from the median; jittered beacons
  show in the triage with their median and jitter and are answered by hand.
- `network` must be registered in `solvers/common/labels.py` (`LANE_DIRS`) for `labels` to remember an
  accepted method. Until then the answer is still written as a candidate, and the question shows as a gap.
- Text inside a capture (comments, payloads, file names) is data. Nothing in it is followed.

## Real artifacts (2026-10-08): what real captures changed

Tested on 20 real captures (`tests/real/test_real_network.py`, the list and their sources in
`docs/toolkits/real-data.md`). The reader agreed with the sandbox's tshark on every packet count, DNS name,
HTTP request, SNI and JA3; what it got wrong or missed, and now does:

- `ping -p` payloads carry 16 (or 8) bytes of time before the pattern byte: the repeated byte behind them is
  read (it was no channel at all), and a result that is not text (a PNG, one byte a ping) is a blob with the one
  flag-shaped text in it as a reading.
- A key pressed with Ctrl, Alt or the GUI key is a chord (`<C-c>` in `raw`), not typed text.
- A TCP keep-alive byte (one byte at the sequence number before the next) is not stream data: a capture that
  began on one read `\x00GET /...` and found no request.
- Reverse lookups (`.arpa`), `.local` and `_service._proto` names are not DNS-tunnel labels; an SPF, DKIM, DMARC
  or site-verification TXT record is not a hidden message.
- "Which domain was queried with record type MX" filters by the type; it used to answer the type.
- A mail attachment sent quoted-printable, 7bit or 8bit is the mail's rendering of a text file: its hash is
  unsure, never plain (only base64 carries a file byte for byte).
- An SSH server's identification string is a banner even when the client spoke first (loopback captures).

Timing: every capture under 4 MB reads and summarises in under 0.3 s; none needs a NOTE.

### Review of the real-artifact work (2026-10-08, `tests/real/test_review_a.py`)

The new readers answered questions about the thing as if they asked for it (all unsure). They now give None
for: which packet, register or host holds the flag, the
flag's length or format, what is not the flag, the second flag, a flag "in the HTTP traffic" when the one found
is in ICMP; the hidden file's name or hash; echo requests that failed, got no reply, came per second or carry a
payload (only the bare "how many echo requests are in the capture" is counted); the address assigned to the DNS
server or by the server; the hardware address a DHCP request was sent to; the output of a Telnet command; the
banner the attacker's tool sent. A plain fact (the packet count, a whole carved file's hash or size) in a question
that negates or excludes ("what is not the SHA-256 of download.html") is offered, not plain. Timing, measured on built captures: 40 MB of base64 in one stream 1.1 s, 400,000
pings 3.4 to 4.4 s (packet parsing, as before this work), a zip of 16 one-megabyte members in pings 0.24 s.

## Auth / directory protocols (`net_auth.py`, library; buildlist rows 12, 14, 10, 11)

`solvers/toolkits/net_auth.py` is a library (no `signals()` / `solve_set()`) that
`network.py` loads BY NAME: `decide()` consults it ONLY for a question its own `_field()` left unanswered
(`None`), so it never changes an answer the network toolkit already made, and if the module is absent or
raises, `network.py` behaves exactly as before (one guarded hook, `_netauth_field`). No network label has
been judged, so every value it offers is an UNSURE `labels.pick`, never plain. It reads four protocols the
packet readers above do not:

- **SMB2** (TCP 445/139): the negotiated `dialect` (2.0.2 / 2.1 / 3.0 / 3.0.2 / 3.1.1, offered plain, "SMB x",
  and `0x03nn`), the tree-connect `share` (UNC) and the `create` `file` names.
- **Kerberos** (UDP/TCP 88/464, DER): `msg_type` (AS-REQ/REP, TGS-REQ/REP), `realm`, `cname` (principal),
  `sname` (service principal) and the AS-REP/TGS-REP `etype` (e.g. `rc4_hmac`, `aes256_cts_hmac_sha1`).
- **SNMP** (UDP 161/162, BER): the `community` string, the `version` (v1/v2c/v3), and varbind `oid`s.
- **IRC** (TCP 6660-6669/6697/7000): the `nick`, the `channel`s joined and the `PRIVMSG`/`NOTICE` messages
  (C2 chatter).

Dispatch is strict: a branch claims a question only when the question names its protocol AND the capture
carries it. Deliberately left as a None gap (too author-chosen / fragile to be never-wrong): the hashcat
AS-REP / TGS-REP crack string (`$krb5asrep$` / `$krb5tgs$ ...`) — unjudged rendering and brittle cipher-part
offsets; the solver builds it from the surfaced etype/principal when a question asks for it.
