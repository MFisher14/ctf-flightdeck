# Toolkit `pcap_creds`: pcap credential-hash material

Built 2026-10-23 (gap-analysis **GAP-PCAP-CREDS**). `network.py` reads DNS/HTTP/TLS/credentials from a capture
and can also reconstruct Net-NTLM material; this toolkit is the narrow specialist that extracts the broader
set of **credential material** a capture carries, in plain Python. Offline, standard library only — no subprocess,
no network.

## Run first

```bash
.venv/bin/python solvers/toolkits/pcap_creds.py <capture>...          # triage of each capture
.venv/bin/python solvers/toolkits/pcap_creds.py --json <capture>...   # the same as JSON
.venv/bin/python solvers/toolkits/pcap_creds.py --attempt <dir>       # every question: field, answer
.venv/bin/python solvers/toolkits/pcap_creds.py --selftest            # the in-file crafted-pcap checks
```

As a solver: `signals(questions, files)` gives 0..1 and `solve_set(questions, files, ctx)` is the runner
contract for running the whole file set at once.
`ownership(questions, files)` claims an answer id only after the complete handshake parses and one exact fact
is selected. The production matcher uses that claim solely to resolve an otherwise exact tie where every tied
reader answers the same ids and offers the same value; DNS/general captures stay with `network`, while a
different id/value or incomplete material still fails closed.

## What it reads (from the exact bytes)

| Material | Source | Output |
| --- | --- | --- |
| WPA* | 802.11 (radiotap / bare Dot11) EAPOL 4-way handshake | the hashcat **22000** (WPA*) line |
| NTLM | NTLMSSP CHALLENGE(type 2) + AUTHENTICATE(type 3) over SMB/HTTP/LDAP (raw or base64 `NTLM `/`Negotiate ` token) | netntlmv1 (**5500**) / netntlmv2 (**5600**) |
| Kerberos | UDP/TCP 88 ASN.1 DER AS-REQ PA-ENC-TIMESTAMP, AS-REP enc-part, TGS-REP ticket enc-part, etype 23 | krb5pa (**7500**) / krb5asrep (**18200**) / krb5tgs (**13100**) |

## Never-guess

The **assembled hashcat string** is a deterministic concatenation of exact captured bytes; only the rendering
(hex case, separators) is unfixed, so it is emitted through `labels.pick(key, renderings)` (lowercase-hex first),
a ranked list you read and reason to one value. The **cracked
password / PSK / plaintext is NEVER derived or submitted** — a question asking for it is `None`. A handshake
missing a required message, a truncated NTLMSSP blob, a Kerberos enc-part whose etype is not 23, or two equally
matching facts → `None`. Never a padded, defaulted or guessed line. The label prefix is `network` (fields
`wpa_hashcat`, `netntlmv2_hashcat`, `krb5asrep_hashcat`, …); the flag is `None`.
