#!/usr/bin/env python3
"""The network toolkit on real captures (solvers/toolkits/network.py).

  .venv/bin/python tests/real/test_real_network.py

Offline. SKIPs when `challenges/_realdata/network/` is absent (tests/real/fetch_a.py fills it). The captures
are three Huntress CTF challenge files (2024 Echo Chamber and Keyboard Junkie, 2025 Bussing Around) and public
sample captures (Wireshark, dpkt, scapy). Every expected value below was read with the sandbox's tshark on
2026-10-08 (packet counts, DNS names, HTTP requests, SNI and JA3, exported HTTP objects, Telnet data, DHCP
fields, the SMTP AUTH strings) or is the flag the challenge's public write-up states.

With CTF_TK_LIVE=1 and the sandbox up, the packet count of every capture is read again with tshark.
"""
import hashlib
import os
import sys

from _real_a import check, finish, folder, is_plain, load, manifest, offers, q, timed, values

D = folder("network")
import network as nw     # noqa: E402

PACKETS = {'bussing_around.pcapng': 16909, 'dhcp.pcap': 4, 'dns.cap': 38, 'dpkt-dns_icmp.pcap': 32, 'dpkt-http.pcap': 43,
           'dpkt-truncated_dns.pcap': 1, 'echo_chamber.pcap': 31934, 'http-brotli.pcapng': 10, 'keyboard_junkie.pcap': 716,
           'scapy-http2_h2c.pcap': 10, 'scapy-http_chunk.pcap.gz': 66, 'scapy-http_compressed.pcap': 3,
           'scapy-http_content_length.pcap': 18, 'scapy-macos.pcapng.gz': 1, 'scapy-ssh_ed25519.pcap': 28,
           'scapy-tls_new-session-ticket.pcap': 12, 'scapy-tls_tcp_frag_withnss.pcap.gz': 17, 'smtp.pcap': 60,
           'telnet-cooked.pcap': 92, 'tls12-dsb.pcapng': 17}
DNS = {'dns.cap': ['1.0.0.127.in-addr.arpa', '104.9.192.66.in-addr.arpa',
                   '_ldap._tcp.05b5292b-34b8-4fb7-85a3-8beef5fd2069.domains._msdcs.utelsystems.local',
                   '_ldap._tcp.dc._msdcs.utelsystems.local', '_ldap._tcp.default-first-site-name._sites.dc._msdcs.utelsystems.local',
                   'google.com', 'grimm.utelsystems.local', 'isc.org', 'www.example.com', 'www.example.notginh', 'www.google.com',
                   'www.isc.org', 'www.l.google.com', 'www.netbsd.org'],
       'dpkt-dns_icmp.pcap': ['2.2.2.4.in-addr.arpa', '4.4.8.8.in-addr.arpa', '8.8.8.8.in-addr.arpa', 'www.wireshark.org'],
       'dpkt-http.pcap': ['pagead2.googlesyndication.com'], 'smtp.pcap': ['mail.patriots.in']}
HTTP = {'dpkt-http.pcap': [('GET', 'www.ethereal.com', '/download.html')],
        'http-brotli.pcapng': [('GET', '192.168.122.33', '/test.txt')],
        'scapy-http2_h2c.pcap': [('GET', 'nghttp2.org', '/robots.txt')],
        'scapy-http_chunk.pcap.gz': [('GET', 'www.httpwatch.com', '/httpgallery/chunked/chunkedimage.aspx?0.2911017199439567')]}
TLS = {'scapy-tls_tcp_frag_withnss.pcap.gz': [('httpbin.org', '9fd0948a7cafdb1cf1b2e689a5fa8db0')],
       'tls12-dsb.pcapng': [('example.com', '00bcd759cb8ad485fdbf1e7a0c5b94b4'), ('example.net', '00bcd759cb8ad485fdbf1e7a0c5b94b4')]}
OBJECTS = {'dpkt-http.pcap': {('download.html', 18070, '9475e5443f5581958175c3ec56994a5910e85f64d919631dbf61ef21e0baa859')},
           'http-brotli.pcapng': {('test.txt', 66, '23f50f671fb3d35e4800426820b5f9247923f49e891c2be13f6f2db1895d26ca')}}
ECHO_FLAG = "flag{6b38aa917a754d8bf384dc73fde633ad}"          # Huntress 2024 Echo Chamber, the write-up's flag
KEYS_FLAG = "flag{f7733e0093b7d281dd0a30fcf34a9634}"          # Huntress 2024 Keyboard Junkie, the write-up's flag
BUS_ZIP = "a920ec65e8acc368da229544f0b5eb80bea73679c4b300016aaf155516a7f9de"


def ask(name, *questions):
    data = (D / name).read_bytes()
    qs = [q(f"q{i}", t if isinstance(t, str) else t[1], "exact_text" if isinstance(t, str) else t[0], artifact=name)
          for i, t in enumerate(questions)]
    got, dt = timed(f"solve_set {name}", lambda: nw.solve_set(qs, {name: data}, {"partial": {}}), len(data))
    return [got.get(x["id"]) for x in qs]


def main() -> int:
    names = [e["name"] for e in manifest("network")]
    check("every capture of the manifest is in the cache", all((D / n).is_file() for n in names), [n for n in names if not (D / n).is_file()])

    # ---- every capture: read, counted as tshark counts it, summarised, never slow
    caps = {}
    for n in names:
        data = load(D, n)
        try:
            cap, dt = timed(f"read+summary {n}", lambda: (lambda c: (c, nw.render(nw.summary(c, 15)))[0])(nw.read(data, n)), len(data))
        except Exception as e:            # noqa: BLE001  a crash on a real file is the finding
            check(f"{n}: read and summarised", False, f"{type(e).__name__}: {e}")
            continue
        caps[n] = cap
        check(f"{n}: {len(cap.packets)} packets, as tshark counts ({dt:.2f} s)", len(cap.packets) == PACKETS.get(n), PACKETS.get(n))
        check(f"{n}: signals() sees a capture", nw.signals([q('a', 'What is in the delivery?', artifact=n)], {n: (D / n).read_bytes()}) >= 0.7)
    for n, want in DNS.items():
        got = sorted({(m.qname or "").lower().rstrip(".") for m in caps[n].dns() if not m.qr and m.proto == "dns"})
        check(f"{n}: the queried names are tshark's dns.qry.name", got == want, got)
    for n, want in HTTP.items():
        got = [(r.method, r.host, r.uri) for r in caps[n].http() if r.method]
        check(f"{n}: the first request is tshark's", got[:1] == want, got[:1])
    for n, want in TLS.items():
        got = [(t.sni, t.ja3) for t in caps[n].tls()]
        check(f"{n}: SNI and JA3 are tshark's", got == want, got)
    for n, want in OBJECTS.items():
        got = {(o.name, o.size, o.sha256) for o in caps[n].objects()}
        check(f"{n}: the carved body is the object tshark exports", want <= got, got)

    # ---- Huntress 2024 Echo Chamber: a PNG and a flag, one byte per ping behind the timeval
    cap = caps["echo_chamber.pcap"]
    h = cap.hidden("icmp")
    check("echo chamber: the echo requests spell the write-up's flag", h.get("echo_request:repeated_byte_flag") == ECHO_FLAG, h)
    blobs = cap.hidden_blobs()
    check("echo chamber: the bytes are one PNG of 15,967 bytes (one per echo request)",
          len(blobs) == 1 and blobs[0].kind == "png" and blobs[0].size == 15967 and blobs[0].data[:8] == b"\x89PNG\r\n\x1a\n", [(b.kind, b.size) for b in blobs])
    a = ask("echo_chamber.pcap", "What flag is hidden in the ICMP echo request payloads?", "What is the flag?",
            ("integer", "How many packets are in the capture?"), ("integer", "How many ICMP echo requests are in the capture?"),
            "What message is hidden in the DNS queries?")
    check("echo chamber: the flag is offered unsure, never plain", values(a[0]) == [ECHO_FLAG] and values(a[1]) == [ECHO_FLAG], a[:2])
    check("echo chamber: the packet count is plain and tshark's", a[2] == "31934", a[2])
    check("echo chamber: 15,967 echo requests (tshark icmp.type == 8), unsure", values(a[3]) == ["15967"], a[3])
    check("echo chamber: no DNS channel is invented", a[4] is None, a[4])

    # ---- Huntress 2024 Keyboard Junkie: USB keyboard reports
    ks = caps["keyboard_junkie.pcap"].usb_keystrokes()
    check("keyboard junkie: one keyboard, and the typed line is the write-up's",
          len(ks) == 1 and ks[0].text == f"so the answer is {KEYS_FLAG} hahahah lol\n", [k.text for k in ks])
    check("keyboard junkie: the closing Ctrl+C is a chord in raw, not a typed c", ks and ks[0].raw.endswith("<C-c>") and not ks[0].text.rstrip("\n").endswith("c"), ks and ks[0].raw[-12:])
    a = ask("keyboard_junkie.pcap", "What flag did the user type on the keyboard?", "What was typed on the USB keyboard?")
    check("keyboard junkie: the flag is the first option of the flag question", values(a[0])[:1] == [KEYS_FLAG], a[0])
    check("keyboard junkie: the whole line answers what was typed", values(a[1]) == [f"so the answer is {KEYS_FLAG} hahahah lol"], a[1])

    # ---- Huntress 2025 Bussing Around: a zip, one bit per Modbus register write
    cap = caps["bussing_around.pcapng"]
    ser = {(m.function, m.address): m for m in cap.modbus_series()}
    check("bussing around: four series of writes (registers 0, 4, 10 and coil 20)", sorted(ser) == [(5, 20), (6, 0), (6, 4), (6, 10)], sorted(ser))
    check("bussing around: register 0 is 2,264 bits that begin like a zip", ser[(6, 0)].writes == 2264 and ser[(6, 0)].reading == "bits_msb"
          and hashlib.sha256(ser[(6, 0)].blob or b"").hexdigest() == BUS_ZIP, (ser[(6, 0)].writes, ser[(6, 0)].reading))
    blobs = [b for b in cap.hidden_blobs() if b.channel == "modbus"]
    check("bussing around: the zip's comment states the password and flag.txt opens with it",
          len(blobs) == 1 and blobs[0].kind == "zip" and blobs[0].members == [("flag.txt", 39, True)] and "password is" in blobs[0].comment
          and len(blobs[0].flags) == 1 and blobs[0].opened.get("flag.txt", b"").strip().decode() == blobs[0].flags[0], blobs and (blobs[0].members, blobs[0].comment))
    a = ask("bussing_around.pcapng", "What flag is hidden in the Modbus register writes?", "What flag is hidden in the capture?",
            "Which port is open on 172.20.10.2?", ("integer", "How many packets are in the capture?"))
    check("bussing around: the flag of flag.txt is offered unsure for both wordings",
          bool(blobs) and values(a[0]) == blobs[0].flags and values(a[1]) == blobs[0].flags, a[:2])
    check("bussing around: port 502 and the packet count", values(a[2]) == ["502"] and a[3] == "16909", a[2:])

    # ---- public samples against tshark
    a = ask("smtp.pcap", "What password was used to authenticate to the SMTP server?", "Which user authenticated to the mail server?",
            "What is the SHA-256 of NEWS.txt?", "What is the name of the attachment?", "Which domain was queried over DNS?")
    check("smtp: the AUTH LOGIN pair is tshark's base64, decoded", values(a[0]) == ["punjab@123"] and values(a[1]) == ["gurpartap@patriots.in"], a[:2])
    check("smtp: a quoted-printable attachment's hash is never plain (the mail's rendering of a text file)",
          not is_plain(a[2]) and values(a[2]) == ["ac04c5d2cd8fa9a2670c959806f5181a56b3e9bb1cc7da150af98ba074c86b55"], a[2])
    check("smtp: attachment name and queried domain", values(a[3]) == ["NEWS.txt"] and values(a[4]) == ["mail.patriots.in"], a[3:])
    a = ask("telnet-cooked.pcap", "What password was used to log in over Telnet?", "What username was used for the Telnet login?",
            "What command did the user run first?", "What is the IP address of the Telnet server?")
    check("telnet: login fake / user, first command, server (tshark telnet.data)", [values(x) for x in a] ==
          [["user"], ["fake"], ["/sbin/ping www.yahoo.com"], ["192.168.0.1"]], a)
    a = ask("dhcp.pcap", "What is the host name of the DHCP client?", "What IP address was assigned to the client?", "What is the MAC address of the DHCP client?")
    check("dhcp: no option 12 in the capture, so no host name", a[0] is None, a[0])
    check("dhcp: the address of the ACK and the client's hardware address", values(a[1]) == ["192.168.0.10"] and values(a[2])[:1] == ["00:0b:82:01:fc:42"], a[1:])
    a = ask("dns.cap", "Which domain was queried with record type MX?", "What message is hidden in the DNS queries?",
            ("integer", "How many unique domains were queried?"), "What is the IP address of the DNS server?")
    check("dns: a record type the question names is a filter, not the answer", values(a[0]) == ["google.com"], a[0])
    check("dns: an SPF record, reverse lookups and _ldap names are not a covert channel", a[1] is None and not caps["dns.cap"].hidden("dns"), a[1])
    check("dns: 14 distinct names; two servers, so no one server", values(a[2]) == ["14"] and a[3] is None, a[2:])
    check("dns_icmp: reverse lookups are not a tunnel", not caps["dpkt-dns_icmp.pcap"].dns_tunnel())
    a = ask("dpkt-http.pcap", "What is the SHA-256 of download.html?", "What URI was requested from www.ethereal.com?", "What did pagead2.googlesyndication.com resolve to?")
    check("http: a whole 200 body's hash is plain and equals tshark's exported object", a[0] == "9475e5443f5581958175c3ec56994a5910e85f64d919631dbf61ef21e0baa859", a[0])
    check("http: the URI by host; two A records are no one answer", offers(a[1], "/download.html") and a[2] is None, a[1:])
    a = ask("http-brotli.pcapng", "What is the SHA-256 of test.txt?")
    check("http: a brotli body is decoded to tshark's object and stays unsure", values(a[0]) == ["23f50f671fb3d35e4800426820b5f9247923f49e891c2be13f6f2db1895d26ca"], a[0])
    st = [s for s in caps["scapy-http_chunk.pcap.gz"].streams().values() if s.dport == 80][0]
    check("http_chunk: a capture that starts on a TCP keep-alive byte still reads the request", st.data.startswith(b"GET /httpgallery/") and st.get("keepalive"), st.data[:20])
    a = ask("scapy-ssh_ed25519.pcap", "What is the SSH server banner?", "What is the IP address of the SSH server?")
    check("ssh: the server's identification string (tshark ssh.protocol from port 22)", values(a[0]) == ["SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1"] and values(a[1]) == ["127.0.0.1"], a)
    a = ask("tls12-dsb.pcapng", "What is the SNI of the first TLS connection?", "What is the JA3 hash of the client?")
    check("tls: SNI and JA3", values(a[0]) == ["example.com"] and values(a[1]) == ["00bcd759cb8ad485fdbf1e7a0c5b94b4"], a)
    check("tls: the embedded key log is reported (decryption is tshark's, in the sandbox)", bool(caps["tls12-dsb.pcapng"].secrets))

    # ---- the command line
    import subprocess
    r = subprocess.run([sys.executable, str(nw.__file__), str(D / "bussing_around.pcapng")], capture_output=True, text=True, timeout=120)
    check("cli: the triage of Bussing Around prints the zip, its comment and the opened flag", r.returncode == 0 and "## hidden_blobs" in r.stdout
          and "The password is" in r.stdout and "## flags" in r.stdout, r.stderr[-300:])

    if os.environ.get("CTF_TK_LIVE") == "1":
        for n in names:
            rows = nw.tshark_fields(load(D, n), ["frame.number"])
            if rows is None:
                print("NOTE sandbox down: the live tshark comparison did not run")
                break
            check(f"live: {n} has {len(rows)} frames in tshark", len(rows) == len(caps[n].packets))
    return finish("test_real_network")


if __name__ == "__main__":
    sys.exit(main())
