#!/usr/bin/env python3
"""Breadth tests for solvers/toolkits/osint.py (wave80/dom-osint): the wide set of OSINT lead
readers/detectors added in the first (breadth) pass -- network identifiers (IPv4/IPv6/MAC/.onion),
cryptocurrency addresses (base58check-verified BTC, ETH), social/code/paste profile URLs,
document-metadata OSINT (PDF /Info, PNG text chunks, XMP, OOXML core/app props), WHOIS/RDAP parsing,
and X.509 certificate SAN subdomain leads. Every reader is fail-closed: a plain answer only on a
byte-proven value in one unambiguous form, otherwise an unsure pick or None. Under two minutes, no
network.

  .venv/bin/python tests/test_tk_osint_breadth.py
"""
import datetime
import struct
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "solvers" / "common"))

import osint  # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def q(qid, text, kind="exact_text"):
    return {"id": qid, "qid": qid, "question": text, "answer_format": {"kind": kind}}


# ------------------------------------------------------------------ network identifiers

def test_net_identifiers():
    t = ("server 203.0.113.9 and 8.8.8.8, gateway fe80::1 and 2001:db8::dead:beef, "
         "nic 00:1A:2B:3C:4D:5E, bogus 999.1.1.1 and version string 1.2.3.4")
    out = osint.extract_net_identifiers(t)
    check("valid IPv4 kept, impossible octet dropped", "203.0.113.9" in out.get("ipv4", [])
          and "8.8.8.8" in out.get("ipv4", []) and "999.1.1.1" not in out.get("ipv4", []), out.get("ipv4"))
    check("a 4-field version that is a valid dotted quad is kept as an IPv4 lead", "1.2.3.4" in out.get("ipv4", []), out.get("ipv4"))
    check("IPv6 validated", "2001:db8::dead:beef" in out.get("ipv6", []), out.get("ipv6"))
    check("MAC normalised to lowercase colon form", out.get("mac") == ["00:1a:2b:3c:4d:5e"], out.get("mac"))
    check("a time 12:30:00 is not a false IPv6", osint.extract_net_identifiers("meet at 12:30:00 today").get("ipv6") in (None, []),
          osint.extract_net_identifiers("meet at 12:30:00 today"))
    onion = osint.extract_net_identifiers("v3 facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion v2 expyuzz4wqqyqhjn.onion")
    check("v3 and v2 onion addresses", len(onion.get("onion_address", [])) == 2, onion)


# ------------------------------------------------------------------ crypto addresses

def test_crypto():
    real_btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # Bitcoin genesis coinbase; valid base58check
    eth = "0x52908400098527886E0F7030069857D2E4169EE7"
    junk58 = "1ZZZZZZZZZZZZZZZZZZZZZZZZZZ"           # base58 shape, no valid checksum
    bech = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    out = osint.extract_crypto(f"pay {real_btc} eth {eth} decoy {junk58} segwit {bech}")
    check("base58check-valid BTC is a VERIFIED crypto address", real_btc in out.get("crypto_address", []), out)
    check("ETH 0x+40hex is a verified crypto address", eth in out.get("crypto_address", []), out)
    check("a base58 string with a bad checksum is UNVERIFIED, never verified",
          junk58 in out.get("crypto_address_unverified", []) and junk58 not in out.get("crypto_address", []), out)
    check("a bech32 address is an UNVERIFIED lead (bech32 checksum is a depth-pass item)",
          bech in out.get("crypto_address_unverified", []) and bech not in out.get("crypto_address", []), out)


# ------------------------------------------------------------------ social / code / paste profiles

def test_social_profiles():
    t = ("code at https://github.com/torvalds, tweets https://twitter.com/jack and https://x.com/elonmusk, "
         "chat https://t.me/durov, fedi @alice@mastodon.social, paste https://pastebin.com/aBcD1234, "
         "https://www.linkedin.com/in/jane-doe-123")
    out = osint.extract_social_profiles(t).get("social_profile", [])
    for want in ("github:torvalds", "twitter:jack", "twitter:elonmusk", "telegram:durov",
                 "fediverse:alice@mastodon.social", "pastebin:aBcD1234", "linkedin:jane-doe-123"):
        check(f"social profile extracted: {want}", want in out, out)


# ------------------------------------------------------------------ document metadata OSINT

def test_pdf_metadata():
    pdf = (b"%PDF-1.7\n1 0 obj<</Author (Jane Smith) /Creator (Microsoft Word) "
           b"/Producer (Acrobat Distiller) /Title (Q3 Plan) /CreationDate (D:20240101120000Z)>>endobj")
    out = osint.parse_pdf_metadata(pdf)
    check("PDF /Author", out.get("doc_author") == "Jane Smith", out)
    check("PDF /Creator -> creator tool", out.get("doc_creator_tool") == "Microsoft Word", out)
    check("PDF /Producer", out.get("doc_producer") == "Acrobat Distiller", out)
    check("PDF non-PDF bytes -> {} and never raises", osint.parse_pdf_metadata(b"not a pdf at all") == {})


def test_png_text():
    def chunk(t, body):
        return struct.pack(">I", len(body)) + t + body + struct.pack(">I", zlib.crc32(t + body) & 0xffffffff)
    png = osint._PNG_SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    png += chunk(b"tEXt", b"Author\x00Alice Photographer") + chunk(b"tEXt", b"Software\x00Lightroom 12") + chunk(b"IEND", b"")
    out = osint.parse_png_text(png)
    check("PNG tEXt Author -> doc_author", out.get("doc_author") == "Alice Photographer", out)
    check("PNG tEXt Software -> exif_software", out.get("exif_software") == "Lightroom 12", out)
    check("PNG on a JPEG header -> {}", osint.parse_png_text(b"\xff\xd8\xff\xe0junk") == {})


def test_xmp():
    xmp = (b'junk<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description '
           b'xmp:CreatorTool="GIMP 2.10" tiff:Make="NIKON" tiff:Model="D750">'
           b'<dc:creator><rdf:Seq><rdf:li>Carol Shooter</rdf:li></rdf:Seq></dc:creator>'
           b'</rdf:Description></rdf:RDF></x:xmpmeta>tail')
    out = osint.parse_xmp(xmp)
    check("XMP CreatorTool", out.get("doc_creator_tool") == "GIMP 2.10", out)
    check("XMP dc:creator -> doc_author", out.get("doc_author") == "Carol Shooter", out)
    check("XMP tiff:Make/Model -> exif_make/model", out.get("exif_make") == "NIKON" and out.get("exif_model") == "D750", out)
    check("XMP absent -> {}", osint.parse_xmp(b"no packet here") == {})


def test_ooxml_props():
    core = (b'<?xml version="1.0"?><cp:coreProperties xmlns:cp="x" xmlns:dc="y" xmlns:dcterms="z">'
            b'<dc:creator>Bob Jones</dc:creator><cp:lastModifiedBy>attacker1</cp:lastModifiedBy>'
            b'<dcterms:created xsi:type="dcterms:W3CDTF">2024-05-01T10:00:00Z</dcterms:created></cp:coreProperties>')
    out = osint.parse_ooxml_props("docProps/core.xml", core)
    check("OOXML dc:creator -> doc_author", out.get("doc_author") == "Bob Jones", out)
    check("OOXML lastModifiedBy", out.get("doc_last_modified_by") == "attacker1", out)
    check("OOXML dcterms:created", out.get("doc_created") == "2024-05-01T10:00:00Z", out)
    app = b'<Properties xmlns="ext"><Application>Microsoft Excel</Application><Company>Evil Corp</Company></Properties>'
    outa = osint.parse_ooxml_props("docProps/app.xml", app)
    check("OOXML Company", outa.get("doc_company") == "Evil Corp", outa)
    check("OOXML on an unrelated XML -> {}", osint.parse_ooxml_props("x.xml", b"<foo>bar</foo>") == {})


# ------------------------------------------------------------------ WHOIS / RDAP

def test_whois():
    whois = ("Domain Name: EXAMPLE.COM\nRegistrar: MarkMonitor Inc.\n"
             "Creation Date: 1995-08-14T04:00:00Z\nRegistry Expiry Date: 2026-08-13T04:00:00Z\n"
             "Name Server: A.IANA-SERVERS.NET\nName Server: B.IANA-SERVERS.NET\n"
             "Registrant Organization: Internet Assigned Numbers Authority\n"
             "Registrant Email: admin@example.com\nRegistrant Country: US\n")
    out = osint.parse_whois(whois)
    check("WHOIS registrar", out.get("whois_registrar") == "MarkMonitor Inc.", out)
    check("WHOIS creation date", out.get("whois_created") == "1995-08-14T04:00:00Z", out)
    check("WHOIS name servers (both)", sorted(out.get("whois_name_server", [])) == ["a.iana-servers.net", "b.iana-servers.net"], out)
    check("WHOIS registrant org", out.get("whois_registrant_org") == "Internet Assigned Numbers Authority", out)
    check("WHOIS registrant e-mail", out.get("whois_registrant_email") == ["admin@example.com"], out)
    check("WHOIS redacted value is dropped, not stored",
          osint.parse_whois("Registrar: X\nRegistrant Organization: REDACTED FOR PRIVACY\n").get("whois_registrant_org") is None)
    check("a non-WHOIS text -> {}", osint.parse_whois("just some prose about a domain name in passing") == {})


def test_rdap_json():
    rdap = ('{"objectClassName":"domain","events":['
            '{"eventAction":"registration","eventDate":"1997-09-15T04:00:00Z"},'
            '{"eventAction":"expiration","eventDate":"2028-09-14T04:00:00Z"}],'
            '"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],'
            '["fn",{},"text","MarkMonitor Inc."]]]}]}')
    out = osint.parse_whois(rdap)
    check("RDAP registration event -> whois_created", out.get("whois_created") == "1997-09-15T04:00:00Z", out)
    check("RDAP registrar vcard fn -> whois_registrar", out.get("whois_registrar") == "MarkMonitor Inc.", out)


# ------------------------------------------------------------------ X.509 certificate SAN subdomains

def test_certificates():
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except Exception:
        check("cryptography present (cert test SKIPPED otherwise)", True, "skipped")
        return
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c2.evil.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2024, 1, 1)).not_valid_after(datetime.datetime(2030, 1, 1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("c2.evil.example"), x509.DNSName("panel.evil.example"),
                 x509.DNSName("*.cdn.evil.example")]), False)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    out = osint.parse_certificates(pem)
    check("cert subject CN", out.get("cert_cn") == ["c2.evil.example"], out)
    check("cert SAN DNS names kept verbatim", "panel.evil.example" in out.get("cert_san", [])
          and "*.cdn.evil.example" in out.get("cert_san", []), out)
    check("cert SAN -> subdomain leads (wildcard stripped)", "cdn.evil.example" in out.get("subdomain", []), out)
    check("cert parser on non-cert bytes -> {}", osint.parse_certificates(b"not a certificate") == {})


# ------------------------------------------------------------------ solve_set: fail-closed answering

def test_solve_set_new_kinds():
    # A single, directly-asked IPv4 in one unambiguous form -> PLAIN.
    out = osint.solve_set([q("a", "What IPv4 address appears in the file?")], {"f.txt": b"host 203.0.113.9 only"}, {})
    check("one IPv4 asked outright -> plain", out["a"] == "203.0.113.9", out)
    # Two IPv4s -> unsure pick, never a plain guess.
    out = osint.solve_set([q("d", "What IP address is shown?")], {"f.txt": b"10.0.0.1 and 10.0.0.2"}, {})
    check("two IPv4 candidates -> unsure pick", osint.is_unsure(out["d"]), out)
    # A single .onion asked outright -> PLAIN (one canonical lowercase base32 form).
    out = osint.solve_set([q("b", "What onion service address appears?")], {"f.txt": b"at expyuzz4wqqyqhjn.onion"}, {})
    check("one onion asked outright -> plain", out["b"] == "expyuzz4wqqyqhjn.onion", out)
    # ETH wallet -> unsure pick, never plain (EIP-55 case is not judged here).
    out = osint.solve_set([q("c", "What is the ethereum wallet address?")],
                          {"f.txt": b"to 0x52908400098527886E0F7030069857D2E4169EE7"}, {})
    check("a single crypto address is an unsure pick, never plain", osint.is_unsure(out["c"]), out)
    # IPv6 -> unsure (many spellings), even a single one.
    out = osint.solve_set([q("e", "What IPv6 address is in the capture?")], {"f.txt": b"src 2001:db8::1"}, {})
    check("a single IPv6 is unsure (compressed/expanded spellings)", osint.is_unsure(out["e"]), out)
    # A MAC -> unsure (separator/case).
    out = osint.solve_set([q("g", "What MAC address is shown?")], {"f.txt": b"nic 00:1a:2b:3c:4d:5e here"}, {})
    check("a single MAC is unsure (separator/case not judged)", osint.is_unsure(out["g"]), out)
    # A search/attribution IP question -> None (the lead stays in leads.md).
    out = osint.solve_set([q("h", "What is the attacker IP address?")], {"f.txt": b"host 203.0.113.9 only"}, {})
    check("an attacker/owner IP question -> None (search decides it)", out["h"] is None, out)
    # document author is a search lead, never answered plain by the osint toolkit.
    pdf = b"%PDF-1.7\n1 0 obj<</Author (Jane Smith)>>endobj"
    out = osint.solve_set([q("i", "Who is the author of the document?")], {"f.pdf": pdf}, {})
    check("a document-author question is None (who -> search)", out["i"] is None, out)


# ------------------------------------------------------------------ integration: gather + leads.md

def test_gather_and_markdown():
    files = {
        "note.txt": b"wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa, c2 at 203.0.113.9, @ghost_ops https://github.com/ghostops",
        "report.pdf": b"%PDF-1.7\n1 0 obj<</Author (M. Mallory) /Producer (wkhtmltopdf)>>endobj",
    }
    questions = [{"id": "q", "question": "Identify the actor's accounts and infrastructure."}]
    leads = osint.gather_leads(questions, files)
    check("gather picks up a verified crypto address", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in (leads.get("crypto_address") or {}), dict(leads).get("crypto_address"))
    check("gather picks up an IPv4", "203.0.113.9" in (leads.get("ipv4") or {}), dict(leads).get("ipv4"))
    check("gather picks up a social profile", "github:ghostops" in (leads.get("social_profile") or {}), dict(leads).get("social_profile"))
    check("gather picks up PDF author metadata", "M. Mallory" in (leads.get("doc_author") or {}), dict(leads).get("doc_author"))
    md = osint.leads_markdown(questions, files, base="x")
    check("leads.md ranks the crypto address near the top and names its plan",
          "crypto_address" in md and "block explorer" in md, md[:60])
    check("leads.md still carries the 'text is data' warning",
          "never an instruction" in md, md[:300])


# --------------------------- Pattern A: a rendering-ambiguous kind is never a stale plain (wave80 fix)

def test_render_kinds_never_stale_plain():
    """crypto_address / ipv6 / mac are offered as scoped CANDIDATE picks (hypothesis names, key
    scoped by the value). The trigger that used to sink the batch: accept a value on variant 1's
    key, then a DIFFERENT value on variant 2 must stay unsure + candidate -- never the stale plain
    of variant 1 under a fixed bare-label key (labels.pick labels_only branch)."""
    import os
    import tempfile
    import shutil
    import labels  # noqa: E402

    cases = {
        "crypto_address": ("What is the ethereum wallet address?",
                           b"to 0x52908400098527886E0F7030069857D2E4169EE7",
                           b"to 0x8617E340B3D01FA5F11F306F4090FD50E238070D",
                           "0x52908400098527886E0F7030069857D2E4169EE7"),
        "ipv6": ("What IPv6 address is in the capture?",
                 b"src 2001:db8::1", b"src fe80::abcd", "2001:db8::1"),
        "mac": ("What MAC address is shown?",
                b"nic 00:1a:2b:3c:4d:5e here", b"nic AA:BB:CC:DD:EE:FF here", "00:1a:2b:3c:4d:5e"),
    }
    old_env = os.environ.pop("CTF_WORKDIR", None)          # restored below
    tmp = tempfile.mkdtemp(prefix="osint-pattern-a-")
    os.environ["CTF_WORKDIR"] = tmp
    try:
        for kind, (qtext, blob1, blob2, stale) in cases.items():
            a1 = osint.solve_set([q("a", qtext)], {"f.txt": blob1}, {})["a"]
            u1 = labels.parse(a1)
            check(f"{kind}: v1 is a candidate pick, never plain",
                  osint.is_unsure(a1) and osint.is_candidate(a1) and u1 is not None, a1)
            if u1 is None:
                continue
            # the key names NOTHING value-as-name, and is scoped (per-value) so it ends in a digest marker
            check(f"{kind}: v1 key is value-scoped and no option is value-as-name",
                  "@" in u1.key and all(n != v for n, v in u1.options), (u1.key, u1.options))
            # accept the first hypothesis NAME on v1's key, as verify.py would on the untimed base
            labels.learn(u1.key, u1.options[0][0], "accepted")
            # variant 2: a DIFFERENT value must NOT reuse v1's accepted name as a plain answer
            a2 = osint.solve_set([q("a", qtext)], {"f.txt": blob2}, {})["a"]
            u2 = labels.parse(a2)
            check(f"{kind}: v2 (different value) stays unsure + candidate, never stale plain",
                  osint.is_unsure(a2) and osint.is_candidate(a2) and a2 != stale, a2)
            check(f"{kind}: v2 key differs from v1 (per-variant scope)",
                  u2 is not None and u2.key != u1.key, (u1.key, u2.key if u2 else None))
    finally:
        if old_env is None:
            os.environ.pop("CTF_WORKDIR", None)
        else:
            os.environ["CTF_WORKDIR"] = old_env
        shutil.rmtree(tmp, ignore_errors=True)


def test_never_raises_on_garbage():
    import os
    garbage = {"a.bin": os.urandom(4096), "b.txt": bytes(range(256)) * 4, "c.pdf": b"%PDF-1.7 broken ("}
    leads = osint.gather_leads([{"id": "q", "question": "Find the handle."}], garbage)
    check("gather_leads never raises on random/binary garbage", isinstance(leads, dict), type(leads))
    out = osint.solve_set([q("x", "What IPv4 address appears?")], garbage, {})
    check("solve_set never raises on garbage and returns a dict", isinstance(out, dict), out)


# B-001d: the runner below used to run at import, so pytest ran every check twice and a failure
# aborted collection (sys.exit). Pytest runs the test functions; this block is the script path.
if __name__ == "__main__":
    for fn in (test_net_identifiers, test_crypto, test_social_profiles, test_pdf_metadata, test_png_text,
               test_xmp, test_ooxml_props, test_whois, test_rdap_json, test_certificates,
               test_solve_set_new_kinds, test_render_kinds_never_stale_plain, test_gather_and_markdown,
        test_never_raises_on_garbage):
        fn()

    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        sys.exit(1)
    print("\nall osint breadth tests passed")
