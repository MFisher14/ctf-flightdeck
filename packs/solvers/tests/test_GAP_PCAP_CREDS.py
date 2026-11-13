#!/usr/bin/env python3
"""GAP-PCAP-CREDS: the pcap credential-hash extractor (solvers/toolkits/pcap_creds.py).

  .venv/bin/python tests/test_GAP_PCAP_CREDS.py

Proves the never-wrong boundary of a byte-derived hashcat line, offline (no process, no request,
no token, no dependency):

  - The ASSEMBLED HASHCAT STRING (WPA 22000, net-NTLMv1/v2, krb5pa / krb5asrep / krb5tgs) is a
    deterministic encoding of the exact captured bytes.  It is emitted ONLY through
    labels.pick(key, renderings) -- an unsure value (starts with "??"), never plain -- whose
    first rendering equals the known-good line byte-for-byte, and whose renderings are spellings
    (hex case) of that ONE fact.  So gm.session() strips it from a direct submit and verify.py
    probes it on the untimed base.
  - The CRACKED password / PSK / secret is NEVER populated and NEVER submitted: a question that
    asks for it answers None.
  - A handshake missing a required message (no M2 MIC / no ANonce / no ESSID), a truncated
    NTLMSSP blob, a Kerberos enc-part whose etype is not 23, or an ambiguous choice -> None,
    never a padded or guessed line.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import pcap_creds as P   # noqa: E402

SENTINEL = "??"


def _unsure(ans):
    """(key, [(name, value), ...]) for an unsure pick; None for anything else (a plain answer)."""
    if not isinstance(ans, str) or not ans.startswith(SENTINEL):
        return None
    body = json.loads(ans[len(SENTINEL):])
    return body["k"], [tuple(o) for o in body["o"]]


# ---- WPA / EAPOL 22000 ---------------------------------------------------------------------------

def t_eapol_assembled_line_is_exact_bytes():
    cap, expect = P.build_eapol_pcap()
    hs = [h for h in P.extract(cap) if h["field"] == "wpa_hashcat"]
    assert len(hs) == 1, hs
    r = P.renderings(hs[0])
    assert r[0] == ("hashcat_lower", expect), r
    assert expect.startswith("WPA*02*") and expect.endswith("*00"), expect
    # the MIC field of the EAPOL portion is zeroed; the MIC is carried separately
    assert "00112233445566778899aabbccddeeff" == expect.split("*")[2]


def t_eapol_is_unsure_pick_never_plain():
    cap, expect = P.build_eapol_pcap()
    q = {"qid": "q", "question": "Give the hashcat-format (mode 22000) hash of the captured WPA handshake."}
    ans = P.solve_set([q], {"wifi.pcap": cap}, {})["q"]
    got = _unsure(ans)
    assert got is not None, f"must be unsure, not plain: {ans!r}"
    key, opts = got
    assert key == "network.wpa_hashcat/hc22000", key
    assert opts[0] == ("hashcat_lower", expect), opts
    # renderings are spellings of ONE fact: upper is the same string, hex upper-cased
    assert len(opts) == 2 and opts[1][0] == "hashcat_upper"
    assert opts[1][1].lower() == opts[0][1].lower()


def t_eapol_uppercase_rendering_is_hex_only():
    cap, _ = P.build_eapol_pcap(essid=b"HuntNet")
    h = [x for x in P.extract(cap) if x["field"] == "wpa_hashcat"][0]
    lower = P.renderings(h)[0][1]
    upper = P._render_wpa(h, True)
    # the WPA* keyword and separators are unchanged; only the hex payload differs by case
    assert upper.startswith("WPA*02*") and upper.split("*")[:2] == lower.split("*")[:2]
    # same fact, case-insensitively equal, but the hex payload differs by case
    assert upper != lower and upper.lower() == lower.lower()


def t_eapol_missing_m2_is_none():
    cap, _ = P.build_eapol_pcap(drop_m2=True)
    assert [h for h in P.extract(cap) if h["field"] == "wpa_hashcat"] == []
    q = {"qid": "q", "question": "hashcat 22000 of the WPA handshake"}
    assert P.solve_set([q], {"wifi.pcap": cap}, {})["q"] is None


def t_eapol_missing_essid_is_none():
    # a capture with M1 and M2 but no beacon -> no ESSID -> never guessed -> nothing extracted
    cap, _ = P.build_eapol_pcap()
    # strip the beacon by rebuilding without it: assert the extractor needs the ESSID
    import struct
    # tamper: zero the SSID IE length is fragile, so instead prove the rule via the SSID map
    ssids, eapols = P._iter_dot11(
        [fr for lt, fr in _dot11_frames(cap)])
    assert ssids, "beacon SSID should be present in the crafted capture"
    # drop the SSID and re-run the pairing: no ESSID -> no handshake
    assert P._wpa_handshakes({}, eapols) == []


def _dot11_frames(cap):
    for lt, fr in P.read_packets(cap):
        dec = P._decode_frame(lt, fr)
        if dec and dec[0] == "dot11":
            yield lt, dec[1]


# ---- NTLM 5500 / 5600 ----------------------------------------------------------------------------

def t_ntlmv2_assembled_line_is_exact_bytes():
    cap, expect = P.build_ntlmv2_pcap()
    hs = [h for h in P.extract(cap) if h["field"] == "netntlmv2_hashcat"]
    assert len(hs) == 1, hs
    assert P.renderings(hs[0])[0] == ("hashcat_lower", expect)
    # shape: user::domain:serverchallenge:ntproof:blob
    parts = expect.split(":")
    assert parts[0] == "Administrator" and parts[1] == "" and parts[2] == "CORP"
    assert len(parts[3]) == 16                     # 8-byte server challenge
    assert len(parts[4]) == 32                     # 16-byte NTProofStr


def t_ntlmv2_is_unsure_pick_never_plain():
    cap, expect = P.build_ntlmv2_pcap()
    q = {"qid": "n", "question": "Provide the Net-NTLMv2 hash in hashcat format."}
    got = _unsure(P.solve_set([q], {"smb.pcap": cap}, {})["n"])
    assert got is not None, "net-NTLMv2 must be unsure, never plain"
    assert got[0] == "network.netntlmv2_hashcat/mode5600"
    assert got[1][0] == ("hashcat_lower", expect)


def t_ntlmv1_assembled_line_shape():
    cap = _ntlmv1_pcap()
    hs = [h for h in P.extract(cap) if h["field"] == "netntlmv1_hashcat"]
    assert len(hs) == 1, hs
    line = P.renderings(hs[0])[0][1]
    parts = line.split(":")
    # user::domain:lm(48hex):nt(48hex):challenge(16hex)
    assert parts[0] == "user" and parts[1] == "" and parts[2] == "DOM"
    assert len(parts[3]) == 48 and len(parts[4]) == 48 and len(parts[5]) == 16


def t_truncated_ntlmssp_is_none():
    # a type-3 header cut before the security buffers -> no answer, no partial line
    import struct
    trunc = P.NTLMSSP_SIG + struct.pack("<I", 3) + b"\x00" * 8     # far short of the 64-byte header
    cap = P._pcap_wrap(1, [P._eth_ipv4(6, "10.0.0.1", "10.0.0.2", 445, 1234, trunc, tcp=True)])
    assert P.extract(cap) == []


# ---- Kerberos 7500 / 18200 / 13100 ---------------------------------------------------------------

def t_kerberos_asrep_assembled_line_is_exact_bytes():
    cap, expect = P.build_kerberos_asrep_pcap()
    hs = [h for h in P.extract(cap) if h["field"] == "krb5asrep_hashcat"]
    assert len(hs) == 1, hs
    assert P.renderings(hs[0])[0] == ("hashcat_lower", expect)
    assert expect.startswith("$krb5asrep$23$svc_web@CORP.LOCAL:")
    # checksum is the first 16 bytes (32 hex) of the enc-part cipher
    assert expect.split(":")[1].split("$")[0] == "00112233445566778899aabbccddeeff"


def t_kerberos_asrep_is_unsure_pick_never_plain():
    cap, expect = P.build_kerberos_asrep_pcap()
    q = {"qid": "k", "question": "What is the krb5asrep (etype 23) hash from the AS-REP?"}
    got = _unsure(P.solve_set([q], {"krb.pcap": cap}, {})["k"])
    assert got is not None, "krb5asrep must be unsure, never plain"
    assert got[0] == "network.krb5asrep_hashcat/mode18200"
    assert got[1][0] == ("hashcat_lower", expect)


def t_kerberos_wrong_etype_is_none():
    # the same AS-REP with the enc-part etype changed from 23 to 18 (AES256) -> not extractable
    cap = _asrep_etype(18)
    assert [h for h in P.extract(cap) if h["field"] == "krb5asrep_hashcat"] == []


# ---- the cracked secret is never a byte-fact -----------------------------------------------------

def t_password_question_is_always_none():
    cap, _ = P.build_eapol_pcap()
    for text in ("What is the WiFi password recovered from the handshake?",
                 "Crack the PSK and provide the passphrase.",
                 "What is the plaintext password for the user?"):
        q = {"qid": "p", "question": text}
        assert P.solve_set([q], {"wifi.pcap": cap}, {})["p"] is None, text


def t_no_password_field_anywhere():
    cap, _ = P.build_eapol_pcap()
    capn, _ = P.build_ntlmv2_pcap()
    capk, _ = P.build_kerberos_asrep_pcap()
    for c in (cap, capn, capk):
        for h in P.extract(c):
            for forbidden in ("password", "psk", "passphrase", "secret", "plaintext", "cracked"):
                assert forbidden not in h, (forbidden, h)


# ---- routing / ambiguity / the contract shape ----------------------------------------------------

def t_unrelated_question_is_none():
    cap, _ = P.build_eapol_pcap()
    q = {"qid": "u", "question": "How many DNS queries are in the capture?"}
    assert P.solve_set([q], {"wifi.pcap": cap}, {})["u"] is None


def t_no_capture_answers_nothing_and_signals_low():
    q = {"qid": "q", "question": "hashcat 22000 of the WPA handshake"}
    assert P.solve_set([q], {"notes.txt": b"hello"}, {})["q"] is None
    assert P.signals([q], {"notes.txt": b"hello"}) <= 0.3


def t_signals_high_with_capture_and_keywords():
    cap, _ = P.build_eapol_pcap()
    q = {"qid": "q", "question": "Provide the hashcat 22000 hash of the WPA EAPOL handshake."}
    assert P.signals([q], {"wifi.pcap": cap}) >= 0.9


def t_ownership_requires_one_complete_byte_fact():
    cap, expect = P.build_ntlmv2_pcap()
    q = {"qid": "n", "answer_id": "wire-n",
         "question": "Provide the Net-NTLMv2 hash in hashcat format."}
    claim = P.ownership([q], {"smb.pcap": cap})
    assert claim == {"n": [value for _method, value in P.renderings(P.extract(cap)[0])]}, claim
    assert expect in claim["n"]


def t_ownership_negative_controls_fail_closed():
    good, _ = P.build_ntlmv2_pcap()
    incomplete = good[:24]                         # valid pcap header, no complete exchange
    hash_q = {"qid": "h", "question": "Provide the Net-NTLMv2 hash in hashcat format."}
    secret_q = {"qid": "p", "question": "What cracked password does this NTLMv2 exchange use?"}
    dns_q = {"qid": "d", "question": "Which DNS name was queried?"}
    assert P.ownership([hash_q], {"broken.pcap": incomplete}) == {}
    assert P.ownership([secret_q], {"smb.pcap": good}) == {}
    assert P.ownership([dns_q], {"smb.pcap": good}) == {}
    assert P.ownership([hash_q], {"notes.txt": b"NTLMSSP hashcat 5600"}) == {}


def t_ownership_is_cold_state_independent():
    cap, expect = P.build_ntlmv2_pcap()
    q = {"qid": "n", "question": "Provide the Net-NTLMv2 hash in hashcat format."}
    P._cache.clear()
    first = P.ownership([q], {"cold.pcap": bytes(cap)})
    P._cache.clear()
    # An unrelated malformed capture first must not prime the result or suppress the complete one.
    assert P.ownership([q], {"bad.pcap": cap[:24]}) == {}
    second = P.ownership([q], {"cold.pcap": bytes(bytearray(cap))})
    assert first == second and expect in second["n"]


def t_solve_set_fills_partial():
    cap, expect = P.build_eapol_pcap()
    ctx = {"partial": {}}
    q = {"qid": "q", "question": "hashcat 22000 of the WPA handshake"}
    out = P.solve_set([q], {"wifi.pcap": cap}, ctx)
    assert out["q"] == ctx["partial"]["q"] and out["q"] is not None


# ---- helpers that build extra fixtures the module's own builders do not ---------------------------

def _ntlmv1_pcap():
    import struct
    challenge = bytes.fromhex("0011223344556677")
    t2 = bytearray(P.NTLMSSP_SIG + struct.pack("<I", 2))
    t2 += struct.pack("<HHI", 0, 0, 0) + struct.pack("<I", 0x00000001) + challenge + b"\x00" * 8
    user = "user".encode("utf-16-le")
    domain = "DOM".encode("utf-16-le")
    lm = bytes(range(24))
    nt = bytes(range(24, 48))          # exactly 24 bytes -> NTLMv1
    base = 64
    nt_off = base + len(lm)
    dom_off = nt_off + len(nt)
    usr_off = dom_off + len(domain)
    ws_off = usr_off + len(user)
    t3 = bytearray(P.NTLMSSP_SIG + struct.pack("<I", 3))
    t3 += struct.pack("<HHI", len(lm), len(lm), base)
    t3 += struct.pack("<HHI", len(nt), len(nt), nt_off)
    t3 += struct.pack("<HHI", len(domain), len(domain), dom_off)
    t3 += struct.pack("<HHI", len(user), len(user), usr_off)
    t3 += struct.pack("<HHI", 0, 0, ws_off)
    t3 += struct.pack("<HHI", 0, 0, ws_off)
    t3 += struct.pack("<I", 0x00000001)
    assert len(t3) == base
    t3 += lm + nt + domain + user
    return P._pcap_wrap(1, [
        P._eth_ipv4(6, "10.0.0.2", "10.0.0.5", 445, 50000, bytes(t2), tcp=True),
        P._eth_ipv4(6, "10.0.0.5", "10.0.0.2", 50000, 445, bytes(t3), tcp=True),
    ])


def _asrep_etype(etype):
    """Rebuild the crafted AS-REP with a chosen enc-part etype (23 = RC4, else not extractable)."""
    def dl(n):
        return P._der_len(n)

    def tlv(tag, body):
        return bytes([tag]) + dl(len(body)) + body

    def ctx(n, inner):
        return tlv(0xA0 | n, inner)

    def integer(v):
        b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
        return tlv(0x02, b)

    def gstr(s):
        return tlv(0x1B, s.encode())

    def seq(body):
        return tlv(0x30, body)

    realm, user = "CORP.LOCAL", "svc_web"
    cipher = bytes(56)
    cname = seq(ctx(0, integer(1)) + ctx(1, seq(gstr(user))))
    encdata = seq(ctx(0, integer(etype)) + ctx(2, tlv(0x04, cipher)))
    ticket = tlv(0x61, seq(ctx(0, integer(5)) + ctx(1, gstr(realm))
                 + ctx(2, seq(ctx(0, integer(2)) + ctx(1, seq(gstr("krbtgt") + gstr(realm)))))
                 + ctx(3, seq(ctx(0, integer(23)) + ctx(2, tlv(0x04, bytes(20)))))))
    kdc_rep = seq(ctx(0, integer(5)) + ctx(1, integer(11)) + ctx(3, gstr(realm))
                  + ctx(4, cname) + ctx(5, ticket) + ctx(6, encdata))
    as_rep = tlv(0x6B, kdc_rep)
    return P._pcap_wrap(1, [P._eth_ipv4(17, "10.0.0.9", "10.0.0.1", 88, 40000, as_rep, tcp=False)])


TESTS = [
    t_eapol_assembled_line_is_exact_bytes,
    t_eapol_is_unsure_pick_never_plain,
    t_eapol_uppercase_rendering_is_hex_only,
    t_eapol_missing_m2_is_none,
    t_eapol_missing_essid_is_none,
    t_ntlmv2_assembled_line_is_exact_bytes,
    t_ntlmv2_is_unsure_pick_never_plain,
    t_ntlmv1_assembled_line_shape,
    t_truncated_ntlmssp_is_none,
    t_kerberos_asrep_assembled_line_is_exact_bytes,
    t_kerberos_asrep_is_unsure_pick_never_plain,
    t_kerberos_wrong_etype_is_none,
    t_password_question_is_always_none,
    t_no_password_field_anywhere,
    t_unrelated_question_is_none,
    t_no_capture_answers_nothing_and_signals_low,
    t_signals_high_with_capture_and_keywords,
    t_ownership_requires_one_complete_byte_fact,
    t_ownership_negative_controls_fail_closed,
    t_ownership_is_cold_state_independent,
    t_solve_set_fills_partial,
]


def main():
    failed = 0
    for test in TESTS:
        try:
            test()
        except AssertionError as e:
            failed += 1
            import traceback
            where = traceback.extract_tb(e.__traceback__)[-1]
            print(f"FAIL  {test.__name__[2:]}: line {where.lineno}: {str(e)[:900]}")
        except Exception as e:
            failed += 1
            import traceback
            where = traceback.extract_tb(e.__traceback__)[-1]
            print(f"FAIL  {test.__name__[2:]}: raised {type(e).__name__}: {e} "
                  f"({Path(where.filename).name}:{where.lineno})")
        else:
            print(f"pass  {test.__name__[2:]}")
    print("ok" if not failed else f"{failed} check(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
