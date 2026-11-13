#!/usr/bin/env python3
"""The email toolkit on real mail (solvers/toolkits/email.py).

  .venv/bin/python tests/real/test_real_email.py

Offline. SKIPs when `challenges/_realdata/email/` is absent (tests/real/fetch_a.py fills it). The files: the
five mails of Huntress CTF 2025 Follow The Money, the mail of Huntress CTF 2024 Ran Somewhere, and public
samples (mail-parser's test mails, extract-msg's .msg examples, CPython's e-mail test messages).

What each expectation rests on:
  attachments   a second reading of the bytes: the base64 block under the part's own file name is cut out
                of the raw mail here and decoded, with no MIME parser; and for Ran Somewhere the three files
                the write-up's author saved from a mail client (same size, same SHA-256).
  headers       mail-parser's readings of the same files, written down on 2026-10-08 (sender, recipient,
                subject, Received count, attachment names).
  .msg          the properties extract-msg reads (subject, sender, attachment names and sizes).
"""
import base64
import hashlib
import importlib.util
import re
import subprocess
import sys

from _real_a import REPO, check, finish, folder, is_plain, manifest, offers, q, timed, values

D = folder("email")
TOOLKIT = REPO / "solvers" / "toolkits" / "email.py"          # loaded by path: its name is the standard library's
spec = importlib.util.spec_from_file_location("tk_email", TOOLKIT)
E = importlib.util.module_from_spec(spec)
sys.modules["tk_email"] = E
spec.loader.exec_module(E)

# mail-parser's readings (2026-10-08): from, to, subject, Received headers
FTM = {1: ("evelyn.carter@harborline-bank.com", "Re: Welcome to Evergate Title! Initial Transfer Guidance"),
       2: ("evelyn.carter@harborline-bank.com", "Re: Upcoming wire for client: M. Rivera — confirming wire details"),
       3: ("justincase@evergatetitle.com", "Re: Incoming Transfer"), 4: ("justincase@evergatetitle.com", "Re: 200 E. Wharf Drive"),
       5: ("justincase@evergatetitle.com", "Re: 200 E. Wharf Drive issue")}
# the three files the Ran Somewhere write-up's author saved from the mail: (name in the mail, bytes, sha256)
RAN = (("4e 6f 74 65.txt", 1127, "037e4514cea88ffc78d9a41fc677b68b1a421a46a44e40a97957109168d967a9"),
       ("66 69 6e 64 20 69 74 20 79 65 74", 2129874, "f496aeba6c9df1e7bfadc5dfe04737ed355f74ee91e01c510351afb557e3135c"),
       ("69 6d 20 6e 65 61 72 62 79", 2505847, "9516faa433a3d09932f5346611ea96df88e794f14c8fd98d45e14cf4ac1ece64"))


def cut_base64(raw: bytes, filename: bytes):
    """The bytes of the base64 part whose headers name the file: cut from the raw mail, no MIME parser."""
    i = raw.find(b'filename="' + filename + b'"')
    if i < 0:
        return None
    m = re.compile(rb"\r?\n\r?\n").search(raw, i)
    end = raw.find(b"\n--", m.end())
    return base64.b64decode(re.sub(rb"\s+", b"", raw[m.end():end if end >= 0 else len(raw)]))


def one(name):
    data = (D / name).read_bytes()
    mails, dt = timed(f"load {name}", lambda: E.load(data, name), len(data))
    return data, (mails[0] if mails else None)


def ask(name, *questions):
    data = (D / name).read_bytes()
    qs = [q(f"q{i}", t if isinstance(t, str) else t[1], "exact_text" if isinstance(t, str) else t[0], artifact=name) for i, t in enumerate(questions)]
    got, _ = timed(f"solve_set {name}", lambda: E.solve_set(qs, {name: data}, {"partial": {}}), len(data))
    return [got.get(x["id"]) for x in qs]


def main() -> int:
    names = [e["name"] for e in manifest("email")]
    check("every mail of the manifest is in the cache", all((D / n).is_file() for n in names), [n for n in names if not (D / n).is_file()][:5])

    # ---- every mail is read and reported, none slowly
    mails = {}
    for n in names:
        try:
            data, m = one(n)
            _, dt = timed(f"report {n}", lambda: E.report(m, qr=False) if m is not None else "", len(data))
        except Exception as e:            # noqa: BLE001  a crash on a real file is the finding
            check(f"{n}: loaded and reported", False, f"{type(e).__name__}: {e}")
            continue
        mails[n] = m
        if m is None:
            check(f"{n}: read as a mail", False, E.sniff(data, n))
    check(f"all {len(mails)} mails load and report without an error", len(mails) == len(names))
    check("signals() is 1.0 for a mail and its questions", E.signals([q("a", "What is the sender's email address?", artifact="m.eml")],
                                                                  {"m.eml": (D / "ftm-email-5.eml").read_bytes()}) >= 0.9)

    # ---- Huntress 2025 Follow The Money: the thread's headers, and the one link that is not the others'
    for i, (sender, subject) in FTM.items():
        m = mails[f"ftm-email-{i}.eml"]
        ad = E.addresses(m)
        check(f"follow the money {i}: sender, subject and three Received headers as mail-parser reads them",
              [a for _, a in ad["from"]] == [sender] and m.get("Subject") == subject and len(m.get_all("Received")) == 3, (ad["from"], m.get("Subject")))
    hosts = {i: sorted({u["host"] for u in E.urls(mails[f"ftm-email-{i}.eml"]) if u["where"].endswith("html:href") and "everg" in (u["host"] or "")}) for i in FTM}
    check("follow the money: mails 3 and 4 link to evergatetitle.netlify.app, mail 5 to evergatetltle.netlify.app (the write-up's finding)",
          hosts[3] == hosts[4] == ["evergatetitle.netlify.app"] and hosts[5] == ["evergatetltle.netlify.app"], hosts)
    la = E.lookalikes(mails["ftm-email-5.eml"])
    check("follow the money 5: the link's host is listed as a look-alike of the sender's domain, one edit apart",
          any(k["domain"] == "evergatetltle.netlify.app" and k["resembles"] == "evergatetitle.com" and k["distance"] == 1 and k["ordered"] for k in la), la)
    check("follow the money 3: no look-alike of the sender's domain when the link is the real one",
          not any("evergate" in k["label"] for k in E.lookalikes(mails["ftm-email-3.eml"])), E.lookalikes(mails["ftm-email-3.eml"]))
    raw5 = (D / "ftm-email-5.eml").read_bytes()
    png = cut_base64(raw5, b"Outlook-abr4cdsm.png")
    a = ask("ftm-email-5.eml", "What is the SHA-256 of Outlook-abr4cdsm.png?", ("integer", "How many attachments does the email have?"),
            'Which URL does the "Evergate Title Transfer" link point to?', "What is the lookalike domain used in the email?",
            "What is the sender's email address?", ("integer", "How many Received headers are there?"), "What is the SPF result?")
    check("follow the money 5: an attachment's SHA-256 is plain and is the hash of the base64 block cut from the raw mail",
          png is not None and a[0] == hashlib.sha256(png).hexdigest(), a[0])
    check("follow the money 5: three attachments (every reading agrees) and three Received headers, plain", a[1] == "3" and a[5] == "3", (a[1], a[5]))
    check("follow the money 5: a link named by its text is answered with its target, unsure", values(a[2])[:1] == ["https://evergatetltle.netlify.app/"], a[2])
    check("follow the money 5: two look-alike pairs in the mail (the bank's own site is one), so no single look-alike is answered", a[3] is None and len(la) == 2, a[3])
    check("follow the money 5: the sender unsure; no SPF result in a mail with no Authentication-Results", values(a[4])[:1] == ["justincase@evergatetitle.com"] and a[6] is None, (a[4], a[6]))

    # ---- Huntress 2024 Ran Somewhere
    m = mails["ran_somewhere.eml"]
    got = {x["filename"]: (x["size"], x["sha256"], x["exact"]) for x in m.attachments}
    check("ran somewhere: the three attachments are byte for byte the files the write-up's author saved", all(got.get(n) == (size, sha, True) for n, size, sha in RAN),
          {k: v[:1] for k, v in got.items()})
    check("ran somewhere: the recipient written `address <address>` is read (the strict standard reader gives nothing for it)",
          [x for _, x in E.addresses(m)["to"]] == ["helpdesk@ITdoesnotexist.tech"], E.addresses(m)["to"])
    a = ask("ran_somewhere.eml", "What is the SHA-256 of the attachment named 4e 6f 74 65.txt?", "Who is the recipient of the email?", ("integer", "How many attachments does the email have?"))
    check("ran somewhere: the named attachment's hash is plain", a[0] == RAN[0][2], a[0])
    check("ran somewhere: the recipient is offered; the attachment count is two readings (an inline logo), so unsure", offers(a[1], "helpdesk@ITdoesnotexist.tech")
          and not is_plain(a[2]) and set(values(a[2])) == {"4", "3"}, a[1:])

    # ---- address headers real mail writes, against mail-parser's readings
    ad = E.addresses(mails["mailparser-mail_test_19.eml"])
    check("an address as display name: `alice@example.com <bob@example.com>` is bob, shown as alice", ad["from"] == [("alice@example.com", "bob@example.com")]
          and [x for _, x in ad["to"]] == ["charlie@example.com", "dave@example.com"], (ad["from"], ad["to"]))
    check("... and the display name's address is reported", E.mismatches(mails["mailparser-mail_test_19.eml"])["display_name_address"] == "alice@example.com")
    ad = E.addresses(mails["mailparser-mail_test_18.eml"])
    check("a comma inside an encoded display name stays in the name", ad["from"] == [("LastßlName, FirstName", "comma.name@example.com")]
          and [x for _, x in ad["to"]] == ["tony.stark@example.com"], (ad["from"], ad["to"]))
    ad = E.addresses(mails["mailparser-mail_test_17.eml"])
    check("an address written wholly as an encoded word is decoded", [x for _, x in ad["from"]] == ["notificaccion-clientes@bbva.mx"], ad["from"])
    ad = E.addresses(mails["mailparser-mail_test_12.eml"])
    check("raw UTF-8 in a To header is read as UTF-8, not as surrogates", [x for _, x in ad["to"]] == ["danglüe@email.com"], ad["to"])
    a = ask("mailparser-mail_test_19.eml", "What is the sender's email address?")
    check("... the sender's address is then offered (it was no answer before)", values(a[0])[:1] == ["bob@example.com"], a[0])

    # ---- attachments real mail writes
    m = mails["mailparser-mail_test_1.eml"]
    raw = (D / "mailparser-mail_test_1.eml").read_bytes()
    zipped = cut_base64(raw, "ФНС_РФ558.zip".encode())
    check("a file name in raw UTF-8 (no RFC 2231, no encoded word) is read: ФНС_РФ558.zip", [x["filename"] for x in m.attachments] == ["ФНС_РФ558.zip"],
          [x["filename"] for x in m.attachments])
    check("... and its bytes are the base64 block of the raw mail (8,932 bytes)", zipped is not None and m.attachments[0]["sha256"] == hashlib.sha256(zipped).hexdigest()
          and m.attachments[0]["size"] == 8932)
    m = mails["mailparser-mail_malformed_2.eml"]
    dsn = [x for x in m.attachments if x["filename"] == "DSN57BAC498.txt"]
    check("a message/delivery-status part with a file name is an attachment by that name, marked not exact (never hashed)", len(dsn) == 1 and not dsn[0]["exact"],
          [(x["filename"], x["exact"]) for x in m.attachments])
    a = ask("mailparser-mail_test_14.eml", ("integer", "How many attachments does the email have?"))
    check("an unnamed inline image: 0 or 1 attachment by the reading, never plain", not is_plain(a[0]) and set(values(a[0])) == {"0", "1"}, a[0])

    # ---- .msg against extract-msg
    try:
        import warnings
        import extract_msg
    except Exception:            # noqa: BLE001
        extract_msg = None
        print("note extract-msg not importable: the .msg comparison is skipped")
    for n in [x for x in names if x.endswith(".msg")]:
        m = mails[n]
        if extract_msg is None or m is None:
            continue
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                x = extract_msg.openMsg(str(D / n))
                theirs = ((x.subject or "").rstrip("\x00"), sorted((a.longFilename or a.shortFilename or "", len(a.data)) for a in x.attachments if isinstance(a.data, bytes)))
                x.close()
            except Exception as e:            # noqa: BLE001  extract-msg cannot read every one of its own examples
                print(f"note extract-msg could not read {n}: {type(e).__name__}")
                continue
        mine = (m.get("Subject") or "", sorted((a["filename"] or "", a["size"]) for a in m.attachments))
        check(f"{n}: subject and attachments (name, bytes) as extract-msg reads them", mine == theirs, (mine, theirs))
    a = ask("extractmsg-unicode.msg", "What is the subject of the email?", "What is the sender's email address?", ("integer", "How many attachments does the email have?"))
    check(".msg: subject and sender unsure, two attachments plain", values(a[0])[:1] == ["Test for TIF files"] and values(a[1])[:1] == ["brizhou@gmail.com"] and a[2] == "2", a)

    # ---- the command line
    r = subprocess.run([sys.executable, str(TOOLKIT), "--no-qr", str(D / "ftm-email-5.eml")], capture_output=True, text=True, timeout=120)
    check("cli: the report of mail 5 names the look-alike domain", r.returncode == 0 and "look-alike domain  evergatetltle.netlify.app" in r.stdout, r.stderr[-300:])
    return finish("test_real_email")


if __name__ == "__main__":
    sys.exit(main())
