#!/usr/bin/env python3
"""The malconfig toolkit on real artifacts: a real native PE (Huntress 2024 'In Plain Sight'), a defanged
VBScript (Huntress 2024 'Ping Me'), and, built here from real inputs, Lua bytecode compiled by the system
luac and the real PE XOR-encoded under a key in the blob (the shape of a packed loader's embedded payload).
No live malware: the PE is a benign crackme and the VBScript is the write-up author's defanged copy.

  .venv/bin/python tests/real/test_real_malconfig.py    the real-file groups SKIP when challenges/_realdata/malconfig is absent

Offline; the cache is filled by tests/real/fetch_c.py. The truth of each file is in the manifest's `what`.
"""
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_c as R  # noqa: E402

tk, ROOT = R.start("malconfig")
lib = tk.lib
check, q = R.check, R.q


def built_in_memory():
    """Real Lua bytecode (system luac) and a real PE XOR-encoded: both run with no cache."""
    luac = shutil.which("luac5.4") or shutil.which("luac")
    if not luac:
        print("SKIP the Lua checks: no luac on PATH")
    else:
        src = 'local c = {c2="updates.cdn-sync.example", port=8443, key="s3cr3tdemokey123"} return c\n'
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "c.lua").write_text(src)
            out = Path(td) / "c.luac"
            subprocess.run([luac, "-o", str(out), str(Path(td) / "c.lua")], check=True, timeout=20)
            data = out.read_bytes()
        info = lib.lua_constants(data)
        check("real luac output: read as Lua bytecode, its string constants recovered",
              info and str(info.get("version", "")).startswith("5.") and "updates.cdn-sync.example" in (info.get("strings") or []), info and info.get("version"))
        got = tk.solve_set([q("fam", "Which malware family is this?"), q("c2", "What is the C2 host in the config?")], {"cfg.luac": data}, {})
        check("real luac: family offered as lua (unsure), and a Lua chunk's constants are not a validated config (c2 None)",
              not R.plain(got["fam"]) and got["fam"] is not None and got["c2"] is None, got)
        check("real luac: signals is non-zero (a Lua marker) but it is no config match on its own", 0 < tk.signals([q("f", "family?")], {"c.luac": data}) <= 0.6)

    # a real PE (the 96 KB .NET assembly) hidden under a repeating XOR, with the key written beside it
    try:
        pe = R.data(ROOT, "HelpfulDesk.dll")
    except R.Skip:
        pe = None
    if pe is not None:
        for key in (b"demokey1", b"K7"):
            blob = b'{"c2":"evil.example","payload_xor":true}\n' + bytes(b ^ key[i % len(key)] for i, b in enumerate(pe))
            hits = lib.xor_pe(blob)
            ok = len(hits) == 1 and hits[0]["key"] == key and hashlib.sha256(hits[0]["plain"][:hits[0]["size"]]).hexdigest() == hashlib.sha256(pe).hexdigest()
            check(f"xor_pe recovers the real PE byte-for-byte under a {len(key)}-byte key", ok, [(h['key'], h['size']) for h in hits])
        # the clean PE on its own is no XOR-ed payload
        check("xor_pe does not invent a payload in the clean PE", lib.xor_pe(pe) == [], len(lib.xor_pe(pe)))


def dotnet_assembly():
    pe = R.data(ROOT, "HelpfulDesk.dll")
    us = lib.us_strings(pe)
    info = lib.dotnet(pe)
    pairs = lib.xor_b64_pairs(info.get("strings") or []) if hasattr(lib, "xor_b64_pairs") else []
    check("Helpful Desk: the real .NET assembly's #US stream has 248 user strings and no RedLine-style XOR/base64 pairs",
          len(us) == 248 and not pairs, (len(us), len(pairs)))
    check("Helpful Desk: proof=pe, and no config (benign app) so signal 0.0 with no question", lib.proof(pe) == "pe" and tk.signals([], {"HelpfulDesk.dll": pe}) == 0.0)


def real_pe():
    pe = R.data(ROOT, "in_plain_sight.exe")
    check("In Plain Sight: a real native PE (proof=pe), not .NET, no #US strings",
          lib.proof(pe) == "pe" and (lib.dotnet(pe) or {}).get("user_strings") in (None, []), lib.proof(pe))
    got = R.timed("solve_set on in_plain_sight.exe (4.7 MB)", tk.solve_set,
                  [q("c2", "What is the C2 server address in the config?"), q("fam", "Which malware family is this?"),
                   q("key", "What is the encryption key in the config?")], {"in_plain_sight.exe": pe}, {})
    check("In Plain Sight: a benign PE with no config answers nothing, invents no family or key", got == {"c2": None, "fam": None, "key": None}, got)
    check("In Plain Sight: with no questions its signal is 0 (no malware marks)", tk.signals([], {"in_plain_sight.exe": pe}) == 0.0)


def defanged_vbs():
    d = R.data(ROOT, "ping_me_defanged.vbs")
    got = R.timed("solve_set on ping_me_defanged.vbs", tk.solve_set,
                  [q("c2", "What is the C2 address in the config?"), q("key", "What is the XOR key?"), q("fam", "Which malware family?")], {"ping_me_defanged.vbs": d}, {})
    check("Ping Me (defanged): a script with no binary config answers nothing", got == {"c2": None, "key": None, "fam": None}, got)
    check("Ping Me: no HCFG/validated config reading in the script", lib.config(d) is None or lib.config(d).get("valid") in (None, "json", "ini"), lib.config(d))


for fn in (built_in_memory, dotnet_assembly, real_pe, defanged_vbs):
    R.section(fn)
sys.exit(R.finish("test_real_malconfig"))
