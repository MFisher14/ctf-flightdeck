#!/usr/bin/env python3
"""Offline tests for the Day 24+ RECON toolkits built 2026-10-23 (backlog T-a / T-b):
solvers/toolkits/pwn.py (ELF analysis), solvers/toolkits/forensics.py (disk/memory/capture
structure), solvers/toolkits/pwn_target.py (the raw-TCP recon stub). No Game Master request, no
token, no network: every ELF and capture is built in memory, and the only socket test is a scope
refusal that never connects.

  .venv/bin/python tests/test_day24_toolkit_pwn.py

Proves: recon/analysis only, never-guess (unsure/None, never plain), the flag always None, a win
address as a candidate pick, ROP gadgets enumerated (reported) not executed, and the live-target
stub scope-locked to private/registered addresses.
"""
import os
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_day24_pwn_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_PLATFORM_URL"] = "https://2026.huntress.ctf.games/"   # the real GM host, so loopback != GM
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import pytest     # noqa: E402
import labels      # noqa: E402
import pwn as P     # noqa: E402
import forensics as F   # noqa: E402
import pwn_target as PT  # noqa: E402

FAILED = []


def judge_backed() -> bool:
    """True when the loaded labels module replays judge acceptance: labels.judge_ledger() is on
    (the event's judge answers per name). Off, or a labels module without it (the neutral shim),
    means an accepted name is never replayed as a plain answer, so the judge tests cannot pass."""
    ledger = getattr(labels, "judge_ledger", None)
    return callable(ledger) and ledger()


# Judge-acceptance tests (an accepted name replays as plain): marked `judge` and skipped, with the
# reason shown, unless a judge-backed labels module is loaded. They used to be dropped from main().
JUDGE = (pytest.mark.judge, pytest.mark.skipif(
    not judge_backed(), reason="judge-acceptance replay needs a judge-backed labels module "
                               "(labels.judge_ledger() is off or absent)"))


def judge(fn):
    for mark in reversed(JUDGE):
        fn = mark(fn)
    return fn


def run_judge(fn):
    """main()'s call of a judge test: run it, or print why it is skipped (never a silent pass)."""
    if judge_backed():
        fn()
    else:
        print(f"skip {fn.__name__}: {JUDGE[1].kwargs['reason']}")


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


# ---------------------------------------------------------------------------- synthetic ELF

PT_LOAD, PT_INTERP = 1, 3
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4


def make_elf(cls=64, little=True, etype=2, machine=0x3E, entry=0x401234, segments=()):
    """A minimal but valid ELF (header + program headers, no sections). Enough for the header and
    program-header facts; symbol-dependent facts are tested on a hand-built report below."""
    ec = "<" if little else ">"
    ident = b"\x7fELF" + bytes([2 if cls == 64 else 1, 1 if little else 2, 1, 0]) + b"\x00" * 8
    phnum = len(segments)
    if cls == 64:
        phoff, phentsize, ehsize = 64, 56, 64
        hdr = ident + struct.pack(ec + "HHIQQQIHHHHHH", etype, machine, 1, entry, phoff, 0, 0,
                                  ehsize, phentsize, phnum, 64, 0, 0)
        phdrs = b"".join(struct.pack(ec + "IIQQQQQQ", t, fl, 0, 0, 0, 0, 0, 0x1000) for t, fl in segments)
    else:
        phoff, phentsize, ehsize = 52, 32, 52
        hdr = ident + struct.pack(ec + "HHIIIIIHHHHHH", etype, machine, 1, entry, phoff, 0, 0,
                                  ehsize, phentsize, phnum, 40, 0, 0)
        phdrs = b"".join(struct.pack(ec + "IIIIIIII", t, 0, 0, 0, 0, 0, fl, 0x1000) for t, fl in segments)
    return hdr + phdrs


def test_elf_header():
    exe = make_elf(segments=[(PT_LOAD, PF_R | PF_X), (PT_GNU_STACK, PF_R | PF_W)])
    info = P.read_elf(exe)
    check("read_elf: 64-bit little-endian amd64 executable, entry read",
          info and info["class"] == 64 and info["arch"] == "amd64" and info["endian"] == "little"
          and info["type"] == "executable" and info["entry"] == 0x401234, info)
    check("NX enabled from a non-executable GNU_STACK; no PIE for ET_EXEC; RELRO none; no canary",
          info["protections"] == {"nx": "enabled", "pie": "disabled", "relro": "none",
                                  "canary": "disabled", "fortify": "disabled"}, info["protections"])
    rwx = make_elf(segments=[(PT_LOAD, PF_R | PF_X), (PT_GNU_STACK, PF_R | PF_W | PF_X)])
    check("NX disabled from an executable GNU_STACK", P.read_elf(rwx)["protections"]["nx"] == "disabled")
    pie = make_elf(etype=3, segments=[(PT_INTERP, PF_R), (PT_LOAD, PF_R | PF_X),
                                      (PT_GNU_RELRO, PF_R), (PT_GNU_STACK, PF_R | PF_W)])
    prot = P.read_elf(pie)["protections"]
    check("ET_DYN + INTERP -> PIE enabled; GNU_RELRO -> partial RELRO",
          prot["pie"] == "enabled" and prot["relro"] == "partial", prot)
    dso = make_elf(etype=3, segments=[(PT_LOAD, PF_R | PF_X), (PT_GNU_STACK, PF_R | PF_W)])
    check("ET_DYN with no INTERP -> a library (pie=dso), not a PIE executable",
          P.read_elf(dso)["protections"]["pie"] == "dso")
    be32 = make_elf(cls=32, little=False, machine=0x14, entry=0x8048000, segments=[(PT_LOAD, PF_R | PF_X)])
    i2 = P.read_elf(be32)
    check("a 32-bit big-endian powerpc header reads too",
          i2["class"] == 32 and i2["endian"] == "big" and i2["arch"] == "powerpc", i2)
    check("not an ELF -> None (no raise)", P.read_elf(b"not elf" + bytes(64)) is None
          and P.read_elf(b"") is None)


def test_pwn_signals():
    exe = make_elf(segments=[(PT_LOAD, PF_R | PF_X), (PT_GNU_STACK, PF_R | PF_W)])
    qs = [{"id": "q-nx", "question": "Is NX enabled and are there any ROP gadgets?",
           "answer_format": {"kind": "exact_text"}}]
    s_elf = P.signals(qs, {"chall": exe})
    check("signals: an ELF + pwn vocabulary reaches the 0.6 threshold", s_elf >= 0.6, s_elf)
    check("signals: no ELF present -> 0.0 (never competes on non-ELF)",
          P.signals(qs, {"a.bin": bytes(64)}) == 0.0 and P.signals(qs, {"x": b"%PDF-1.4\n"}) == 0.0)
    check("signals: a 64-byte zero blob with a generic question -> 0.0",
          P.signals([{"id": "q", "question": "What is it?"}], {"a.bin": bytes(64)}) == 0.0)


def test_pwn_never_guess():
    exe = make_elf(segments=[(PT_LOAD, PF_R | PF_X), (PT_GNU_STACK, PF_R | PF_W)])
    files = {"chall": exe}
    ctx = {"set": 0, "attempt": {}}

    def ans(qid, question):
        return P.solve_set([{"id": qid, "question": question, "answer_format": {"kind": "exact_text"}}],
                           files, ctx)[qid]

    arch = ans("q1", "What architecture is the binary?")
    check("arch is unsure (labels.pick), never plain, under a pwn.* key",
          labels.is_unsure(arch) and labels.parse(arch).key.startswith("pwn.arch/"), arch)
    nx = ans("q2", "Is NX (no-execute) enabled?")
    check("NX is unsure under a pwn.nx key, enabled spelling first",
          labels.is_unsure(nx) and labels.parse(nx).key.startswith("pwn.nx/")
          and labels.parse(nx).options[0][1] == "enabled", nx)
    endian = ans("q3", "What is the byte order / endianness?")
    check("endianness is unsure (little first)",
          labels.is_unsure(endian) and labels.parse(endian).options[0][1] == "little", endian)
    entry = ans("q4", "What is the entry point address?")
    check("entry point is a candidate pick (hex/dec forms), never plain",
          labels.is_candidate(entry) and any(v == hex(0x401234) for _n, v in labels.parse(entry).options), entry)
    flag = ans("q5", "What is the flag?")
    check("the flag is always None (never derived, never submitted)", flag is None)
    gadget = ans("q6", "How many ROP gadgets does the binary contain?")
    check("a ROP-gadget count is None (tool-defined, never guessed)", gadget is None)
    offset = ans("q7", "What is the offset to the return address?")
    check("a buffer offset is None (unprovable statically)", offset is None)
    check("an unrecognised question is None", ans("q8", "What colour is the icon?") is None)


def test_symbol_facts_and_candidates():
    # A hand-built report exercises the symbol-dependent answers without crafting a symbol table.
    info = {"class": 64, "arch": "amd64", "arch_spellings": ["amd64", "x86_64"], "endian": "little",
            "type": "executable", "entry": 0x401234,
            "protections": {"nx": "enabled", "pie": "disabled", "relro": "none",
                            "canary": "enabled", "fortify": "disabled"},
            "symbols": ["main", "__stack_chk_fail", "win", "gets"],
            "dangerous_imports": ["gets", "system"], "win_candidates": [("win", 0x401176)]}

    def ans(question, aid="a"):
        return P._answer_one({"id": aid, "question": question,
                              "answer_format": {"kind": "exact_text"}}, info)

    canary = ans("Is a stack canary present?")
    check("canary enabled -> unsure 'enabled' under pwn.canary",
          labels.is_unsure(canary) and labels.parse(canary).key.startswith("pwn.canary/")
          and labels.parse(canary).options[0][1] == "enabled", canary)
    vuln = ans("Which dangerous / unsafe function does it import?")
    check("the dangerous function is a candidate pick (gets ranked first), never plain",
          labels.is_candidate(vuln) and labels.parse(vuln).options[0][1] == "gets", vuln)
    winname = ans("What is the name of the win function?")
    check("a win function NAME is a candidate pick", labels.is_candidate(winname)
          and labels.parse(winname).options[0][1] == "win", winname)
    winaddr = ans("What is the address of the win function?", aid="win-addr")
    check("a win ADDRESS is a candidate pick carrying hex and dec forms",
          labels.is_candidate(winaddr)
          and any(v == hex(0x401176) for _n, v in labels.parse(winaddr).options)
          and any(v == str(0x401176) for _n, v in labels.parse(winaddr).options), winaddr)


@judge
def test_h6_per_binary_keying():
    """new-code-audit-v2 H6: a per-binary fact (an NX-off recompile, an aarch64 build) must never
    get the stale accepted label of a different variant. The varying fact is in the key shape, so
    an accepted name answers plain ONLY the variant that carries that value."""
    def ans(info, question, aid="a"):
        return P._answer_one({"id": aid, "question": question,
                              "answer_format": {"kind": "exact_text"}}, info)

    def plain(v):
        return isinstance(v, str) and not labels.is_unsure(v)

    # NX: accepted 'enabled' on an NX-ENABLED binary must not answer an NX-DISABLED one.
    nx_on = P.read_elf(make_elf(segments=[(PT_LOAD, PF_R | PF_X), (PT_GNU_STACK, PF_R | PF_W)]))
    nx_off = P.read_elf(make_elf(segments=[(PT_LOAD, PF_R | PF_X), (PT_GNU_STACK, PF_R | PF_W | PF_X)]))
    check("H6 precondition: NX enabled vs disabled",
          nx_on["protections"]["nx"] == "enabled" and nx_off["protections"]["nx"] == "disabled")
    before = ans(nx_on, "Is NX enabled?")
    check("H6 NX: unsure before any verdict", labels.is_unsure(before), before)
    labels.learn(labels.parse(before).key, "enabled", "accepted", scope="key")  # judge accepts on the enabled variant
    check("H6 NX: enabled variant -> plain 'enabled' (legitimate same-value case still plain)",
          ans(nx_on, "Is NX enabled?") == "enabled")
    off = ans(nx_off, "Is NX enabled?")
    check("H6 NX: disabled variant -> unsure, NOT stale 'enabled'",
          labels.is_unsure(off) and labels.parse(off).options[0][1] == "disabled", off)

    # arch: accepted 'amd64' (e_machine 0x3E) must not answer an aarch64 (0xB7) build.
    amd = P.read_elf(make_elf(machine=0x3E))
    arm = P.read_elf(make_elf(machine=0xB7))
    a_before = ans(amd, "What architecture?")
    labels.learn(labels.parse(a_before).key, "amd64", "accepted", scope="key")
    check("H6 arch: amd64 variant -> plain 'amd64' (legitimate same-value case still plain)",
          ans(amd, "What architecture?") == "amd64")
    a_arm = ans(arm, "What architecture?")
    check("H6 arch: aarch64 variant -> unsure, NOT stale 'amd64'",
          labels.is_unsure(a_arm) and labels.parse(a_arm).options[0][1] == "aarch64", a_arm)
    check("H6: the arch keys of the two variants differ (fact in the shape)",
          labels.parse(a_before).key != labels.parse(a_arm).key)


def test_gadgets_report_only():
    # pop rdi ; ret  (0x5f 0xc3) then a bare ret (0xc3). Enumerated, reported, never executed.
    info = {"class": 64, "arch": "amd64", "exec_sections": [(".text", 0x1000, bytes([0x5F, 0xC3, 0xC3]))]}
    g = P.enumerate_gadgets(info)
    try:
        import capstone  # noqa: F401
        has_cs = True
    except Exception:  # noqa: BLE001
        has_cs = False
    if has_cs:
        texts = [t for _a, t in g]
        check("ROP gadgets are ENUMERATED (a 'pop rdi; ...; ret' gadget found), as data to report",
              g and all(t.endswith("ret") for t in texts) and any("pop rdi" in t for t in texts), texts)
    else:
        print("skip gadget enumeration (capstone absent)")
    check("gadget enumeration returns a list of (addr, text) tuples; it runs nothing",
          isinstance(g, list) and all(isinstance(a, int) and isinstance(t, str) for a, t in g))
    check("a non-x86 arch enumerates no gadgets (no disassembly attempted)",
          P.enumerate_gadgets({"class": 64, "arch": "aarch64", "exec_sections": [(".text", 0, b"\xc3\xc3")]}) == [])


# ---------------------------------------------------------------------------- forensics fixtures

def pcap_bytes():
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # classic pcap, LE, linktype 1 (ethernet)


def pcapng_bytes():
    shb = struct.pack("<II", 0x0A0D0D0A, 28) + struct.pack("<I", 0x1A2B3C4D) + struct.pack("<HHq", 1, 0, -1) \
        + struct.pack("<I", 28)
    idb = struct.pack("<II", 0x00000001, 20) + struct.pack("<HHI", 1, 0, 0) + struct.pack("<I", 20)  # linktype 1
    return shb + idb


def mbr_bytes(fs=None):
    sec = bytearray(512)
    sec[446 + 4] = 0x83                 # one partition entry, type Linux
    sec[510:512] = b"\x55\xaa"
    if fs == "ntfs":
        sec[3:11] = b"NTFS    "
    elif fs == "fat32":
        sec[82:90] = b"FAT32   "
    return bytes(sec)


def gpt_bytes():
    return bytes(512) + b"EFI PART" + bytes(504) + b"\x00" * 0


def ext_bytes():
    b = bytearray(0x440)
    b[0x438:0x43A] = b"\x53\xef"
    return bytes(b)


def test_forensics_readers():
    check("pcap: format/endian/datalink", F.read_capture(pcap_bytes())
          == {"format": "pcap", "endian": "little", "linktype": 1, "linktype_name": "ethernet"})
    png = F.read_capture(pcapng_bytes())
    check("pcapng: format and datalink from the IDB",
          png and png["format"] == "pcapng" and png["linktype_name"] == "ethernet", png)
    check("memory: windows crashdump / LiME / ELF core / minidump",
          F.read_memory(b"PAGEDU64" + bytes(64)) == {"format": "windows_crashdump", "os": "windows"}
          and F.read_memory(b"EMiL" + bytes(64)) == {"format": "lime", "os": "linux"}
          and F.read_memory(b"MDMP" + bytes(64)) == {"format": "minidump", "os": "windows"}
          and F.read_memory(make_elf(etype=4, segments=[(PT_LOAD, PF_R)]))["format"] == "elf_core")
    check("disk: MBR scheme + boot signature", F.read_disk(mbr_bytes())
          == {"scheme": "mbr", "filesystem": None, "boot_signature": True})
    check("disk: NTFS / FAT32 filesystem, GPT scheme, ext superblock",
          F.read_disk(mbr_bytes("ntfs"))["filesystem"] == "ntfs"
          and F.read_disk(mbr_bytes("fat32"))["filesystem"] == "fat32"
          and F.read_disk(gpt_bytes())["scheme"] == "gpt"
          and F.read_disk(ext_bytes())["filesystem"] == "ext")
    check("not a container -> None", F.classify(bytes(64)) is None and F.classify(b"hello") is None)


def test_forensics_signals_and_answers():
    qs = [{"id": "q", "question": "What datalink / link-layer type is the capture?",
           "answer_format": {"kind": "exact_text"}}]
    check("forensics signals on a validatable capture, 0.0 on a zero blob / e-mail-ish text",
          F.signals(qs, {"c.pcap": pcap_bytes()}) >= 0.45 and F.signals(qs, {"a.bin": bytes(64)}) == 0.0
          and F.signals(qs, {"m": b"From: a@b\r\nSubject: x\r\n\r\nhi"}) == 0.0)
    ctx = {"set": 0, "attempt": {}}
    dl = F.solve_set(qs, {"c.pcap": pcap_bytes()}, ctx)["q"]
    check("datalink answer is unsure under forensics.linktype, never plain",
          labels.is_unsure(dl) and labels.parse(dl).key.startswith("forensics.linktype/")
          and labels.parse(dl).options[0][1] == "ethernet", dl)
    count = F.solve_set([{"id": "q", "question": "How many packets are in the capture?"}],
                        {"c.pcap": pcap_bytes()}, ctx)["q"]
    check("a packet count is None (payloads belong to `network`, not this toolkit)", count is None)
    sch = F.solve_set([{"id": "q", "question": "What partition scheme does the disk image use?"}],
                      {"d.img": mbr_bytes()}, ctx)["q"]
    check("partition scheme is unsure under forensics.partition_scheme",
          labels.is_unsure(sch) and labels.parse(sch).key.startswith("forensics.partition_scheme/"), sch)
    flag = F.solve_set([{"id": "q", "question": "What is the flag stored on the disk?"}],
                       {"d.img": mbr_bytes()}, ctx)["q"]
    check("forensics answers the flag None", flag is None)


@judge
def test_forensics_h5_fact_keyed():
    """H5 (docs/retro/new-code-audit-v2.md): a varying container fact (linktype/os/filesystem/...)
    must be keyed by the FACT, not by the KIND, so an accepted name never answers a differing
    variant plain. An accepted name still answers the variant that shares its fact plain."""
    # A linux_sll capture (DLT 113), a LiME dump (linux), a FAT32 MBR -- differing facts.
    linux_sll = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 113)
    lime = b"EMiL" + bytes(64)
    fat32 = mbr_bytes("fat32")
    qdl = [{"id": "q", "question": "What datalink / link-layer type is the capture?",
            "answer_format": {"kind": "exact_text"}}]
    qos = [{"id": "q", "question": "What operating system produced the memory image?"}]
    qfs = [{"id": "q", "question": "What filesystem is on the disk image?"}]
    ctx = {"set": 0, "attempt": {}}

    # The judge has accepted a name for an EARLIER variant whose fact differed.
    labels.learn("forensics.linktype/ethernet", "ethernet", "accepted", scope="key")
    labels.learn("forensics.os/windows", "windows", "accepted", scope="key")
    labels.learn("forensics.filesystem/ntfs", "ntfs", "accepted", scope="key")

    dl = F.solve_set(qdl, {"c.pcap": linux_sll}, ctx)["q"]
    check("H5: linktype on a linux_sll variant is unsure, not the accepted 'ethernet' plain",
          labels.is_unsure(dl) and labels.parse(dl).key == "forensics.linktype/linux_sll"
          and labels.parse(dl).options[0][1] == "linux_sll", dl)
    osv = F.solve_set(qos, {"m.lime": lime}, ctx)["q"]
    check("H5: os on a LiME(linux) dump is unsure, not the accepted 'windows' plain",
          labels.is_unsure(osv) and labels.parse(osv).key == "forensics.os/linux", osv)
    fsv = F.solve_set(qfs, {"d.img": fat32}, ctx)["q"]
    check("H5: filesystem on a FAT32 image is unsure, not the accepted 'ntfs' plain",
          labels.is_unsure(fsv) and labels.parse(fsv).key == "forensics.filesystem/fat32", fsv)

    # The legitimate same-value case is still plain: an ethernet capture after 'ethernet' accepted.
    dl_ok = F.solve_set(qdl, {"c.pcap": pcap_bytes()}, ctx)["q"]
    check("H5: linktype on an ethernet variant is still plain 'ethernet' (fix only restricts)",
          dl_ok == "ethernet", dl_ok)


# ---------------------------------------------------------------------------- the live-target stub

def test_pwn_target_scope():
    check("pwn_target has no solve_set/signals (a hand tool, never matched or on a clock)",
          not hasattr(PT, "solve_set") and not hasattr(PT, "signals"))
    check("a public address is refused and never contacted (OutOfScope)",
          _raises(PT.ct.OutOfScope, lambda: PT.PwnTarget("8.8.8.8", 9999)))
    check("a loopback address is in scope (no connection is made by constructing it)",
          PT.PwnTarget("127.0.0.1", 31337).host == "127.0.0.1")
    check("an unregistered target name is refused (NotRegistered)",
          _raises(PT.ct.NotRegistered, lambda: PT.PwnTarget.from_registry("no-such-target")))
    probes = PT.probes()
    check("the probe library is benign bytes only (no shellcode, no payload)",
          probes and all(isinstance(p, bytes) and len(p) <= 8 for _c, p in probes), probes)
    check("send() refuses anything but caller-supplied bytes (generates no payload)",
          _raises(TypeError, lambda: PT.PwnTarget("127.0.0.1", 1).send(1234)))


def _raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    except Exception as e:  # noqa: BLE001
        return isinstance(e, exc)
    return False


def main():
    import shutil
    try:
        test_elf_header()
        test_pwn_signals()
        test_pwn_never_guess()
        test_symbol_facts_and_candidates()
        run_judge(test_h6_per_binary_keying)
        test_gadgets_report_only()
        test_forensics_readers()
        test_forensics_signals_and_answers()
        run_judge(test_forensics_h5_fact_keyed)
        test_pwn_target_scope()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
