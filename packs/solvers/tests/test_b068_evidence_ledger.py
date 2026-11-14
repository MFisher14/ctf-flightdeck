"""B-068 -- Evidence ledger: cross-file key/GUID/password join.

Every fixture is built synthetically in the test; nothing is executed and no real challenge file is
used. The LNK, registry-hive and FTP-capture byte layouts are hand-built to the documented formats
(MS-SHLLINK, regf, pcap/TCP) so each reader is exercised against bytes it must truly parse, not a
mock of itself. The module never invents a password: every candidate it returns literally appears in
(or is statically derived, by the two spec-allowed PowerShell forms, from) the bytes it was given.
"""
import io
import json
import struct
import tarfile
import uuid

import pytest

import evidence_ledger as el
import evidence_core as ec
import archive_passwords as ap


TICKS = 132262245061234567
CLSID = uuid.UUID("00021401-0000-0000-c000-000000000046").bytes_le
GUID = "550e8400-e29b-41d4-a716-446655440000"


# ---------------------------------------------------------------- synthetic byte fixtures

def _lnk(args, machine_id=b"LABHOST"):
    header = bytearray(76)
    struct.pack_into("<I", header, 0, 76)
    header[4:20] = CLSID
    struct.pack_into("<IIQQQIiI", header, 20, 0xBC, 0x20, TICKS, TICKS + 1, TICKS + 2, 1, 0, 3)
    body = bytearray(header)
    for text in ["Desc", r".\a.exe", r"C:\w", args]:
        raw = text.encode("utf-16-le")
        body.extend(struct.pack("<H", len(raw) // 2) + raw)
    block = bytearray(96)
    struct.pack_into("<IIII", block, 0, 96, 0xA0000003, 0x58, 0)
    block[16:16 + len(machine_id)] = machine_id
    body.extend(block)
    return bytes(body) + b"\0" * 4


def _hive(values):
    """A regf hive whose root key ROOT holds the given REG_SZ values."""
    hbin = 0x1000
    data = bytearray(0x8000)
    data[:4] = b"regf"
    struct.pack_into("<IIQIIIIIII", data, 4, 1, 1, TICKS, 1, 5, 0, 1, 0x20, 0x7000, 1)
    data[0x30:0x30 + 12] = "SYSTEM".encode("utf-16-le")
    data[hbin:hbin + 4] = b"hbin"
    struct.pack_into("<II", data, hbin + 4, 0, 0x7000)
    cur = 0x20

    def alloc(size):
        nonlocal cur
        size = (size + 7) & ~7
        off = cur
        struct.pack_into("<i", data, hbin + off, -size)
        cur += size
        return off

    vk_offs = []
    for name, value in values.items():
        s = value.encode("utf-16-le") + b"\x00\x00"
        doff = alloc(4 + len(s))
        data[hbin + doff + 4:hbin + doff + 4 + len(s)] = s
        vk = alloc(4 + 0x14 + len(name))
        data[hbin + vk + 4:hbin + vk + 6] = b"vk"
        struct.pack_into("<HIIIHH", data, hbin + vk + 6, len(name), len(s), doff, 1, 1, 0)
        data[hbin + vk + 4 + 0x14:hbin + vk + 4 + 0x14 + len(name)] = name.encode("latin-1")
        vk_offs.append(vk)
    vl = alloc(4 + 4 * len(vk_offs))
    for i, vo in enumerate(vk_offs):
        struct.pack_into("<I", data, hbin + vl + 4 + 4 * i, vo)
    nk = alloc(4 + 0x50)
    data[hbin + nk + 4:hbin + nk + 6] = b"nk"
    struct.pack_into("<HQ", data, hbin + nk + 6, 0x24, TICKS)
    struct.pack_into("<I", data, hbin + nk + 4 + 0x10, 0xFFFFFFFF)
    struct.pack_into("<II", data, hbin + nk + 4 + 0x24, len(vk_offs), vl)
    struct.pack_into("<HH", data, hbin + nk + 4 + 0x48, 4, 0)
    data[hbin + nk + 4 + 0x4C:hbin + nk + 4 + 0x50] = b"ROOT"
    struct.pack_into("<I", data, 0x24, nk)
    return bytes(data)


def _ip4(src, dst, payload, proto=6):
    a = bytes(int(x) for x in src.split("."))
    b = bytes(int(x) for x in dst.split("."))
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, a, b) + payload


def _tcp(sport, dport, seq, ack, flags, data=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + data


def _eth(payload):
    return bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + b"\x08\x00" + payload


def _pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1_790_000_000 + i, 0, len(f), len(f)) + f
    return out


def _ftp_pcap(password, user="bob"):
    c, s, cp, sp = "10.0.0.2", "10.0.0.1", 40000, 21
    frames = []

    def c2s(seq, ack, flags, data=b""):
        frames.append(_eth(_ip4(c, s, _tcp(cp, sp, seq, ack, flags, data))))

    def s2c(seq, ack, flags, data=b""):
        frames.append(_eth(_ip4(s, c, _tcp(sp, cp, seq, ack, flags, data))))

    c2s(1000, 0, 0x02)
    s2c(5000, 1001, 0x12)
    c2s(1001, 5001, 0x10)
    s2c(5001, 1001, 0x18, b"220 ready\r\n")
    user_cmd = f"USER {user}\r\n".encode()
    c2s(1001, 5012, 0x18, user_cmd)
    s2c(5012, 1001 + len(user_cmd), 0x18, b"331 need pass\r\n")
    pass_cmd = f"PASS {password}\r\n".encode()
    c2s(1001 + len(user_cmd), 5027, 0x18, pass_cmd)
    s2c(5027, 1001 + len(user_cmd) + len(pass_cmd), 0x18, b"230 ok\r\n")
    return _pcap(frames)


def _pax_tar(keyword, value, member="secret.txt"):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:", format=tarfile.PAX_FORMAT) as tf:
        ti = tarfile.TarInfo(member)
        body = b"x"
        ti.size = len(body)
        ti.pax_headers[keyword] = value
        tf.addfile(ti, io.BytesIO(body))
    return bio.getvalue()


# ---------------------------------------------------------------- evidence_core: the guid kind

def test_guid_is_scanned_from_raw_bytes():
    ix = ec.ioc({"n.txt": f"token {GUID} end".encode()})
    assert GUID in ix.values("guid")


def test_guid_join_is_case_insensitive_and_brace_stripped():
    ix = ec.ioc({"a.txt": ("ref " + GUID.upper()).encode(),
                 "b.txt": ("use {" + GUID + "}").encode()})
    pivots = ix.cross(kinds=("guid",))
    assert len(pivots) == 1
    kind, value, members = pivots[0]
    assert (kind, value) == ("guid", GUID)              # lowercased, braces stripped: one indicator
    assert set(members) == {"a.txt", "b.txt"}


def test_guid_regex_does_not_split_a_sha_run():
    sha = "a" * 64
    ix = ec.ioc({"h.txt": sha.encode()})
    assert ix.values("guid") == {}                      # a 64-hex run is a hash, never a GUID


# ---------------------------------------------------------------- the readers

def test_lnk_reader_surfaces_guid_and_argument_password():
    data = _lnk(f"-pLnk_Secret_9 run {{{GUID}}}")
    found = el.lnk_indicators(data)
    assert ("password", "Lnk_Secret_9", "lnk") in found
    assert any(k == "guid" and v.strip("{}").lower() == GUID for k, v, _ in found)


def test_hive_reader_surfaces_machineguid_and_password_value():
    data = _hive({"MachineGuid": GUID, "DefaultPassword": "Hive_Secret_1"})
    found = el.hive_indicators(data)
    assert ("guid", GUID, "hive") in found
    assert ("password", "Hive_Secret_1", "hive") in found


def test_history_reader_extracts_tool_passwords():
    hist = (b"#1700000000\n7z x -pSuperSecret_7z data.7z\n"
            b"unzip -P hunter2zip a.zip\n"
            b"curl -u admin:Curl_Pass1 http://x\nls -la\n")
    pws = {v for k, v, _ in el.history_indicators(hist) if k == "password"}
    assert pws == {"SuperSecret_7z", "hunter2zip", "Curl_Pass1"}


def test_history_reader_does_not_invent_a_password_from_a_plain_line():
    assert el.history_indicators(b"ls -la\ncd /tmp\necho hi\n") == []


def test_pcap_reader_extracts_cleartext_ftp_password():
    data = _ftp_pcap("Ftp_Secret_1")
    assert el.pcap_indicators(data) == [("password", "Ftp_Secret_1", "pcap")]


def test_pax_reader_surfaces_xattr_value():
    tar = _pax_tar("SCHILY.xattr.user.note", "PaxSecret_99")
    found = el.pax_indicators(tar)
    assert ("PaxSecret_99" in [v for _, v, _ in found])


def test_pax_reader_ignores_standard_keywords():
    # mtime / path only restate tar fields; a pax reader must not offer them as secrets.
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:", format=tarfile.PAX_FORMAT) as tf:
        ti = tarfile.TarInfo("f.txt")
        ti.size = 1
        ti.mtime = 1700000000
        tf.addfile(ti, io.BytesIO(b"x"))
    assert el.pax_indicators(bio.getvalue()) == []


# ---------------------------------------------------------------- PowerShell: static recipes only

def test_powershell_base64_literal_becomes_a_candidate():
    script = b'$b = [Convert]::FromBase64String("UGxhaW5QYXNzMTIz")\n'
    found = el.powershell_indicators(script)
    assert ("password", "PlainPass123", "powershell>base64") in found


def test_powershell_hmac_over_machineguid_is_derived_statically():
    import hmac
    import hashlib
    script = ('$h = New-Object System.Security.Cryptography.HMACSHA256\n'
              '$salt = "FixedSalt"\n').encode()
    found = el.powershell_indicators(script, machine_guids=[GUID])
    expected = hmac.new(GUID.encode(), b"FixedSalt", hashlib.sha256).digest().hex()
    assert any(k == "key" and v == expected for k, v, _ in found)


def test_powershell_without_a_recipe_derives_nothing():
    assert el.powershell_indicators(b'Write-Host "hello world"\n') == []


# ---------------------------------------------------------------- the join + candidates

def test_cross_file_join_of_a_guid_in_a_hive_and_a_lnk():
    files = {
        "SYSTEM": _hive({"MachineGuid": GUID}),
        "shortcut.lnk": _lnk(f"run {{{GUID}}}"),
    }
    index = el.collect(files)
    js = el.joins(index, kinds=("guid",))
    pivot = [p for p in js if p[1] == GUID]
    assert pivot, "the shared GUID must join across the hive and the lnk"
    assert len(pivot[0][2]) >= 2


def test_candidates_include_a_history_password_and_a_guid():
    files = {".bash_history": b"7z x -pFromHistory_1 a.7z\n", "SYSTEM": _hive({"MachineGuid": GUID})}
    cands = el.candidates(el.collect(files))
    assert "FromHistory_1" in cands
    assert GUID in cands
    assert "{" + GUID.upper() + "}" in cands           # the registry brace form is offered too


# ---------------------------------------------------------------- end-to-end into the harvest store

def _aes_zip(password, member="flag.txt", content=b"CSCTF{joined_password_opened_it}"):
    pyzipper = pytest.importorskip("pyzipper")
    bio = io.BytesIO()
    with pyzipper.AESZipFile(bio, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.writestr(member, content)
    return bio.getvalue()


@pytest.mark.needs_tool("py:pyzipper")
def test_feed_store_opens_an_encrypted_member_with_a_cross_file_password(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))     # isolate the archive-password store
    password = "CrossFile_Zip_Pw_7"
    files = {
        "vault.zip": _aes_zip(password),
        "notes.bash_history": f"unzip -P {password} vault.zip\n".encode(),
    }
    # Before the join the store has only its built-ins; the encrypted member is locked.
    report = el.feed_store(files, source="test")
    assert report["new"], "the harvested cross-file password must be new to the store"
    # The password is reported only masked, never in the clear.
    assert all(password not in m for m in report["new"])
    # And the archive-open store now opens the member with that harvested candidate.
    opened, locked = ap.read_all(files["vault.zip"])
    assert locked == []
    assert any(b"CSCTF{" in body for body in opened.values())


def test_feed_store_masks_every_value_it_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    files = {"SYSTEM": _hive({"MachineGuid": GUID}), "shortcut.lnk": _lnk(f"run {{{GUID}}}")}
    report = el.feed_store(files)
    for j in report["joins"]:
        assert j["value"].startswith("<") and j["value"].endswith(">")   # mask form, never the value


@pytest.mark.needs_tool("py:pyzipper")
def test_hmac_over_machineguid_derives_the_zip_password(tmp_path, monkeypatch):
    # csctf 9067 shape: the password is HMAC_SHA256(key=MachineGuid, msg=salt), written nowhere as a
    # literal. Only the static PowerShell derivation (never running pwsh) reaches it.
    import hmac
    import hashlib
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    password = hmac.new(GUID.encode(), b"FixedSalt", hashlib.sha256).digest().hex()
    files = {
        "vault.zip": _aes_zip(password, content=b"CSCTF{hmac_over_machineguid}"),
        "SYSTEM": _hive({"MachineGuid": GUID}),
        "derive.ps1": b'$h = New-Object System.Security.Cryptography.HMACSHA256\n$salt = "FixedSalt"\n',
    }
    el.feed_store(files)
    opened, locked = ap.read_all(files["vault.zip"])
    assert locked == []
    assert any(b"CSCTF{hmac_over_machineguid}" == body for body in opened.values())


@pytest.mark.needs_tool("py:pyzipper")
def test_sweep_harvest_step_uses_the_cross_file_join(tmp_path, monkeypatch):
    # The B-013 sweep's _harvest_into_store is the hook the ledger feeds: a password reachable only
    # by a cross-file join (an xattr here) must reach the store through it. The plain string harvest
    # would not read a pax extended header, so this isolates the B-068 wiring.
    from ctf import sweep
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    password = "Pax_Join_Pw_33"
    blobs = {
        "vault.zip": _aes_zip(password, content=b"CSCTF{pax_join}"),
        "archive.tar": _pax_tar("SCHILY.xattr.user.zippassword", password),
    }
    notes = []
    new = sweep._harvest_into_store(blobs, [], notes)
    assert password in new                         # the join value reached the store
    opened, locked = ap.read_all(blobs["vault.zip"])
    assert locked == [] and any(b"CSCTF{pax_join}" == body for body in opened.values())
