"""Synthetic tests for the local, static libc-db matcher in pwn_exploit.py."""
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import pwn_exploit as X  # noqa: E402


def _strtab(names):
    blob, offsets = b"\0", {}
    for name in names:
        offsets[name] = len(blob)
        blob += name.encode() + b"\0"
    return blob, offsets


def build_libc(symbols, build_id: bytes):
    """Minimal valid ELF64 ET_DYN with defined .dynsym functions and a GNU build-id note."""
    dynstr, names = _strtab(list(symbols))
    dynsym = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    for name, value in symbols.items():
        dynsym += struct.pack("<IBBHQQ", names[name], (1 << 4) | 2, 0, 1, value, 0)
    note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" + build_id
    note += b"\0" * ((-len(note)) & 3)

    sections = [
        ("", 0, 0, 0, 0, 0, b""),
        (".text", 1, 0x6, 0x1000, 0, 16, b"\x90" * 16),
        (".dynsym", 11, 0x2, 0x2000, 3, 24, dynsym),
        (".dynstr", 3, 0x2, 0x3000, 0, 1, dynstr),
        (".note.gnu.build-id", 7, 0x2, 0x4000, 0, 4, note),
        (".shstrtab", 3, 0, 0, 0, 1, None),
    ]
    shstr, shnames = _strtab([row[0] for row in sections if row[0]])
    shnames[""] = 0
    sections[-1] = (".shstrtab", 3, 0, 0, 0, 1, shstr)
    offsets, blobs, cur = [], [], 64
    for _name, _typ, _flags, _addr, _link, align, data in sections:
        data = data or b""
        if data:
            align = max(1, align)
            pad = (-cur) % align
            if pad:
                blobs.append(b"\0" * pad)
                cur += pad
            offsets.append(cur)
            blobs.append(data)
            cur += len(data)
        else:
            offsets.append(0)
    shoff = (cur + 7) & ~7
    if shoff > cur:
        blobs.append(b"\0" * (shoff - cur))
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 3, 0x3E, 1, 0, 0, shoff, 0,
                               64, 0, 0, 64, len(sections), len(sections) - 1)
    headers = bytearray()
    for i, (name, typ, flags, addr, link, align, data) in enumerate(sections):
        info = 1 if typ == 11 else 0
        entsize = 24 if typ == 11 else 0
        headers += struct.pack("<IIQQQQIIQQ", shnames[name], typ, flags, addr, offsets[i],
                               len(data or b""), link, info, max(1, align), entsize)
    return ehdr + b"".join(blobs) + bytes(headers)


def library_set(tmp_path):
    one_id = bytes.fromhex("11" * 20)
    two_id = bytes.fromhex("22" * 20)
    one = tmp_path / "libc-one.so.6"
    two = tmp_path / "libc-two.so.6"
    one.write_bytes(build_libc({"puts": 0x1000, "read": 0x2000, "system": 0x3000,
                                "execve": 0x4000}, one_id))
    two.write_bytes(build_libc({"puts": 0x1100, "read": 0x2600, "system": 0x3900,
                                "execve": 0x4800}, two_id))
    return one, two, one_id.hex(), two_id.hex()


def test_index_and_multi_leak_signature(tmp_path):
    one, two, one_id, two_id = library_set(tmp_path)
    indexed = X.index_libcs(tmp_path, names=("puts", "read", "system", "execve"))
    assert [Path(row["path"]).name for row in indexed] == [one.name, two.name]
    assert indexed[0]["build_id"] == one_id
    assert indexed[1]["build_id"] == two_id
    assert indexed[0]["offsets"]["system"] == 0x3000

    base = 0x7F1200000000
    ranked = X.identify_libc({"puts": base + 0x1000, "read": base + 0x2000}, tmp_path)
    assert Path(ranked[0]["path"]).name == one.name
    assert ranked[0]["exact"] is True
    assert ranked[0]["base"] == base
    assert ranked[0]["resolved"]["system"] == base + 0x3000
    assert Path(ranked[1]["path"]).name == two.name
    assert ranked[1]["exact"] is False
    assert ranked[1]["mismatches"]


def test_build_id_lookup_and_single_leak_page_ranking(tmp_path):
    one, two, one_id, two_id = library_set(tmp_path)
    by_id = X.identify_libc(two_id, tmp_path)
    assert len(by_id) == 1
    assert Path(by_id[0]["path"]).name == two.name
    assert by_id[0]["base"] is None
    assert by_id[0]["offsets"]["execve"] == 0x4800

    base = 0x7F5500000000
    by_one_leak = X.identify_libc({"puts": base + 0x1000}, tmp_path)
    assert Path(by_one_leak[0]["path"]).name == one.name
    assert by_one_leak[0]["page_aligned"] is True


def test_cli_identify_json_and_guarded_error(tmp_path, capsys):
    _one, _two, _one_id, _two_id = library_set(tmp_path)
    base = 0x7F7700000000
    rc = X.main(["--identify", f"puts={base + 0x1000:#x},read={base + 0x2000:#x}",
                 "--libc-dir", str(tmp_path), "--json"])
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result[0]["base"] == hex(base)
    assert result[0]["resolved"]["system"] == hex(base + 0x3000)

    assert X.main(["--identify", "not-a-leak", "--libc-dir", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("pwn_exploit.py:")
    assert "Traceback" not in err


def test_matcher_rejects_untrusted_shapes():
    try:
        X.match_libc_index({"bad name": 1}, [])
    except ValueError as exc:
        assert "invalid leak symbol" in str(exc)
    else:
        raise AssertionError("invalid symbol accepted")
