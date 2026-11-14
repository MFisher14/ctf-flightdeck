"""Synthetic fixtures for the B-070 tests: a git directory written byte by byte (no git program), small
valid images, and archives. Everything is built in memory; nothing here is a real challenge file.

    g = GitDir()
    c1 = g.commit({"README.md": b"hi\n"}, "first", when=1730000000)
    c2 = g.commit({"README.md": b"hi\n", "notes.c": b"..."}, "second", parents=[c1], when=1730000100)
    g.branch("main", c2)                      # refs/heads/main + HEAD + a reflog line
    files = g.files(prefix="repo/.git/")      # {path: bytes} to zip, to write to disk, or to hand a reader
"""
import hashlib
import io
import struct
import zipfile
import zlib

ZERO = "0" * 40


class GitDir:
    """A SHA-1 git directory with loose objects only."""

    def __init__(self, description=True):
        self.t = {"config": b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"}
        if description:
            self.t["description"] = b"Unnamed repository; edit this file 'description' to name the repository.\n"
        self.t["hooks/pre-commit.sample"] = b"#!/bin/sh\nexit 0\n"
        self.t["info/exclude"] = b"# git ls-files --others --exclude-from=.git/info/exclude\n"
        self.raw = {}                    # object id -> (type, body), in the order written

    def obj(self, typ: str, body: bytes) -> str:
        raw = f"{typ} {len(body)}".encode() + b"\x00" + body
        oid = hashlib.sha1(raw).hexdigest()
        self.t[f"objects/{oid[:2]}/{oid[2:]}"] = zlib.compress(raw)
        self.raw[oid] = (typ, body)
        return oid

    def pack(self) -> bytes:
        """Every object written so far as one version-2 packfile (whole objects, no deltas)."""
        out = b"PACK" + struct.pack(">II", 2, len(self.raw))
        for typ, body in self.raw.values():
            size, first = len(body), {"commit": 1, "tree": 2, "blob": 3, "tag": 4}[typ] << 4 | (len(body) & 0x0F)
            size >>= 4
            head = bytearray([first | (0x80 if size else 0)])
            while size:
                head.append((size & 0x7F) | (0x80 if size >> 7 else 0))
                size >>= 7
            out += bytes(head) + zlib.compress(body)
        return out + hashlib.sha1(out).digest()

    def index(self, staged: dict):
        """Write a version-2 index holding {path: bytes} (each content also written as a blob)."""
        body = b"DIRC" + struct.pack(">II", 2, len(staged))
        for path, data in sorted(staged.items()):
            name = path.encode()
            entry = struct.pack(">10I", 0, 0, 0, 0, 0, 0, 0o100644, 0, 0, len(data))
            entry += bytes.fromhex(self.blob(data)) + struct.pack(">H", len(name) & 0xFFF) + name
            body += entry + b"\x00" * (8 - len(entry) % 8)
        self.t["index"] = body + hashlib.sha1(body).digest()

    def blob(self, data: bytes) -> str:
        return self.obj("blob", data)

    def tree(self, files: dict) -> str:
        """The tree object of {path: bytes}; folders become sub-trees."""
        here, sub = {}, {}
        for path, data in files.items():
            head, sep, rest = path.partition("/")
            if sep:
                sub.setdefault(head, {})[rest] = data
            else:
                here[head] = data
        entries = [(name, b"100644", self.blob(data)) for name, data in here.items()]
        entries += [(name, b"40000", self.tree(inner)) for name, inner in sub.items()]
        body = b"".join(mode + b" " + name.encode() + b"\x00" + bytes.fromhex(oid)
                        for name, mode, oid in sorted(entries))
        return self.obj("tree", body)

    def commit(self, files: dict, message: str, parents=(), when=1730000000, who="Ada <ada@example.test>") -> str:
        lines = [f"tree {self.tree(files)}"] + [f"parent {p}" for p in parents]
        lines += [f"author {who} {when} +0000", f"committer {who} {when} +0000", "", message]
        return self.obj("commit", ("\n".join(lines) + "\n").encode())

    def log(self, ref: str, old: str, new: str, message: str, when=1730000000):
        line = f"{old} {new} Ada <ada@example.test> {when} +0000\t{message}\n".encode()
        self.t[f"logs/{ref}"] = self.t.get(f"logs/{ref}", b"") + line

    def branch(self, name: str, tip: str, old: str = ZERO, message: str = "commit: tip"):
        self.t[f"refs/heads/{name}"] = tip.encode() + b"\n"
        self.t["HEAD"] = f"ref: refs/heads/{name}\n".encode()
        self.log("HEAD", old, tip, message)
        self.log(f"refs/heads/{name}", old, tip, message)

    def files(self, prefix: str = ".git/") -> dict:
        return {prefix + p: d for p, d in self.t.items()}


def write_tree(root, files: dict):
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def zip_bytes(entries: dict, compression=zipfile.ZIP_DEFLATED) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=compression) as z:
        for name, data in entries.items():
            z.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), data, compress_type=compression)
    return bio.getvalue()


def shift_zip(z: bytes, delta: int) -> bytes:
    """The zip with every offset in its directory moved by `delta`: the form `zip -A` leaves, where
    offsets count from the start of the file the zip was appended to, not from the zip's own start."""
    eocd = z.rfind(b"PK\x05\x06")
    count, _size, start = struct.unpack_from("<HII", z, eocd + 10)
    out, pos = bytearray(z), start
    for _ in range(count):
        assert z[pos:pos + 4] == b"PK\x01\x02"
        name, extra, comment = struct.unpack_from("<HHH", z, pos + 28)
        struct.pack_into("<I", out, pos + 42, struct.unpack_from("<I", z, pos + 42)[0] + delta)
        pos += 46 + name + extra + comment
    struct.pack_into("<I", out, eocd + 16, start + delta)
    return bytes(out)


def pulled(tmp_path, files: dict, description="", cid=9074, category="Forensics"):
    """A pulled challenge folder (challenge.json + files/) under tmp_path/wd; `files` is {relative path: bytes}."""
    import json
    ch = tmp_path / "wd" / f"{cid}-x"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps({"id": cid, "name": "x", "category": category,
                                                   "description": description}))
    write_tree(ch / "files", files)
    return ch


def _chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)


def png(width=2, height=2, text: dict = None, break_crc=False, private: bytes = None) -> bytes:
    """A valid grey PNG (IHDR, optional tEXt, optional private chunk `prVt`, IDAT, IEND); break_crc
    spoils the IDAT checksum."""
    raw = b"".join(b"\x00" + bytes(width) for _ in range(height))
    out = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
    for key, value in (text or {}).items():
        out += _chunk(b"tEXt", key.encode() + b"\x00" + value.encode())
    if private is not None:
        out += _chunk(b"prVt", private)
    idat = _chunk(b"IDAT", zlib.compress(raw))
    if break_crc:
        idat = idat[:-1] + bytes([idat[-1] ^ 0xFF])
    return out + idat + _chunk(b"IEND", b"")


def jpeg() -> bytes:
    """A structurally valid 1x1 baseline JPEG: SOI, SOF0, SOS, three bytes of scan data, EOI."""
    sof = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, 1, 1, 1) + b"\x01\x11\x00"
    sos = b"\xff\xda" + struct.pack(">HB", 8, 1) + b"\x01\x00\x00\x3f\x00"
    return b"\xff\xd8" + sof + sos + b"\x12\x34\x56" + b"\xff\xd9"


def bmp() -> bytes:
    """A valid 1x1 24-bit BMP (BITMAPINFOHEADER)."""
    dib = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, 4, 2835, 2835, 0, 0)
    return b"BM" + struct.pack("<IHHI", 14 + 40 + 4, 0, 0, 54) + dib + b"\x00\x00\xff\x00"


def webp() -> bytes:
    """A RIFF/WEBP container with one VP8 chunk (the chunk walk is valid; the bitstream is filler)."""
    chunk = b"VP8 " + struct.pack("<I", 10) + bytes(10)
    return b"RIFF" + struct.pack("<I", 4 + len(chunk)) + b"WEBP" + chunk


def gif() -> bytes:
    """A valid 1x1 GIF89a."""
    return (b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0x80, 0, 0) + b"\x00\x00\x00\xff\xff\xff"
            + b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0) + b"\x02\x02\x44\x01\x00" + b"\x3b")
