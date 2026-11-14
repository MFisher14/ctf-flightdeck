"""What a dropped file is, and what is wrong with a challenge's drop (B-209).

Reads only the first bytes of each file (a 1 GB memory image costs one 512-byte read) and never
executes or decompresses anything. Two layers:

    classify(path)            -> Kind(kind, role, detail)       one file
    file_problems(path, kind) -> [Problem]                       one file: empty, HTML saved as a
                                                                 binary, extension vs content
    challenge_problems(files, description) -> [Problem]          the set: a helper with no capture,
                                                                 a described capture that is absent

role is "capture" (the evidence itself: memory image, packet capture, disk image, event log),
"helper" (something that only makes sense next to a capture: Volatility symbol tables, a TLS key
log), or "file" (everything else). The Spooky case this exists for: a challenge whose drop held
symbols.json.xz (the Volatility helper) but not the 1 GB .lime capture it describes.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

HEAD = 512

# Partial downloads: browsers write these while a download is running. Never filed.
PARTIAL_SUFFIXES = (".crdownload", ".part", ".partial", ".download", ".opdownload", ".tmp")


@dataclass(frozen=True)
class Kind:
    kind: str      # memory, pcap, disk, evtx, symbols, keylog, html, archive, pdf, image, elf, pe,
                   # macho, text, empty, data
    role: str      # capture | helper | file
    detail: str    # one line for the human


@dataclass(frozen=True)
class Problem:
    code: str      # empty_file | disguised_html | extension_mismatch | helper_without_capture |
                   # capture_missing
    file: str      # the file it is about ("" for a challenge-level problem)
    message: str   # what the human should do

    @property
    def key(self) -> str:
        return f"{self.code}:{self.file}" if self.file else self.code


CAPTURE_LABEL = {"memory": "memory image", "pcap": "packet capture", "disk": "disk image",
                 "evtx": "Windows event log"}

_ROLE = {"memory": "capture", "pcap": "capture", "disk": "capture", "evtx": "capture",
         "symbols": "helper", "keylog": "helper"}

# helper kind -> the capture kind it is a helper for
HELPER_FOR = {"symbols": "memory", "keylog": "pcap"}

_ARCHIVE_MAGIC = (
    (b"PK\x03\x04", "zip archive"), (b"PK\x05\x06", "zip archive (empty)"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"), (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "gzip data"), (b"\xfd7zXZ\x00", "xz data"), (b"BZh", "bzip2 data"),
    (b"\x28\xb5\x2f\xfd", "zstd data"),
)
_PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
_DISK_MAGIC = (
    (b"EVF\x09\x0d\x0a\xff\x00", "EnCase E01 image"), (b"EVF2\x0d\x0a\x81\x00", "EnCase Ex01 image"),
    (b"KDMV", "VMDK sparse disk"), (b"# Disk DescriptorFile", "VMDK descriptor"),
    (b"vhdxfile", "VHDX disk"), (b"QFI\xfb", "QCOW disk"), (b"conectix", "VHD disk"),
    (b"ADSEGMENTEDFILE", "AccessData AD1 image"),
)
_MEMORY_MAGIC = (
    (b"EMiL", "LiME memory image"), (b"PAGEDU64", "Windows 64-bit crash dump"),
    (b"PAGEDUMP", "Windows crash dump"), (b"HIBR", "Windows hibernation file"),
    (b"hibr", "Windows hibernation file"), (b"MDMP", "Windows minidump"),
)

# Extensions that name a capture by convention but carry no magic of their own (raw memory/disk).
_NAME_ONLY = {".mem": "memory", ".vmem": "memory", ".raw": "memory", ".dmp": "memory",
              ".lime": "memory", ".dd": "disk", ".img": "disk", ".001": "disk"}

# Extension -> the kinds its content may be. A file whose content is another known kind is flagged.
_EXPECT = {
    ".pcap": {"pcap"}, ".pcapng": {"pcap"}, ".cap": {"pcap"},
    ".zip": {"archive"}, ".7z": {"archive"}, ".rar": {"archive"}, ".gz": {"archive"},
    ".tgz": {"archive"}, ".xz": {"archive", "symbols"}, ".bz2": {"archive"}, ".zst": {"archive"},
    ".jar": {"archive"}, ".apk": {"archive"}, ".docx": {"archive"}, ".xlsx": {"archive"},
    ".pptx": {"archive"},
    ".pdf": {"pdf"}, ".png": {"image"}, ".jpg": {"image"}, ".jpeg": {"image"}, ".gif": {"image"},
    ".lime": {"memory"}, ".e01": {"disk"}, ".vmdk": {"disk"}, ".vhdx": {"disk"}, ".qcow2": {"disk"},
    ".ad1": {"disk"}, ".evtx": {"evtx"}, ".exe": {"pe"}, ".dll": {"pe"}, ".sys": {"pe"},
}
# Content kinds weak enough that an extension disagreeing with them proves nothing.
_WEAK = {"data", "text"}
_HTML_OK = {".html", ".htm", ".xhtml", ".txt", ".md", ".xml", ".svg", ".php", ".js", ".eml", ".mhtml"}

_SYMBOLS_NAME = re.compile(r"(symbol|\bisf\b|banners?\b).*\.json(\.(xz|gz|bz2|zip))?$|\.isf$", re.I)
_KEYLOG_TEXT = (b"CLIENT_RANDOM ", b"CLIENT_HANDSHAKE_TRAFFIC_SECRET ", b"# SSL/TLS secrets log",
                b"SERVER_HANDSHAKE_TRAFFIC_SECRET ", b"RSA Session-ID:")

# Description words that promise a capture of a kind.
_DESC = {
    "memory": re.compile(r"memory (dump|image|capture|snapshot)|ram (dump|capture|image)|\bmem ?dump"
                         r"|volatility|\blime\b|\.vmem\b|\.lime\b", re.I),
    "pcap": re.compile(r"\bpcap(ng)?\b|packet capture|network capture|traffic capture|wireshark", re.I),
    "disk": re.compile(r"disk image|forensic image|\be01\b|\.vmdk\b|\.dd\b|drive image", re.I),
}


def is_partial(name: str) -> bool:
    low = name.lower()
    return low.endswith(PARTIAL_SUFFIXES) or low.startswith((".~lock", "~$"))


def _ext(name: str) -> str:
    return Path(name).suffix.lower()


def _head(path: Path) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(HEAD)


def _kind(name: str, head: bytes, size: int) -> tuple[str, str]:
    if size == 0:
        return "empty", "empty file (0 bytes)"
    for magic, what in _MEMORY_MAGIC:
        if head.startswith(magic):
            return "memory", what
    if head.startswith(_PCAP_MAGIC):
        return "pcap", "pcap packet capture"
    if head.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcap", "pcapng packet capture"
    for magic, what in _DISK_MAGIC:
        if head.startswith(magic):
            return "disk", what
    if head.startswith(b"ElfFile\x00"):
        return "evtx", "Windows event log"
    if _SYMBOLS_NAME.search(name):
        return "symbols", "Volatility symbol table (a helper for a memory image, not the image)"
    if head.startswith(b"\x7fELF"):
        if len(head) >= 18:
            etype = int.from_bytes(head[16:18], "big" if head[5] == 2 else "little")
            if etype == 4:            # ET_CORE: a process or VM core (memory)
                return "memory", "ELF core dump"
        return "elf", "ELF executable"
    if head.startswith(b"MZ"):
        return "pe", "PE executable"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho", "Mach-O executable"
    for magic, what in _ARCHIVE_MAGIC:
        if head.startswith(magic):
            return "archive", what
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "archive", "tar archive"
    if head.startswith(b"%PDF"):
        return "pdf", "PDF document"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")):
        return "image", "image"
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if stripped.startswith((b"<!doctype html", b"<html", b"<head", b"<!-- saved from")):
        return "html", "HTML page"
    if any(head.startswith(m) for m in _KEYLOG_TEXT):
        return "keylog", "TLS key log (a helper for a packet capture, not the capture)"
    ext = _ext(name)
    if ext in _NAME_ONLY:
        k = _NAME_ONLY[ext]
        return k, f"{CAPTURE_LABEL[k]} by its extension ({ext}; raw images carry no magic)"
    sample = head[:HEAD]
    if sample and all(b in b"\t\r\n" or 32 <= b < 127 or b >= 128 for b in sample):
        try:
            sample.decode("utf-8")
            return "text", "text"
        except UnicodeDecodeError:
            pass
    return "data", "unrecognised binary data"


def classify(path: Path) -> Kind:
    p = Path(path)
    size = p.stat().st_size
    kind, detail = _kind(p.name, _head(p) if size else b"", size)
    return Kind(kind, _ROLE.get(kind, "file"), detail)


def file_problems(rel: str, kind: Kind) -> list[Problem]:
    """Problems with one file on its own. `rel` is its name inside the challenge's files/."""
    name = Path(rel).name
    ext = _ext(name)
    if kind.kind == "empty":
        return [Problem("empty_file", rel, f"{rel} is empty (0 bytes): download it again")]
    if kind.kind == "html" and ext not in _HTML_OK:
        return [Problem("disguised_html", rel,
                        f"{rel} is an HTML page, not a {ext or 'binary'} file: the download saved a "
                        "web page (a sign-in, virus-scan or redirect page?); download the real file")]
    want = _EXPECT.get(ext)
    if want and kind.kind not in want and kind.kind not in _WEAK:
        return [Problem("extension_mismatch", rel,
                        f"{rel} is named {ext} but its content is {kind.detail}: check it is the "
                        "right file")]
    return []


def challenge_problems(files: dict[str, Kind], description: str = "") -> list[Problem]:
    """Problems with the drop as a whole: a helper whose capture is absent, or a capture the
    description promises that no file is. `files` maps rel name -> Kind. An empty drop has no
    problems here (the checklist already asks for its files)."""
    if not files:
        return []
    have = {k.kind for k in files.values()}
    out: list[Problem] = []
    for rel, k in sorted(files.items()):
        cap = HELPER_FOR.get(k.kind)
        if cap and cap not in have:
            out.append(Problem("helper_without_capture", rel,
                               f"{rel} is a {k.detail.split(' (')[0]}, a helper; the "
                               f"{CAPTURE_LABEL[cap]} it goes with is not here: download the "
                               f"{CAPTURE_LABEL[cap]} itself"))
    helped = {HELPER_FOR[k.kind] for k in files.values() if k.kind in HELPER_FOR}
    for cap, rx in _DESC.items():
        if cap in have or cap in helped or not rx.search(description or ""):
            continue
        # An archive may hold the capture; say so instead of asserting it is missing.
        hedge = (" (an archive here may hold it: unpack and check)"
                 if "archive" in have else "")
        out.append(Problem("capture_missing", "",
                           f"the description mentions a {CAPTURE_LABEL[cap]} but no file is one"
                           f"{hedge}: download the {CAPTURE_LABEL[cap]}"))
    return out


def matches(pattern: str, name: str) -> bool:
    """Case-insensitive glob on a file's base name (used for a need's --expect)."""
    return fnmatch.fnmatch(Path(name).name.lower(), pattern.lower())
