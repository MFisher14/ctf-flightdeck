"""Day 15 ooxml.external_relationship_targets for the Metadata speed solver: the Target of every Relationship
with TargetMode="External" in every .rels part, XML-unescaped, as a compact JSON array sorted ascending (the
judged order, conventions +order -> sorted). A duplicate target fails closed (None), as the shipped reader.

Merged (B-001 hm-11) against CSCTF readers_formats._ext_targets/external (the judged reader): only an OOXML
package ([Content_Types].xml present) is read; a .rels part that is not UTF-8 or a Target holding markup fails
closed (None) instead of being read with replacement characters; the JSON keeps non-ASCII text as written
(properties_strict._json, ensure_ascii=False). Kept from Huntress: the lean zip reader and the single sorted form.
"""
from __future__ import annotations

import html
import json
import re
import struct
import zipfile
import zlib

try:
    from .metadata_zip import open_zip
except ImportError:  # loaded without the package
    from metadata_zip import open_zip

_REL = re.compile(r"<Relationship\b[^>]*>")
_TGT = re.compile(r'\bTarget="([^"]*)"')


def external_targets(name, d):
    if d[:4] != b"PK\x03\x04":
        return None
    try:
        z = open_zip(d)
        names = z.namelist()
        if "[Content_Types].xml" not in names:
            return None
        out = []
        for nm in names:
            if not nm.endswith(".rels"):
                continue
            body = z.read(nm).decode("utf-8")
            for m in _REL.finditer(body):
                tag = m.group(0)
                if 'TargetMode="External"' in tag:
                    t = _TGT.search(tag)
                    if t:
                        if "<" in t.group(1):
                            return None
                        out.append(html.unescape(t.group(1)))
    except (zipfile.BadZipFile, zlib.error, struct.error, UnicodeDecodeError, KeyError, OSError, NotImplementedError, RuntimeError):
        return None
    if not out or len(set(out)) != len(out):
        return None
    return json.dumps(sorted(out), separators=(",", ":"), ensure_ascii=False)


PROPS = {"ooxml-external-relationship-targets": external_targets}
