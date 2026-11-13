#!/usr/bin/env python3
"""Schema-bundle semantic decoders: field-level ISO 15118 / DIN 70121 EXI, ASN.1 (UPER/BER) and VMF-style bit-dictionary output from schemas the operator supplies.

The sector engines stop where a licensed schema starts: sec_evcharge_v2g reports the EXI header and
keeps the body opaque, sec_v2x_etsi lists the Release-2 header and keeps the body opaque,
sec_tdl_link22 reads the VMF header prefix only. This engine decodes those bodies against the real
schema, loaded from a folder outside the repo (the `schema-bundle` asset of tools/assets.toml:
$CTF_ASSET_SCHEMAS, else <toolbox>/schemas). Nothing is vendored: docs/toolkits/schema_bundle.md
records, per schema, where it comes from and whether it may be redistributed.

    <bundle>/iso15118-2/   V2G_CI_AppProtocol.xsd V2G_CI_MsgDef.xsd (+ the files they import)
    <bundle>/din70121/     V2G_CI_AppProtocol.xsd V2G_CI_MsgDef.xsd (+ imports)
    <bundle>/iso15118-20/  V2G_CI_AppProtocol.xsd V2G_CI_CommonMessages.xsd V2G_CI_AC.xsd ...
    <bundle>/etsi-its-r2/  *.asn  (CAM-PDU-Descriptions, DENM-PDU-Descriptions, ETSI-ITS-CDD)
    <bundle>/mms/          *.asn  (the ISO 9506-2 MMS module)
    <bundle>/vmf-k/        <message>.json dictionaries the operator transcribes (see _schema_bits)

A missing bundle, family folder, schema file or pycrate is a named failure (BundleMissing,
SchemaMissing, ToolMissing), and so is a schema that is there but cannot be loaded (SchemaUnusable);
there is no fallback decode. PROFINET IO has no machine-readable wire schema to load and stays with
ics_app_depth / network_ics_depth (family `pnio`, decoder "none").

Known limit, found against the real files on 2026-11-12: pycrate 0.8.1 does not compile the ETSI
Release 2 CDD module (family `etsi-its-r2`, decoder "blocked"), so real CAM/DENM Release 2 PDUs do
not decode yet; the ASN.1 path itself is tested on modules pycrate compiles.

CLI (run with tools/ctfpy or `python -m ctf run`):

  tools/ctfpy solvers/toolkits/schema_bundle.py status
  tools/ctfpy solvers/toolkits/schema_bundle.py exi frame.bin --family iso15118-2 [--document message]
  tools/ctfpy solvers/toolkits/schema_bundle.py exi body.exi --xsd my.xsd          # any XSD + EXI pair
  tools/ctfpy solvers/toolkits/schema_bundle.py asn1 cam.uper --family etsi-its-r2 --pdu cam
  tools/ctfpy solvers/toolkits/schema_bundle.py asn1 pdu.ber --asn a.asn b.asn --pdu Mod.Type --codec ber
  tools/ctfpy solvers/toolkits/schema_bundle.py bits body.bin --family vmf-k --message K05.1
  python -m ctf run toolkits.schema_bundle <challenge_dir> [--opt family=iso15118-2]

`--asn` compiles the ASN.1 text with pycrate and imports the generated Python: name only modules
you trust. The CLI refuses an --asn module that lies under the work folder or a challenge corpus
(it is challenge-supplied) and warns on every --asn run. `solve()` never compiles a challenge's own
files; it reads schemas from the bundle only.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Mapping, Sequence

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:                  # the helpers sit beside this file
    sys.path.insert(0, str(_HERE))
try:                                            # a bare script run needs the checkout root for `ctf`
    import ctf  # noqa: F401
except ModuleNotFoundError:
    sys.path.append(str(_HERE.parent.parent))

import _schema_bits as bits_codec  # noqa: E402
import _schema_exi as exi  # noqa: E402

ME = "toolkits.schema_bundle"
ASSET = "schema-bundle"
MAX_INPUT = 1 << 20
MAX_FILES = 200
MAX_ASN_BYTES = 8 << 20
MAX_NODES = 100_000
MAX_DEPTH = 64
V2GTP_EXI = 0x8001

__all__ = ["SchemaBundleError", "BundleMissing", "SchemaMissing", "SchemaUnusable", "ToolMissing", "DecodeFailed",
           "Family", "FAMILIES", "family", "bundle_root", "status", "exi_schema", "decode_exi",
           "decode_exi_xsd", "split_v2gtp", "decode_v2gtp", "compile_asn1", "decode_asn1",
           "decode_asn1_files", "decode_bits", "solve", "main"]


class SchemaBundleError(ValueError):
    """Base of every failure this engine raises."""


class BundleMissing(SchemaBundleError):
    """The schema bundle folder is not configured or not there."""


class SchemaMissing(SchemaBundleError):
    """A family's folder or one of its schema files is not in the bundle. `.family`, `.path`."""

    def __init__(self, fam: "Family", path: Path, why: str):
        self.family, self.path = fam.id, Path(path)
        super().__init__(f"schema family {fam.id!r}: {path} {why}. Obtain it from: {fam.source} "
                         f"(redistributable: {fam.redistributable}; see docs/toolkits/schema_bundle.md)")


class SchemaUnusable(SchemaBundleError):
    """A schema is there but cannot be loaded: an XSD construct outside the reader, or ASN.1 modules
    the compiler rejects."""


class ToolMissing(SchemaBundleError):
    """pycrate (the ASN.1 compiler and runtime) is not importable."""


class DecodeFailed(SchemaBundleError):
    """The input does not decode against the named schema."""


@dataclass(frozen=True)
class Family:
    id: str
    kind: str                        # exi | asn1 | bits | none
    title: str
    source: str                      # where a human obtains the schema
    licence: str
    obtainable: str                  # free | paid | restricted | none
    redistributable: str             # yes | no | unclear | n/a
    decoder: str                     # built | built-unverified | blocked | none
    documents: tuple[tuple[str, str], ...] = ()     # exi: (document name, root XSD file)
    pdus: tuple[tuple[str, str, str], ...] = ()     # asn1: (pdu name, type name, codec)
    note: str = ""

    @property
    def folder(self) -> str:
        return self.id


FAMILIES: tuple[Family, ...] = (
    Family("iso15118-2", "exi", "ISO 15118-2:2014 V2G messages (EXI)",
           source="the ISO 15118-2 electronic inserts on standards.iso.org (iso/15118/-2/ed-2/en/)",
           licence="ISO Customer Licence Agreement, accepted on download: use in the original format "
                   "for the standard's purposes; no redistribution grant",
           obtainable="free", redistributable="no", decoder="built",
           documents=(("app-protocol", "V2G_CI_AppProtocol.xsd"), ("message", "V2G_CI_MsgDef.xsd"))),
    Family("din70121", "exi", "DIN SPEC 70121:2014 V2G messages (EXI)",
           source="the schema files delivered with DIN SPEC 70121 (a purchased specification)",
           licence="DIN copyright; purchased, no redistribution",
           obtainable="paid", redistributable="no", decoder="built",
           documents=(("app-protocol", "V2G_CI_AppProtocol.xsd"), ("message", "V2G_CI_MsgDef.xsd"))),
    Family("iso15118-20", "exi", "ISO 15118-20:2022 V2G messages (EXI)",
           source="the ISO 15118-20 electronic inserts on standards.iso.org (iso/15118/-20/ed-1/en/)",
           licence="ISO Customer Licence Agreement, accepted on download: use in the original format "
                   "for the standard's purposes; no redistribution grant",
           obtainable="free", redistributable="no", decoder="built-unverified",
           documents=(("app-protocol", "V2G_CI_AppProtocol.xsd"), ("common", "V2G_CI_CommonMessages.xsd"),
                      ("ac", "V2G_CI_AC.xsd"), ("dc", "V2G_CI_DC.xsd"), ("wpt", "V2G_CI_WPT.xsd"),
                      ("acdp", "V2G_CI_ACDP.xsd")),
           note="no known-answer vector was available for -20; the EXI options profile is assumed to be "
                "the -2 one (bit-packed, schema-informed, strict=false)"),
    Family("etsi-its-r2", "asn1", "ETSI ITS Release 2 CAM (TS 103 900) and DENM (TS 103 831), UPER",
           source="the ETSI forge ITS ASN.1 repositories (forge.etsi.org/rep/ITS/asn1: cam_ts103900, "
                  "denm_ts103831 and the CDD module they import, branch release2)",
           licence="BSD 3-Clause, copyright ETSI (each repository's LICENSE)",
           obtainable="free", redistributable="yes", decoder="blocked",
           pdus=(("cam", "CAM", "uper"), ("denm", "DENM", "uper")),
           note="may be redistributed with the ETSI copyright notice and licence text kept. Blocked on the "
                "compiler, not the licence: pycrate 0.8.1 rejects the release2 CDD module ('BasicLaneInformation: "
                "invalid value reference for SEQUENCE, (WITH COMPONENTS ...)'; with those constraints removed, a "
                "TypeError in its constraint verification), so the real modules do not load; the decode path is "
                "built and tested on modules pycrate compiles"),
    Family("mms", "asn1", "ISO 9506-2 MMS PDUs (BER)",
           source="the ASN.1 module of ISO 9506-2 (a purchased standard); open-source transcriptions "
                  "exist inside GPL projects",
           licence="ISO copyright; transcriptions carry their project's licence",
           obtainable="paid", redistributable="no", decoder="built-unverified",
           pdus=(("mmspdu", "MMSpdu", "ber"),),
           note="never tried against the real module (none was available); ot_mms_services already "
                "decodes confirmed-service choices 0..77 without a schema"),
    Family("vmf-k", "bits", "VMF K-series message bodies (MIL-STD-6017)",
           source="MIL-STD-6017 from its controlling office; distribution is restricted, there is no "
                  "public copy",
           licence="US DoD limited distribution",
           obtainable="restricted", redistributable="no", decoder="built",
           note="the interpreter is built; each message table is a JSON dictionary the holder of the "
                "standard transcribes into <bundle>/vmf-k/"),
    Family("pnio", "none", "PROFINET IO (IEC 61158-6-10) block dictionary",
           source="IEC 61158-6-10 / the PI PROFINET specification (purchased, or PI membership)",
           licence="IEC / PI copyright",
           obtainable="paid", redistributable="no", decoder="none",
           note="there is no machine-readable wire schema to load (GSDML describes devices, not PDUs); "
                "decoding stays with ics_app_depth and network_ics_depth"),
)


def family(name: str) -> Family:
    for fam in FAMILIES:
        if fam.id == name:
            return fam
    raise SchemaBundleError(f"unknown schema family {name!r} (known: {', '.join(f.id for f in FAMILIES)})")


# --------------------------------------------------------------------------------------------------
# The bundle

def bundle_root(environ: Mapping[str, str] | None = None) -> Path:
    """The schema bundle folder: the `schema-bundle` asset of tools/assets.toml. BundleMissing names
    the variable, the folders tried and the fix; an override that names nothing is never skipped."""
    from ctf.toolchain import assets
    try:
        items = [a for a in assets.load() if a.name == ASSET]
    except assets.AssetsError as exc:
        raise BundleMissing(f"schema bundle: {exc}") from None
    if not items:
        raise BundleMissing(f"schema bundle: tools/assets.toml has no {ASSET!r} asset")
    state, = assets.resolve(items, environ=environ)
    if not state.ok:
        raise BundleMissing(f"schema bundle is {state.state}: {state.detail} (fix: {state.fix})")
    return Path(state.path)


def _family_dir(fam: Family, root: Path | None) -> Path:
    base = bundle_root() if root is None else Path(root)
    folder = base / fam.folder
    if not folder.is_dir():
        raise SchemaMissing(fam, folder, "is not in the bundle")
    return folder


def _asn_files(fam: Family, folder: Path) -> list[Path]:
    files = sorted(p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in (".asn", ".asn1"))
    if not files:
        raise SchemaMissing(fam, folder, "holds no .asn file")
    return files


def status(root: Path | None = None, environ: Mapping[str, str] | None = None) -> dict:
    """What the bundle holds, family by family. Never raises for a missing bundle: says so.

    {"bundle": path | None, "bundle_error": str | None, "families": [{"id", "kind", "title",
    "state": present | incomplete | missing | no-bundle | not-loadable, "detail", "files",
    "source", "licence", "obtainable", "redistributable", "decoder", "note"}]}"""
    error = None
    if root is None:
        try:
            root = bundle_root(environ)
        except BundleMissing as exc:
            error = str(exc)
    rows = []
    for fam in FAMILIES:
        row: dict[str, Any] = {"id": fam.id, "kind": fam.kind, "title": fam.title, "files": [], "detail": "",
                               "source": fam.source, "licence": fam.licence, "obtainable": fam.obtainable,
                               "redistributable": fam.redistributable, "decoder": fam.decoder, "note": fam.note}
        if fam.kind == "none":
            row["state"] = "not-loadable"
            row["detail"] = "no schema file exists for this family"
        elif root is None:
            row["state"] = "no-bundle"
        else:
            folder = Path(root) / fam.folder
            if not folder.is_dir():
                row["state"], row["detail"] = "missing", f"{folder} is not there"
            else:
                names = sorted(p.name for p in folder.iterdir() if p.is_file())
                if fam.kind == "exi":
                    need = [f for _d, f in fam.documents]
                    lost = [f for f in need if f not in names]
                    row["files"] = [n for n in names if n.lower().endswith(".xsd")]
                    row["state"] = "incomplete" if lost else "present"
                    row["detail"] = f"missing {', '.join(lost)}" if lost else ""
                elif fam.kind == "asn1":
                    row["files"] = [n for n in names if n.lower().endswith((".asn", ".asn1"))]
                    row["state"] = "present" if row["files"] else "incomplete"
                    row["detail"] = "" if row["files"] else "no .asn file"
                else:
                    row["files"] = [n for n in names if n.lower().endswith(".json")]
                    row["state"] = "present" if row["files"] else "incomplete"
                    row["detail"] = "" if row["files"] else "no <message>.json dictionary"
        rows.append(row)
    return {"bundle": str(root) if root is not None else None, "bundle_error": error, "families": rows}


# --------------------------------------------------------------------------------------------------
# EXI

_EXI_CACHE: dict[tuple, exi.Schema] = {}


def _load_xsd(paths: Sequence[Path]) -> exi.Schema:
    key = tuple((str(p.resolve()), p.stat().st_mtime_ns, p.stat().st_size) for p in paths if p.is_file())
    hit = _EXI_CACHE.get(key) if len(key) == len(paths) else None
    if hit is None:
        hit = exi.load_schema(paths)
        if len(key) == len(paths):
            _EXI_CACHE[key] = hit
    return hit


def exi_schema(fam: Family | str, document: str, root: Path | None = None) -> exi.Schema:
    """The loaded XSD of one document of an EXI family (cached per file identity)."""
    fam = family(fam) if isinstance(fam, str) else fam
    if fam.kind != "exi":
        raise SchemaBundleError(f"family {fam.id!r} is not an EXI family")
    files = dict(fam.documents)
    if document not in files:
        raise SchemaBundleError(f"family {fam.id!r} has no document {document!r} (known: {', '.join(files)})")
    path = _family_dir(fam, root) / files[document]
    if not path.is_file():
        raise SchemaMissing(fam, path, "is not in the bundle")
    try:
        return _load_xsd([path])
    except exi.ExiSchemaMissing as exc:
        raise SchemaMissing(fam, exc.path, f"is not in the bundle ({exc})") from None
    except exi.ExiSchemaError as exc:
        raise SchemaUnusable(f"schema family {fam.id!r}: {exc}") from None


def _exi_result(out: dict, label: str) -> dict:
    out = dict(out)
    out["schema"] = label
    out["fields"] = [{"path": p, "value": v} for p, v in exi.flatten(out["document"])]
    return out


def decode_exi(data: bytes, fam: Family | str, document: str | None = None, root: Path | None = None) -> dict:
    """Decode one EXI document against a bundle family.

    With `document` None every document of the family is tried and exactly one must decode (the EXI
    grammars reject each other's streams); none or several is a DecodeFailed naming each outcome.
    Returns the _schema_exi.decode result plus "family", "document", "schema" and "fields"."""
    fam = family(fam) if isinstance(fam, str) else fam
    if fam.kind != "exi":
        raise SchemaBundleError(f"family {fam.id!r} is not an EXI family")
    names = [document] if document else [d for d, _f in fam.documents]
    good, bad, lost = [], [], []
    for name in names:
        try:
            schema = exi_schema(fam, name, root)
        except SchemaMissing as exc:
            if document:
                raise
            lost.append(exc)
            continue
        try:
            out = _exi_result(exi.decode(_blob(data), schema), f"{fam.id}/{name}")
        except exi.ExiError as exc:
            bad.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        out["family"], out["document"], out["tree"] = fam.id, name, out["document"]
        good.append(out)
    if len(good) == 1:
        return good[0]
    if good:
        raise DecodeFailed(f"{fam.id}: the stream decodes under several documents "
                           f"({', '.join(g['document'] for g in good)}); name one")
    if lost and not bad:
        raise lost[0]
    gaps = "".join(f"; not tried: {e}" for e in lost)
    raise DecodeFailed(f"{fam.id}: the stream decodes under no document ({' | '.join(bad)}){gaps}")


def decode_exi_xsd(data: bytes, xsd: Sequence[Path | str]) -> dict:
    """Decode one EXI document against XSD files named by the caller (a challenge's own schema)."""
    paths = [Path(p) for p in xsd]
    try:
        schema = _load_xsd(paths)
        out = _exi_result(exi.decode(_blob(data), schema), ", ".join(p.name for p in paths))
    except exi.ExiSchemaError as exc:
        raise SchemaBundleError(str(exc)) from None
    except exi.ExiError as exc:
        raise DecodeFailed(f"{type(exc).__name__}: {exc}") from None
    out["tree"] = out.pop("document")
    return out


def _blob(data: Any) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise DecodeFailed("input must be bytes")
    data = bytes(data)
    if not data or len(data) > MAX_INPUT:
        raise DecodeFailed(f"input must hold 1..{MAX_INPUT} bytes")
    return data


def split_v2gtp(data: bytes) -> list[dict]:
    """The V2GTP frames `data` is made of, back to back: [{"offset", "payload_type", "payload"}].
    DecodeFailed unless the whole input is frames (version 0x01, inverse 0xFE, big-endian type and
    length).

    Not sec_evcharge_v2g.parse_v2gtp: that parses exactly one frame (it rejects concatenation) and
    refuses reserved payload types and -20 types under -2 context, while a capture here is several
    frames back to back whose boundaries come from each header's length, and a frame of a type this
    engine does not decode is kept and reported as skipped rather than failing the whole capture.
    A test checks that the two agree on every frame of a known type."""
    data = _blob(data)
    frames, at = [], 0
    while at < len(data):
        head = data[at:at + 8]
        if len(head) < 8 or head[0] != 0x01 or head[1] != 0xFE:
            raise DecodeFailed(f"no V2GTP header (01 FE) at offset {at}")
        length = int.from_bytes(head[4:8], "big")
        if at + 8 + length > len(data):
            raise DecodeFailed(f"the V2GTP frame at offset {at} declares {length} payload bytes; "
                               f"{len(data) - at - 8} remain")
        frames.append({"offset": at, "payload_type": int.from_bytes(head[2:4], "big"),
                       "payload": data[at + 8:at + 8 + length]})
        at += 8 + length
    return frames


def decode_v2gtp(data: bytes, fam: Family | str, document: str | None = None, root: Path | None = None) -> list[dict]:
    """Decode every EXI frame of a V2GTP byte string: [{"offset", "payload_type", "decoded" | "skipped"}]."""
    out = []
    for frame in split_v2gtp(data):
        row: dict[str, Any] = {"offset": frame["offset"], "payload_type": frame["payload_type"]}
        if frame["payload_type"] == V2GTP_EXI or 0x8002 <= frame["payload_type"] <= 0x8006:
            row["decoded"] = decode_exi(frame["payload"], fam, document, root)
        else:
            row["skipped"] = f"payload type {frame['payload_type']:#06x} is not an EXI message"
        out.append(row)
    return out


# --------------------------------------------------------------------------------------------------
# ASN.1 (pycrate compiles the bundle's modules at run time)

_ASN_CACHE: dict[str, Any] = {}
_ASN_LOCAL_LOCK = RLock()


def _pycrate():
    try:
        import pycrate_asn1c.asnproc as asnproc
        import pycrate_asn1c.generator as generator
        import pycrate_asn1rt.codecs as codecs
        from pycrate_core.charpy import Charpy
    except ImportError as exc:
        raise ToolMissing(f"ASN.1 decoding needs pycrate (pinned in requirements.in): {exc}") from None
    lock = getattr(codecs, "_csctf_v2x_codec_lock", None)     # the lock sec_v2x_etsi shares
    if lock is None:
        lock = RLock()
        setattr(codecs, "_csctf_v2x_codec_lock", lock)
    return asnproc, generator, codecs, Charpy, lock


def compile_asn1(files: Sequence[Path | str]) -> Any:
    """Compile ASN.1 module files with pycrate and import the generated module (cached per content).

    The generated Python is executed: pass only schema files you trust. ToolMissing without pycrate;
    SchemaBundleError when a file is missing, SchemaUnusable when the modules do not compile."""
    asnproc, generator, _codecs, _charpy, lock = _pycrate()
    texts, digest = [], hashlib.sha256()
    for path in [Path(f) for f in files]:
        if not path.is_file():
            raise SchemaBundleError(f"ASN.1 module file {path} is missing")
        raw = path.read_bytes()
        if len(raw) > MAX_ASN_BYTES:
            raise SchemaBundleError(f"ASN.1 module file {path} is larger than {MAX_ASN_BYTES} bytes")
        digest.update(len(raw).to_bytes(8, "big") + raw)
        texts.append(raw.decode("utf-8", "replace"))
    if not texts:
        raise SchemaBundleError("no ASN.1 module file given")
    key = digest.hexdigest()
    with _ASN_LOCAL_LOCK, lock:
        hit = _ASN_CACHE.get(key)
        if hit is not None:
            return hit
        with tempfile.TemporaryDirectory(prefix="ctf-schema-asn1-") as tmp:
            dest = Path(tmp) / f"schema_asn1_{key[:16]}.py"
            try:
                asnproc.GLOBAL.clear()
                asnproc.compile_text(texts)
                asnproc.generate_modules(generator.PycrateGenerator, str(dest))
            except BaseException as exc:
                if not isinstance(exc, (Exception, SystemExit)):
                    raise
                raise SchemaUnusable(
                    f"pycrate could not compile {', '.join(Path(f).name for f in files)}: "
                    f"{type(exc).__name__}: {str(exc)[:300]}") from None
            finally:
                asnproc.GLOBAL.clear()
            spec = importlib.util.spec_from_file_location(dest.stem, dest)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
            except Exception as exc:
                raise SchemaUnusable(f"the compiled ASN.1 modules do not import: "
                                        f"{type(exc).__name__}: {str(exc)[:300]}") from None
        if not _asn1_modules(module):               # pycrate compiles text that holds no module to nothing
            raise SchemaUnusable(f"no ASN.1 module found in {', '.join(Path(f).name for f in files)}")
        _ASN_CACHE[key] = module
        return module


def _asn1_modules(module: Any) -> dict[str, Any]:
    return {getattr(v, "_name_"): v for v in vars(module).values()
            if isinstance(v, type) and isinstance(getattr(v, "_name_", None), str) and hasattr(v, "_all_")}


def _find_pdu(module: Any, pdu: str) -> tuple[str, Any]:
    """`Type` or `Module.Type` -> (module name, the pycrate object). Ambiguity is an error."""
    mods = _asn1_modules(module)
    want_mod, _, want = pdu.rpartition(".")
    attr = want.replace("-", "_")
    hits = [(name, getattr(cls, attr)) for name, cls in sorted(mods.items())
            if (not want_mod or name == want_mod) and hasattr(getattr(cls, attr, None), "from_uper")]
    hits = [(n, o) for n, o in hits if getattr(o, "_name", None) == want]
    if not hits:
        raise SchemaBundleError(f"no ASN.1 type {pdu!r} in modules {', '.join(sorted(mods)) or '(none)'}")
    if len(hits) > 1:
        raise SchemaBundleError(f"ASN.1 type {want!r} is defined in several modules "
                                f"({', '.join(n for n, _o in hits)}); write Module.Type")
    return hits[0]


def _plain(value: Any, budget: list[int], depth: int = 0) -> Any:
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH:
        raise DecodeFailed("the decoded ASN.1 value exceeds the structural limits")
    if isinstance(value, (bytes, bytearray)):
        return {"hex": bytes(value).hex()}
    if isinstance(value, tuple):
        if len(value) == 2 and isinstance(value[0], str):
            return {value[0]: _plain(value[1], budget, depth + 1)}
        if len(value) == 2 and all(type(v) is int for v in value):
            return {"bits": format(value[0], f"0{value[1]}b") if value[1] else "", "bit_length": value[1]}
        return [_plain(v, budget, depth + 1) for v in value]
    if isinstance(value, list):
        return [_plain(v, budget, depth + 1) for v in value]
    if isinstance(value, dict):
        return {str(k): _plain(v, budget, depth + 1) for k, v in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def _walk(value: Any, path: str, out: list[dict]) -> None:
    if isinstance(value, dict) and set(value) - {"hex"} and set(value) != {"bits", "bit_length"}:
        for key, item in value.items():
            _walk(item, f"{path}/{key}" if path else key, out)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk(item, f"{path}[{index}]", out)
    else:
        out.append({"path": path, "value": value})


def _decode_pdu(module: Any, pdu: str, codec: str, data: bytes) -> dict:
    _asnproc, _generator, codecs, Charpy, lock = _pycrate()
    if codec not in ("uper", "aper", "ber", "der", "oer"):
        raise SchemaBundleError(f"codec must be uper, aper, ber, der or oer, not {codec!r}")
    mod_name, schema = _find_pdu(module, pdu)
    data = _blob(data)
    per = codecs.ASN1CodecPER
    with lock:
        saved = (list(per._off), per.ALIGNED)
        try:
            obj = copy.deepcopy(schema)
            buf = Charpy(data)
            getattr(obj, "from_" + codec)(buf)
            left = buf.len_bit()
            if left > 7 or (left and buf.to_uint() != 0):
                raise DecodeFailed(f"{left} bit(s) follow the {pdu} PDU and are not padding")
            canonical = None
            if codec in ("uper", "aper", "der", "oer"):
                canonical = getattr(obj, "to_" + codec)() == data
                if not canonical:
                    raise DecodeFailed(f"the {codec.upper()} bytes do not re-encode to themselves under {pdu}: "
                                       "wrong schema, wrong type, or a non-canonical encoding")
            value = obj.get_val()
        except SchemaBundleError:
            raise
        except Exception as exc:
            raise DecodeFailed(f"not a {codec.upper()} {pdu}: {type(exc).__name__}: {str(exc)[:200]}") from None
        finally:
            per._off[:] = saved[0]
            per.ALIGNED = saved[1]
    plain = _plain(value, [MAX_NODES])
    rows: list[dict] = []
    _walk(plain, "", rows)
    return {"module": mod_name, "pdu": pdu.rpartition(".")[2], "codec": codec, "value": plain, "fields": rows,
            "canonical": canonical}


def decode_asn1(data: bytes, fam: Family | str, pdu: str, root: Path | None = None,
                codec: str | None = None) -> dict:
    """Decode one PDU against an ASN.1 bundle family. `pdu` is a family PDU name (`cam`, `denm`,
    `mmspdu`) or a `Type` / `Module.Type` of the family's modules (then `codec` is required)."""
    fam = family(fam) if isinstance(fam, str) else fam
    if fam.kind != "asn1":
        raise SchemaBundleError(f"family {fam.id!r} is not an ASN.1 family")
    known = {name: (typ, how) for name, typ, how in fam.pdus}
    if pdu.lower() in known:
        type_name, how = known[pdu.lower()]
        how = codec or how
    elif codec:
        type_name, how = pdu, codec
    else:
        raise SchemaBundleError(f"family {fam.id!r} has no PDU {pdu!r} (known: {', '.join(known)}); "
                                "name a Type or Module.Type together with a codec")
    files = _asn_files(fam, _family_dir(fam, root))
    try:
        module = compile_asn1(files)
    except SchemaUnusable as exc:
        raise SchemaUnusable(f"schema family {fam.id!r}: {exc}" + (f" ({fam.note})" if fam.note else "")) from None
    out = _decode_pdu(module, type_name, how, data)
    out["family"], out["schema"] = fam.id, f"{fam.id}: {', '.join(p.name for p in files)}"
    return out


def decode_asn1_files(data: bytes, files: Sequence[Path | str], pdu: str, codec: str) -> dict:
    """Decode one PDU against ASN.1 module files named by the caller (trusted files only)."""
    out = _decode_pdu(compile_asn1(files), pdu, codec, data)
    out["schema"] = ", ".join(Path(f).name for f in files)
    return out


# --------------------------------------------------------------------------------------------------
# Bit dictionaries (VMF K-series)

def decode_bits(data: bytes, fam: Family | str, message: str, root: Path | None = None,
                bit_length: int | None = None) -> dict:
    """Decode a body against <bundle>/<family>/<message>.json (see _schema_bits for the format)."""
    fam = family(fam) if isinstance(fam, str) else fam
    if fam.kind != "bits":
        raise SchemaBundleError(f"family {fam.id!r} is not a bit-dictionary family")
    if not message or any(c in message for c in "/\\") or message.startswith("."):
        raise SchemaBundleError(f"message name {message!r} is not a plain file stem")
    path = _family_dir(fam, root) / f"{message}.json"
    if not path.is_file():
        raise SchemaMissing(fam, path, "is not in the bundle (no dictionary for this message)")
    try:
        spec = bits_codec.load_dictionary(path)
        out = bits_codec.decode(_blob(data), spec, bit_length=bit_length)
    except bits_codec.BitDictionaryError as exc:
        raise SchemaBundleError(f"schema family {fam.id!r}: {exc}") from None
    except bits_codec.BitDecodeError as exc:
        raise DecodeFailed(f"{fam.id}/{message}: {exc}") from None
    out["family"], out["schema"] = fam.id, f"{fam.id}/{path.name}"
    return out


# --------------------------------------------------------------------------------------------------
# Contract entry

def _inputs(folder: Path) -> list[Path]:
    out = []
    for path in sorted(folder.rglob("*")):
        if len(out) >= MAX_FILES:
            break
        rel = path.relative_to(folder)
        if any(part.startswith(".") for part in rel.parts) or path.is_symlink() or not path.is_file():
            continue
        if 0 < path.stat().st_size <= MAX_INPUT:
            out.append(path)
    return out


def _payloads(raw: bytes) -> list[tuple[str, bytes, bool]]:
    """(kind, bytes, sure) candidates in one file: V2GTP frames, a bare EXI stream, an ITS Release-2
    PDU, either as bytes or as one blob of hex text. `sure` is False when only a leading header byte
    matched (a bare 0x80 EXI header, an ITS 02 01 / 02 02 header): many unrelated binaries start that
    way, so solve says so in any note about such a file."""
    blobs = [raw]
    text = bytes(b for b in raw if b not in b" \t\r\n")
    if text and len(text) % 2 == 0 and all(c in b"0123456789abcdefABCDEF" for c in text):
        blobs = [bytes.fromhex(text.decode("ascii"))]
    out: list[tuple[str, bytes, bool]] = []
    for blob in blobs:
        if blob[:2] == b"\x01\xfe":
            try:
                out.extend(("exi", f["payload"], True) for f in split_v2gtp(blob)
                           if f["payload_type"] == V2GTP_EXI or 0x8002 <= f["payload_type"] <= 0x8006)
            except DecodeFailed:
                pass
        elif blob[:4] == b"$EXI":
            out.append(("exi", blob, True))
        elif blob[:1] == b"\x80":
            out.append(("exi", blob, False))
        elif len(blob) >= 6 and blob[0] == 2 and blob[1] in (1, 2):
            out.append(("denm" if blob[1] == 1 else "cam", blob, False))
    return out


def _guess_note(guessed: Sequence[str]) -> str:
    if not guessed:
        return ""
    shown = ", ".join(guessed[:10]) + (f" and {len(guessed) - 10} more" if len(guessed) > 10 else "")
    return (f" [payload detection was heuristic for {shown}: only a leading header byte matched "
            "(0x80 for EXI, 02 01 / 02 02 for an ITS PDU), so these may not be EXI or ITS payloads at all]")


def _texts(fields: list[dict]) -> str:
    lines = []
    for row in fields:
        value = row["value"]
        lines.append(f"{row['path']} = {value}")
        if isinstance(value, dict) and "hex" in value:
            lines.append(bytes.fromhex(value["hex"]).decode("latin-1"))
    return "\n".join(lines)


def solve(challenge_dir, profile, **opts):
    """Decode the challenge's V2GTP/EXI streams and ITS Release-2 CAM/DENM PDUs against the schema
    bundle and look for the flag in the decoded fields.

    Options: `family` (limit EXI decoding to one family; default every EXI family the bundle holds),
    `challenge_id`. `blocked` when a file needs a schema the bundle does not hold (the note names the
    family and where it comes from), holds one that cannot be loaded, or is itself missing; `none` when no file is a
    V2GTP/EXI/ITS payload; `unsure` when fields decoded but hold no flag (they are in the evidence)."""
    from ctf import flagfmt
    from ctf.result import Cost, Evidence, SolverResult

    t0 = time.monotonic()
    cid = opts.get("challenge_id")

    def result(status, **kw):
        return SolverResult(status, engine=ME, challenge_id=cid,
                            cost=Cost(seconds=round(time.monotonic() - t0, 3)), **kw)

    folder = Path(challenge_dir)
    found = []
    for path in _inputs(folder):
        for kind, payload, sure in _payloads(path.read_bytes()):
            found.append((path, kind, payload, sure))
    if not found:
        return result("none", notes="no V2GTP frame, EXI stream or ITS Release-2 CAM/DENM PDU in the challenge files")

    def guessed(paths) -> list[str]:
        return list(dict.fromkeys(str(p.relative_to(folder)) for p in paths))

    try:
        root = bundle_root()
    except BundleMissing as exc:
        return result("blocked", notes=str(exc) + _guess_note(guessed(p for p, _k, _b, sure in found if not sure)))
    try:
        exi_families = [family(opts["family"])] if opts.get("family") else [f for f in FAMILIES if f.kind == "exi"]
    except SchemaBundleError as exc:
        return result("blocked", notes=str(exc))
    if any(f.kind != "exi" for f in exi_families):
        return result("blocked", notes=f"option family={opts['family']!r} is not an EXI family")
    evidence, flags, blocked, failed, blocked_files, blocked_guesses = [], [], [], [], [], []
    for path, kind, payload, sure in found:
        rel = str(path.relative_to(folder))
        decoded = None
        reasons: list[str] = []
        if kind == "exi":
            for fam in exi_families:
                try:
                    decoded = decode_exi(payload, fam, None, root)
                    break
                except (SchemaMissing, SchemaUnusable) as exc:
                    reasons.append(str(exc))
                except SchemaBundleError as exc:
                    failed.append(f"{rel}: {exc}")
        else:
            try:
                decoded = decode_asn1(payload, "etsi-its-r2", kind, root)
            except (SchemaMissing, SchemaUnusable, ToolMissing) as exc:
                reasons.append(str(exc))
            except SchemaBundleError as exc:
                failed.append(f"{rel}: {exc}")
        if decoded is None:
            if reasons:                             # a schema it needs is missing or does not load
                blocked.extend(reasons)
                blocked_files.append(path)
                if not sure:
                    blocked_guesses.append(path)
            continue
        text = _texts(decoded["fields"])
        hits = [f for f in flagfmt.find_flags(text, profile) if f not in flags]
        flags.extend(hits)
        head = "; ".join(f"{r['path']}={json.dumps(r['value'])[:60]}" for r in decoded["fields"][:6])
        evidence.append(Evidence("decode", f"{decoded['schema']}: {head}"[:400] +
                                 (f" -> flag {hits[0]}" if hits else ""), path=rel))
    blocked = list(dict.fromkeys(blocked))
    also = ""
    if blocked:                                     # other payloads still need a schema: say which and why
        also = (f"payloads in {', '.join(guessed(blocked_files)[:10])} could not be tried: "
                + " | ".join(blocked))[:1500] + _guess_note(guessed(blocked_guesses))
    if flags:
        return result("solved", flags=flags, evidence=evidence, notes=also)
    if evidence:
        return result("unsure", evidence=evidence,
                      notes=f"{len(evidence)} payload(s) decoded to fields; none holds a flag-format value"
                            + (f"; {also}" if also else ""))
    if blocked:
        return result("blocked", notes=" | ".join(blocked)[:1500] + _guess_note(guessed(blocked_guesses)))
    return result("none", notes=("payloads found but none decodes against the bundle: " + " | ".join(failed))[:1500])


# --------------------------------------------------------------------------------------------------
# CLI

def _read(path: str) -> bytes:
    data = Path(path).read_bytes()
    text = bytes(b for b in data if b not in b" \t\r\n")
    if text and len(text) % 2 == 0 and all(c in b"0123456789abcdefABCDEF" for c in text):
        return bytes.fromhex(text.decode("ascii"))
    return data


def _challenge_roots() -> list[tuple[str, Path]]:
    """Folders that hold challenge files: the default work base (every event's work folder), the
    current work folder (paths.workdir(), which $CTF_WORKDIR moves), the real-data corpus, the saved
    challenges and the rehearsal corpus.

    A corpus variable set to something that is not a folder fails loudly, naming the variable (the
    error ctf.paths raises so a typo is never read as "nothing there"): the guard does not run on a
    misconfiguration it cannot see past."""
    from ctf import paths
    from ctf.event import EventError
    roots = [("the work base", paths.DEFAULT_WORK_BASE.expanduser().resolve())]
    try:
        roots.append(("the work folder ($CTF_WORKDIR)", paths.workdir()))
    except EventError:
        pass                                        # no current event: the work base above covers its folder
    roots.append(("the real-data corpus ($CTF_REALDATA)", paths.realdata_root()))
    for label, get in (("the saved challenges ($CTF_REAL_CHALLENGES)", paths.saved_challenges_root),
                       ("the rehearsal corpus ($CTF_REHEARSAL_CORPUS)", paths.rehearsal_corpus_root)):
        try:
            root = get()
        except FileNotFoundError as exc:
            raise SchemaBundleError(f"--asn guard cannot check {label}: {exc}; fix or unset the variable, "
                                    "then run again") from exc
        if root is not None:
            roots.append((label, root))
    return roots


def _refuse_challenge_asn(files: Sequence[str]) -> None:
    """--asn compiles ASN.1 to Python and runs it: a module that sits among challenge files is
    challenge-supplied, so untrusted, and is refused by name (rule: challenge files are data)."""
    roots = _challenge_roots()
    for name in files:
        path = Path(name).expanduser().resolve()
        for label, root in roots:
            if path == root or root in path.parents:
                raise SchemaBundleError(
                    f"--asn {name}: the module lies under {label} ({root}), so it is challenge-supplied; "
                    "compiling it would run Python generated from untrusted text. Review it, then copy it "
                    "outside the challenge folders if you trust it")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode EXI, ASN.1 and bit-dictionary messages against "
                                                 "the operator's schema bundle")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="what the bundle holds, and where each schema comes from")
    p = sub.add_parser("exi", help="decode an EXI document or V2GTP frames (bytes or hex text)")
    p.add_argument("file")
    p.add_argument("--family")
    p.add_argument("--document")
    p.add_argument("--xsd", nargs="+", help="decode against these XSD files instead of a bundle family")
    p = sub.add_parser("asn1", help="decode one ASN.1 PDU")
    p.add_argument("file")
    p.add_argument("--family")
    p.add_argument("--asn", nargs="+", help="compile these (trusted) module files instead of a bundle family")
    p.add_argument("--pdu", required=True)
    p.add_argument("--codec")
    p = sub.add_parser("bits", help="decode a bit message against a dictionary of the bundle")
    p.add_argument("file")
    p.add_argument("--family", default="vmf-k")
    p.add_argument("--message", required=True)
    p.add_argument("--bits", type=int, help="the body's length in bits when it is not whole octets")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "status":
            out: Any = status()
        elif args.cmd == "exi":
            data = _read(args.file)
            if args.xsd:
                out = decode_exi_xsd(data, args.xsd)
            elif not args.family:
                parser.error("exi needs --family or --xsd")
            elif data[:2] == b"\x01\xfe":
                out = decode_v2gtp(data, args.family, args.document)
            else:
                out = decode_exi(data, args.family, args.document)
        elif args.cmd == "asn1":
            data = _read(args.file)
            if args.asn:
                if not args.codec:
                    parser.error("asn1 --asn needs --codec")
                _refuse_challenge_asn(args.asn)
                print("schema_bundle: --asn compiles these modules to Python and runs it; pass only modules "
                      "you trust, never a challenge's own", file=sys.stderr)
                out = decode_asn1_files(data, args.asn, args.pdu, args.codec)
            elif not args.family:
                parser.error("asn1 needs --family or --asn")
            else:
                out = decode_asn1(data, args.family, args.pdu, codec=args.codec)
        else:
            out = decode_bits(_read(args.file), args.family, args.message, bit_length=args.bits)
    except SchemaBundleError as exc:
        print(f"schema_bundle: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"schema_bundle: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, indent=2, sort_keys=True, default=str))
    if args.cmd == "status" and out["bundle_error"]:
        print(f"schema_bundle: {out['bundle_error']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
