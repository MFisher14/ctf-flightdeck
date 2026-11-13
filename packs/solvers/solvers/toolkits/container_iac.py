#!/usr/bin/env python3
"""Offline OCI/Docker layer forensics and IaC exposure analysis.

Archives are parsed in memory and never extracted (an unpacked layout folder is read in place).
`--dump DIR` (B-072) writes each layer's file versions as plain files, never links, with the config,
the report and an `index.md` of labels, annotations and history.  Whiteouts are applied according
to OCI semantics while deleted/overwritten bytes remain available to the caller for
forensics.  IaC inputs are supplied JSON, YAML, Terraform HCL/state/plan, CloudFormation
and Kubernetes manifests; this module never contacts or starts a container/cloud.
"""
from __future__ import annotations

import argparse
import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import posixpath
import re
import sys
import tarfile
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None
try:
    import zstandard
except ImportError:  # pragma: no cover
    zstandard = None

MAX_ARCHIVE = 512 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
# B-072: the bytes resolved hard links add to an image (each link carries its target's bytes, and the
# dump writes them once per link), counted image-wide: many links to one big file cannot amplify it.
MAX_LINKED = MAX_TOTAL
MAX_MEMBERS = 500_000
MAX_FINDINGS = 50_000


def _finding(kind: str, severity: str, message: str, **evidence) -> dict:
    out = {"kind": kind, "severity": severity, "message": message}
    out.update({key: value for key, value in evidence.items() if value is not None})
    return out


def _sort(findings: list[dict]) -> list[dict]:
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    unique = {(item.get("kind"), item.get("source"), item.get("path"), item.get("object"),
               item.get("key"), item.get("offset"), item.get("message")): item for item in findings}
    return sorted(unique.values(), key=lambda item: (-rank.get(item.get("severity"), 0),
                                                      str(item.get("kind")), str(item.get("path", ""))))[:MAX_FINDINGS]


def _path(name: str) -> str:
    replaced = name.replace("\\", "/")
    if "\0" in replaced or any(part == ".." for part in replaced.split("/")):
        raise ValueError("unsafe archive path")
    clean = posixpath.normpath("/" + replaced.lstrip("/"))
    if clean == "/":
        raise ValueError("unsafe or empty archive path")
    return clean.lstrip("/")


@dataclass
class FileVersion:
    path: str
    layer: int
    content: bytes
    mode: int = 0
    reason: str = "present"
    linkname: str | None = None
    # file | symlink | hardlink (content is its target's bytes) | hardlink-unresolved (no target found)
    kind: str = "file"

    def metadata(self) -> dict:
        return {"path": self.path, "layer": self.layer, "size": len(self.content),
                "sha256": hashlib.sha256(self.content).hexdigest(), "reason": self.reason,
                "mode": oct(self.mode), "linkname": self.linkname, "kind": self.kind}


@dataclass
class ImageForensics:
    format: str
    files: dict[str, FileVersion] = field(default_factory=dict)
    recovered: list[FileVersion] = field(default_factory=list)
    layers: list[dict] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    versions: list[FileVersion] = field(default_factory=list)   # B-072: every file version, layer order
    meta: dict = field(default_factory=dict)                    # B-072: index/manifest annotations, platform

    def report(self) -> dict:
        history = image_history(self.config, len(self.layers))
        made_by = layer_history(history)

        def with_history(row: dict, layer) -> dict:
            step = made_by.get(layer)
            if step:
                row.update({key: step[key] for key in ("created_by", "comment") if key in step})
            return row

        return {"format": self.format, "layer_count": len(self.layers), "final_file_count": len(self.files),
                "layers": [with_history(dict(layer), layer.get("index")) for layer in self.layers],
                "config": public_config(self.config),
                "labels": image_labels(self.config), "history": history,
                "annotations": self.meta.get("annotations", {}), "platform": self.meta.get("platform"),
                "versions": [with_history(item.metadata(), item.layer) for item in self.versions],
                "recovered": [item.metadata() for item in self.recovered],
                "findings": _sort(self.findings),
                **({"dump": self.meta["dump"]} if "dump" in self.meta else {})}

    def identity(self) -> str:
        """A stable name for this image: sha256 over its layer digests and its config."""
        digest = hashlib.sha256()
        for layer in self.layers:
            digest.update(str(layer.get("digest")).encode() + b"\n")
        digest.update(json.dumps(self.config, sort_keys=True, default=str).encode())
        return digest.hexdigest()


def layer_history(history: list[dict]) -> dict[int, dict]:
    """{layer index: the history record that made it} from image_history's rows."""
    return {row["layer"]: row for row in history if row.get("layer") is not None}


def image_labels(config: dict) -> dict:
    """The image config's labels (`config.Labels`, OCI image-spec), values as text."""
    section = config.get("config", config) if isinstance(config, dict) else {}
    labels = section.get("Labels") if isinstance(section, dict) else None
    return {str(key): str(value) for key, value in sorted(labels.items())} if isinstance(labels, dict) else {}


def config_diff_ids(config: dict) -> list[str] | None:
    """The config's `rootfs.diff_ids` as text, or None when the config states none."""
    rootfs = config.get("rootfs") if isinstance(config, dict) else None
    ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
    return [str(item) for item in ids] if isinstance(ids, list) else None


def image_history(config: dict, layer_count: int) -> list[dict]:
    """One entry per config history record with its `created_by`, and the layer it made: the records
    without `empty_layer` map in order onto the layers; an empty-layer record (ENV, LABEL, CMD...) and a
    record past the last layer map to None."""
    history = config.get("history") if isinstance(config, dict) else None
    out, layer = [], 0
    for index, item in enumerate(history if isinstance(history, list) else []):
        item = item if isinstance(item, dict) else {}
        empty = item.get("empty_layer") is True
        row = {"index": index, "layer": None if empty or layer >= layer_count else layer,
               "empty_layer": empty}
        for key in ("created", "created_by", "author", "comment"):
            if isinstance(item.get(key), str):
                row[key] = item[key]
        if not empty:
            layer += 1
        out.append(row)
    return out


def _tar_members(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE:
        raise ValueError("archive exceeds input cap")
    out, total = {}, 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as exc:
        raise ValueError("invalid tar archive") from exc
    try:
        with archive:
            for index, member in enumerate(archive):
                if index >= MAX_MEMBERS:
                    raise ValueError("archive member cap exceeded")
                if not member.isfile():
                    continue
                name = _path(member.name)
                if member.size > MAX_MEMBER:
                    raise ValueError(f"archive member exceeds cap: {name}")
                handle = archive.extractfile(member)
                body = handle.read(MAX_MEMBER + 1) if handle else b""
                if len(body) != member.size or len(body) > MAX_MEMBER:
                    raise ValueError(f"truncated/oversized archive member: {name}")
                total += len(body)
                if total > MAX_TOTAL:
                    raise ValueError("expanded archive exceeds total cap")
                if name in out:
                    raise ValueError(f"duplicate archive member: {name}")
                out[name] = body
    except tarfile.TarError as exc:
        raise ValueError("invalid or truncated tar archive") from exc
    return out


def _decompress_layer(data: bytes) -> bytes:
    try:
        if data.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                body = stream.read(MAX_ARCHIVE + 1)
            if len(body) > MAX_ARCHIVE:
                raise ValueError("gzip layer exceeds expanded cap")
            return body
        if data.startswith(b"BZh"):
            decoder = bz2.BZ2Decompressor()
            body = decoder.decompress(data, max_length=MAX_ARCHIVE + 1)
            if len(body) > MAX_ARCHIVE:
                raise ValueError("bzip2 layer exceeds expanded cap")
            if not decoder.eof:
                raise ValueError("truncated bzip2 layer")
            return body
        if data.startswith(b"\xfd7zXZ\0"):
            decoder = lzma.LZMADecompressor()
            body = decoder.decompress(data, max_length=MAX_ARCHIVE + 1)
            if len(body) > MAX_ARCHIVE:
                raise ValueError("xz layer exceeds expanded cap")
            if not decoder.eof:
                raise ValueError("truncated xz layer")
            return body
        if data.startswith(b"\x28\xb5\x2f\xfd"):
            if zstandard is None:
                raise ValueError("zstd-compressed layer requires zstandard")
            try:
                return zstandard.ZstdDecompressor().decompress(data, max_output_size=MAX_ARCHIVE)
            except zstandard.ZstdError as exc:
                raise ValueError("invalid zstd-compressed layer") from exc
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise ValueError("invalid compressed layer") from exc
    return data


def _layer_entries(data: bytes, index: int) -> list[FileVersion]:
    return _layer_entries_raw(_decompress_layer(data), index)


def _layer_entries_raw(raw: bytes, index: int) -> list[FileVersion]:
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("expanded layer exceeds cap")
    out, total = [], 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    except tarfile.TarError as exc:
        raise ValueError("invalid layer tar") from exc
    with archive:
        for count, member in enumerate(archive):
            if count >= MAX_MEMBERS:
                raise ValueError("layer member cap exceeded")
            # Directories and devices are never recorded, so their names are not checked: a layer
            # made with `tar -C rootfs -cf layer.tar .` starts with a `./` root entry.
            if not (member.isreg() or member.issym() or member.islnk()):
                continue
            name = _path(member.name)
            kind = "file"
            if member.isreg():
                if member.size > MAX_MEMBER:
                    raise ValueError(f"layer member exceeds cap: {name}")
                handle = archive.extractfile(member)
                body = handle.read(MAX_MEMBER + 1) if handle else b""
                if len(body) != member.size:
                    raise ValueError(f"truncated layer member: {name}")
                total += len(body)
                if total > MAX_TOTAL:
                    raise ValueError("layer expanded total cap exceeded")
            elif member.issym():
                body, kind = b"", "symlink"
            else:
                # A hard link names an earlier file of this layer or one in a lower layer; _analyze_store
                # resolves it against the filesystem as built so far, in tar order.
                body, kind = b"", "hardlink-unresolved"
            out.append(FileVersion(name, index, body, member.mode, linkname=member.linkname or None, kind=kind))
    return out


def _link_target(linkname: str) -> str | None:
    try:
        return _path(linkname)
    except ValueError:
        return None


def _json_member(store: dict[str, bytes], path: str) -> dict:
    try:
        value = json.loads(store[path])
    except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"missing or invalid JSON member: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON member is not an object: {path}")
    return value


def _oci_blob_path(digest: str) -> str:
    algorithm, marker, value = digest.partition(":")
    if marker != ":" or algorithm != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("unsupported OCI digest")
    return f"blobs/sha256/{value}"


def _verify_blob(store: dict[str, bytes], descriptor: dict) -> tuple[str, bytes]:
    if not isinstance(descriptor, dict):
        raise ValueError("OCI descriptor is not an object")
    path = _oci_blob_path(str(descriptor.get("digest", "")))
    try:
        body = store[path]
    except KeyError as exc:
        raise ValueError(f"missing OCI blob: {path}") from exc
    if hashlib.sha256(body).hexdigest() != path.rsplit("/", 1)[-1]:
        raise ValueError(f"OCI digest mismatch: {path}")
    if descriptor.get("size") is not None and int(descriptor["size"]) != len(body):
        raise ValueError(f"OCI size mismatch: {path}")
    return path, body


_INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json")
MAX_INDEX_DEPTH = 4


def _pick_descriptor(descriptors: list) -> dict:
    """The image of an index: the first descriptor that is not a buildx attestation (`unknown/unknown`)."""
    for descriptor in descriptors:
        platform = descriptor.get("platform") if isinstance(descriptor, dict) else None
        if isinstance(platform, dict) and platform.get("os") == "unknown":
            continue
        return descriptor
    return descriptors[0]


def _oci_parts(store, meta: dict) -> tuple[str, list[bytes], dict]:
    index = _json_member(store, "index.json")
    annotations = dict(index.get("annotations") or {}) if isinstance(index.get("annotations"), dict) else {}
    for _depth in range(MAX_INDEX_DEPTH):
        descriptors = index.get("manifests")
        if not isinstance(descriptors, list) or not descriptors:
            raise ValueError("OCI index has no manifest")
        descriptor = _pick_descriptor(descriptors)
        if isinstance(descriptor, dict):
            if isinstance(descriptor.get("annotations"), dict):
                annotations.update(descriptor["annotations"])
            if isinstance(descriptor.get("platform"), dict):
                meta["platform"] = descriptor["platform"]
        _, manifest_raw = _verify_blob(store, descriptor)
        try:
            manifest = json.loads(manifest_raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("invalid OCI manifest") from exc
        if not isinstance(manifest, dict):
            raise ValueError("invalid OCI manifest object")
        if manifest.get("mediaType") in _INDEX_TYPES or ("manifests" in manifest and "layers" not in manifest):
            index = manifest              # a nested (multi-platform) index: descend to its image
            continue
        break
    else:
        raise ValueError("OCI index nesting exceeds depth cap")
    if isinstance(manifest.get("annotations"), dict):
        annotations.update(manifest["annotations"])
    meta["annotations"] = {str(key): str(value) for key, value in sorted(annotations.items())}
    _, config_raw = _verify_blob(store, manifest.get("config", {}))
    try:
        config = json.loads(config_raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid OCI config") from exc
    raw_layers = manifest.get("layers", [])
    if not isinstance(raw_layers, list):
        raise ValueError("OCI manifest layers is not a list")
    if len(raw_layers) > MAX_MEMBERS:
        raise ValueError("OCI layer count exceeds cap")
    layers = [_verify_blob(store, descriptor)[1] for descriptor in raw_layers]
    meta["layer_media_types"] = [str(d.get("mediaType", "")) if isinstance(d, dict) else "" for d in raw_layers]
    return "oci-layout", layers, config


def _image_parts(store, meta: dict | None = None) -> tuple[str, list[bytes], dict]:
    meta = {} if meta is None else meta
    if "oci-layout" in store and "index.json" in store:  # B-072: an OCI layout (Docker 25+ saves one too)
        return _oci_parts(store, meta)
    if "manifest.json" in store:  # docker save
        try:
            manifests = json.loads(store["manifest.json"])
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("invalid docker manifest") from exc
        if not isinstance(manifests, list) or not manifests or not isinstance(manifests[0], dict):
            raise ValueError("docker manifest has no image")
        manifest = manifests[0]
        raw_layers = manifest.get("Layers", [])
        if not isinstance(raw_layers, list):
            raise ValueError("docker manifest Layers is not a list")
        layers = [store[path] for path in raw_layers if path in store]
        if len(layers) > MAX_MEMBERS:
            raise ValueError("docker layer count exceeds cap")
        if len(layers) != len(raw_layers):
            raise ValueError("docker save is missing a layer")
        config = _json_member(store, str(manifest.get("Config")))
        return "docker-save", layers, config
    if "index.json" in store:  # OCI layout without its oci-layout marker
        return _oci_parts(store, meta)
    raise ValueError("archive is neither docker-save nor OCI layout")


_SECRET_PATTERNS = (
    ("private-key", "critical", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws-access-key", "critical", re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("github-token", "critical", re.compile(rb"(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,255}")),
    ("slack-token", "high", re.compile(rb"(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{10,200}")),
    ("jwt", "high", re.compile(rb"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")),
    ("secret-assignment", "high", re.compile(rb"(?i)(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?([^\s'\";,]{6,256})")),
)


def scan_secret_bytes(data: bytes, *, source: str, path: str, layer: int | None = None,
                      recovered: bool = False) -> list[dict]:
    findings = []
    sample = data[:MAX_MEMBER]
    for secret_type, severity, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(sample):
            raw = match.group(1) if match.lastindex else match.group(0)
            findings.append(_finding("embedded-secret", severity, "credential-like material is present in supplied image evidence",
                                     source=source, path=path, layer=layer, recovered=recovered,
                                     secret_type=secret_type, offset=match.start(), value=raw.decode("utf-8", "replace")))
            if len(findings) >= 256:
                return findings
    return findings


def public_config(config: dict) -> dict:
    section = config.get("config", config) if isinstance(config, dict) else {}
    env = section.get("Env", []) if isinstance(section, dict) else []
    env = env if isinstance(env, list) else []
    return {"architecture": config.get("architecture") if isinstance(config, dict) else None,
            "os": config.get("os") if isinstance(config, dict) else None,
            "environment_names": sorted({str(item).split("=", 1)[0] for item in env if isinstance(item, str)}),
            "history_entries": len(config.get("history", [])) if isinstance(config, dict) and isinstance(config.get("history"), list) else 0}


class LayoutDir:
    """A read-only store over an unpacked image folder (an OCI layout or a docker-save tree): the same
    `name in store` / `store[name]` the in-memory tar store answers, reading only the members asked for.
    A link anywhere on the path, or a member outside the folder, is not a member; caps as for a tar."""

    def __init__(self, root: Path):
        self.root = Path(root)
        if not self.root.is_dir() or self.root.is_symlink():
            raise ValueError(f"not an image folder: {root}")
        self._real = self.root.resolve()
        self.total = 0

    def _file(self, name: str) -> Path | None:
        try:
            rel = _path(name)
        except ValueError:
            return None
        here = self._real
        for part in rel.split("/"):
            here = here / part
            if here.is_symlink():
                return None
        return here if here.is_file() else None

    def __contains__(self, name) -> bool:
        return isinstance(name, str) and self._file(name) is not None

    def __getitem__(self, name: str) -> bytes:
        found = self._file(name)
        if found is None:
            raise KeyError(name)
        size = found.stat().st_size
        if size > MAX_ARCHIVE:
            raise ValueError(f"image member exceeds input cap: {name}")
        self.total += size
        if self.total > MAX_TOTAL:
            raise ValueError("image folder read exceeds total cap")
        return found.read_bytes()


def _analyze_store(store) -> ImageForensics:
    meta: dict = {}
    image_format, layers, config = _image_parts(store, meta)
    image = ImageForensics(image_format, config=config, meta=meta)
    media_types = meta.get("layer_media_types", [])
    diff_ids = config_diff_ids(config)
    if diff_ids is not None and len(diff_ids) != len(layers):
        image.findings.append(_finding("layer-count-mismatch", "medium",
                                       "config rootfs.diff_ids and the manifest name different layer counts",
                                       source="config", value=f"{len(diff_ids)} diff_ids, {len(layers)} layers"))
    linked = 0
    for index, layer_data in enumerate(layers):
        raw = _decompress_layer(layer_data)
        entries = _layer_entries_raw(raw, index)
        layer_meta = {"index": index, "digest": "sha256:" + hashlib.sha256(layer_data).hexdigest(),
                      "diff_id": "sha256:" + hashlib.sha256(raw).hexdigest(),
                      "entry_count": len(entries), "whiteouts": []}
        if index < len(media_types) and media_types[index]:
            layer_meta["media_type"] = media_types[index]
        # B-072: the config's rootfs.diff_ids name each uncompressed layer in order; a layer whose
        # digest is not the one the config names was swapped or reordered.
        if diff_ids is not None:
            expected = diff_ids[index] if index < len(diff_ids) else None
            layer_meta["diff_id_ok"] = expected == layer_meta["diff_id"]
            if not layer_meta["diff_id_ok"]:
                layer_meta["diff_id_expected"] = expected
                image.findings.append(_finding("layer-diff-id-mismatch", "medium",
                                               "layer content does not match the config's rootfs.diff_ids entry",
                                               source="config", path=f"rootfs.diff_ids[{index}]", layer=index,
                                               value=expected))
        # Whiteouts take effect before ordinary additions from the same layer.
        for entry in entries:
            base = posixpath.basename(entry.path)
            directory = posixpath.dirname(entry.path)
            if base == ".wh..wh..opq":
                prefix = directory.rstrip("/") + "/" if directory else ""
                victims = [path for path in image.files if path.startswith(prefix)]
                for path in victims:
                    victim = image.files.pop(path)
                    victim.reason = f"opaque-whiteout@layer-{index}"
                    image.recovered.append(victim)
                layer_meta["whiteouts"].append({"path": directory or ".", "opaque": True, "deleted": sorted(victims)})
            elif base.startswith(".wh."):
                target = posixpath.join(directory, base[4:]) if directory else base[4:]
                victims = [path for path in image.files if path == target or path.startswith(target.rstrip("/") + "/")]
                for path in victims:
                    victim = image.files.pop(path)
                    victim.reason = f"whiteout@layer-{index}"
                    image.recovered.append(victim)
                layer_meta["whiteouts"].append({"path": target, "opaque": False, "deleted": sorted(victims)})
        for entry in entries:
            if posixpath.basename(entry.path).startswith(".wh."):
                continue
            if entry.kind == "hardlink-unresolved":   # its target: this layer's earlier file, or a lower one
                lower = image.files.get(_link_target(entry.linkname or "") or "")
                if lower is not None and lower.kind in ("file", "hardlink"):
                    linked += len(lower.content)
                    if linked > MAX_LINKED:
                        raise ValueError(f"hard links expand past the linked-bytes cap at {entry.path}")
                    entry.content, entry.kind = lower.content, "hardlink"
            prior = image.files.get(entry.path)
            if prior:
                prior.reason = f"overwritten@layer-{index}"
                image.recovered.append(prior)
            image.files[entry.path] = entry
            image.versions.append(entry)
            if entry.kind != "hardlink":   # a hard link's bytes are its target's, scanned once there
                image.findings.extend(scan_secret_bytes(entry.content, source="layer", path=entry.path, layer=index))
        image.layers.append(layer_meta)
    for recovered in image.recovered:
        if recovered.kind == "hardlink":
            continue
        image.findings.extend(scan_secret_bytes(recovered.content, source="recovered-layer", path=recovered.path,
                                                layer=recovered.layer, recovered=True))
    section = config.get("config", config) if isinstance(config, dict) else {}
    for entry in section.get("Env", []) if isinstance(section, dict) and isinstance(section.get("Env"), list) else []:
        if not isinstance(entry, str) or "=" not in entry:
            continue
        name, value = entry.split("=", 1)
        if re.search(r"(?i)(?:pass|secret|token|api[_-]?key|credential|private)", name) and value:
            image.findings.append(_finding("config-env-secret", "high", "image config embeds a secret-named environment value",
                                           source="config", key=name, value=value))
    for index, history in enumerate(config.get("history", []) if isinstance(config, dict) and isinstance(config.get("history"), list) else []):
        command = history.get("created_by", "") if isinstance(history, dict) else ""
        if isinstance(command, str):
            image.findings.extend(scan_secret_bytes(command.encode(), source="history", path=f"history[{index}]"))
    return image


def analyze_image_archive(data: bytes) -> ImageForensics:
    return _analyze_store(_tar_members(data))


def analyze_layout_dir(root: Path) -> ImageForensics:
    """An unpacked OCI layout (or docker-save tree) read in place, never copied."""
    return _analyze_store(LayoutDir(root))


def image_root(target: Path) -> Path:
    """The folder or archive an input names: a folder or an archive is itself; the layout's own
    `oci-layout`, `index.json` or `manifest.json` file names its folder (what intake passes)."""
    target = Path(target)
    if target.is_file() and target.name in ("oci-layout", "index.json", "manifest.json"):
        return target.parent
    return target


def analyze_image_path(target: Path) -> ImageForensics:
    root = image_root(target)
    if root.is_dir():
        return analyze_layout_dir(root)
    if not root.is_file():
        raise ValueError(f"no such image input: {target}")
    if root.stat().st_size > MAX_ARCHIVE:
        raise ValueError("archive exceeds input cap")
    return analyze_image_archive(root.read_bytes())


def _write_new(folder: Path, rel: str, body: bytes) -> None:
    """Write body at folder/rel, creating parents; never through a link (O_NOFOLLOW on the file, every
    parent checked), never outside folder."""
    target = folder
    for part in rel.split("/")[:-1]:
        target = target / part
        if target.is_symlink():
            raise OSError(f"link on the dump path: {rel}")
        target.mkdir(exist_ok=True)
    target = target / rel.split("/")[-1]
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(body)


def _md_cell(value) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _fold(rel: str) -> str:
    """The key two dump paths share when one filesystem would store them as one file: macOS (APFS,
    HFS+) and Windows ignore case, and APFS ignores Unicode normalization."""
    return unicodedata.normalize("NFC", rel).casefold()


def dump_image(image: ImageForensics, dest: Path) -> Path:
    """B-072: the layer dump. Writes `dest/image-<id12>/` with every file version as its layer added it
    (`layers/<NN>/<path>`), the raw image config (`config.json`), the full report (`report.json`) and an
    evidence index for a reader (`index.md`: labels, annotations, history with `created_by` and
    `comment`, and per layer the files it added or replaced, its whiteouts and what each deleted).
    Link entries are listed, never created: a symbolic link is not written; a hard link whose target is in
    the image is written as a plain file holding its target's bytes. Two versions whose dump paths differ
    only in case or Unicode normalization (`Foo`, `foo`), or repeat one path in one layer, would land on
    one file on a case-insensitive disk: the later one is written as `<path>~N` and listed under
    `dump.renamed`. Returns the image folder."""
    folder = Path(dest) / f"image-{image.identity()[:12]}"
    folder.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    renamed: list[dict] = []
    written: dict[str, str] = {}   # folded dump path -> the dump path written there
    for version in image.versions:
        if version.kind not in ("file", "hardlink"):   # a hard link is written as its target's bytes
            continue
        rel = f"layers/{version.layer:02d}/{version.path}"
        if _fold(rel) in written:
            clash, number = written[_fold(rel)], 1
            while _fold(f"{rel}~{number}") in written:
                number += 1
            renamed.append({"path": rel, "written_as": f"{rel}~{number}", "clashes_with": clash})
            rel = f"{rel}~{number}"
        written[_fold(rel)] = rel
        try:
            _write_new(folder, rel, version.content)
        except OSError as exc:
            errors.append(f"{rel}: {exc.__class__.__name__}: {exc}")
    image.meta["dump"] = {"folder": str(folder), "errors": errors, "renamed": renamed}
    report = image.report()
    _write_new(folder, "config.json", json.dumps(image.config, indent=2, sort_keys=True, default=str).encode())
    _write_new(folder, "report.json", json.dumps(report, indent=2, sort_keys=True).encode())
    lines = [f"# Image layer dump ({image.format})", "",
             f"{len(image.layers)} layer(s), {len(image.files)} file(s) in the final filesystem, "
             f"{len(image.versions)} file version(s), {len(image.recovered)} deleted or replaced.",
             "File versions are under `layers/<NN>/<path>`; `report.json` is the full report.", ""]
    for title, values in (("Labels", report["labels"]), ("Annotations", report["annotations"])):
        lines += [f"## {title}", ""]
        lines += [f"- `{_md_cell(key)}` = `{_md_cell(value)}`" for key, value in values.items()] or ["- none"]
        lines.append("")
    lines += ["## History", "", "| # | layer | created_by | comment |", "|---|---|---|---|"]
    for row in report["history"]:
        layer = "empty" if row["empty_layer"] else ("?" if row["layer"] is None else row["layer"])
        lines.append(f"| {row['index']} | {layer} | {_md_cell(row.get('created_by', ''))} | "
                     f"{_md_cell(row.get('comment', ''))} |")
    lines.append("")
    by_layer: dict[int, list[dict]] = {}
    for row in report["versions"]:
        by_layer.setdefault(row["layer"], []).append(row)
    for layer in report["layers"]:
        index = layer["index"]
        lines += [f"## Layer {index:02d}", "", f"- digest `{layer['digest']}`, diff_id `{layer['diff_id']}`"
                  + ("" if layer.get("diff_id_ok", True) else f" (config names `{layer.get('diff_id_expected')}`)")]
        if layer.get("created_by"):
            lines.append(f"- created_by: `{_md_cell(layer['created_by'])}`")
        if layer.get("comment"):
            lines.append(f"- comment: {_md_cell(layer['comment'])}")
        for whiteout in layer["whiteouts"]:
            kind = "opaque whiteout of" if whiteout["opaque"] else "whiteout of"
            lines.append(f"- {kind} `{_md_cell(whiteout['path'])}`, deleting "
                         + (", ".join(f"`{_md_cell(p)}`" for p in whiteout["deleted"]) or "nothing below"))
        lines += ["", "| path | size | sha256 | state |", "|---|---|---|---|"]
        for row in by_layer.get(index, []):
            state = row["reason"] + {
                "symlink": f" -> `{_md_cell(row['linkname'])}`",
                "hardlink": f", hard link to `{_md_cell(row['linkname'])}` (written as its bytes)",
                "hardlink-unresolved": f", hard link to `{_md_cell(row['linkname'])}`: target not found, not written",
            }.get(row.get("kind"), "")
            lines.append(f"| `{_md_cell(row['path'])}` | {row['size']} | {row['sha256'][:16]} | {state} |")
        lines.append("")
    if renamed:
        lines += ["## Written under another name", ""] + [
            f"- `{_md_cell(item['path'])}` is at `{_md_cell(item['written_as'])}`: its name clashes with "
            f"`{_md_cell(item['clashes_with'])}` on a case-insensitive disk" for item in renamed] + [""]
    if errors:
        lines += ["## Not written", ""] + [f"- {_md_cell(item)}" for item in errors] + [""]
    _write_new(folder, "index.md", "\n".join(lines).encode())
    return folder


def _yaml_documents(text: str) -> list:
    if yaml is None:
        return []

    class Loader(yaml.SafeLoader):
        pass

    def unknown(loader, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    Loader.add_constructor(None, unknown)
    try:
        return [item for item in yaml.load_all(text, Loader=Loader) if item is not None]
    except yaml.YAMLError:
        return []


def _walk(value, path: str = "$", depth: int = 0):
    if depth > 64:
        return
    yield path, value
    if isinstance(value, dict):
        for key, child in list(value.items())[:MAX_MEMBERS]:
            yield from _walk(child, f"{path}.{key}", depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value[:MAX_MEMBERS]):
            yield from _walk(child, f"{path}[{index}]", depth + 1)


def _secret_values(document, source: str) -> list[dict]:
    findings = []
    for path, value in _walk(document):
        key = path.rsplit(".", 1)[-1]
        if isinstance(value, str):
            findings.extend(scan_secret_bytes(value.encode(), source=source, path=path))
            if re.search(r"(?i)(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)$", key) and value:
                findings.append(_finding("iac-literal-secret", "high", "secret-named IaC field contains a literal value",
                                         source=source, path=path, key=key, value=value))
    return findings


def analyze_cloudformation(template: dict) -> list[dict]:
    if not isinstance(template, dict):
        return []
    findings = _secret_values(template, "cloudformation")
    for name, parameter in (template.get("Parameters", {}) if isinstance(template.get("Parameters"), dict) else {}).items():
        if not isinstance(parameter, dict):
            continue
        if re.search(r"(?i)(?:pass|secret|token|key)", str(name)):
            if parameter.get("NoEcho") is not True:
                findings.append(_finding("cfn-sensitive-parameter-visible", "high", "sensitive-looking parameter lacks NoEcho",
                                         source="cloudformation", object=f"Parameter/{name}"))
            if parameter.get("Default") not in (None, ""):
                findings.append(_finding("cfn-sensitive-default", "high", "sensitive parameter has a literal default",
                                         source="cloudformation", object=f"Parameter/{name}", value=parameter.get("Default")))
    resources = template.get("Resources", {}) if isinstance(template.get("Resources"), dict) else {}
    for name, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        typ = str(resource.get("Type", "")); props = resource.get("Properties", {})
        props = props if isinstance(props, dict) else {}
        identity = f"{typ}/{name}"
        if typ == "AWS::S3::Bucket":
            if props.get("AccessControl") in {"PublicRead", "PublicReadWrite", "AuthenticatedRead"}:
                findings.append(_finding("cfn-public-bucket", "critical", "S3 bucket uses a public ACL", source="cloudformation", object=identity))
            block = props.get("PublicAccessBlockConfiguration", {})
            if isinstance(block, dict) and any(block.get(key) is False for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                findings.append(_finding("cfn-public-access-block-disabled", "high", "S3 public-access protection is disabled", source="cloudformation", object=identity))
        if typ == "AWS::S3::BucketPolicy":
            policy = props.get("PolicyDocument", {})
            statements = policy.get("Statement", []) if isinstance(policy, dict) else []
            statements = statements if isinstance(statements, list) else [statements]
            for statement in statements:
                principal = statement.get("Principal") if isinstance(statement, dict) else None
                aws_principals = principal.get("AWS") if isinstance(principal, dict) else None
                public = (principal == "*" or aws_principals == "*"
                          or (isinstance(aws_principals, list) and "*" in aws_principals))
                if isinstance(statement, dict) and str(statement.get("Effect", "")).lower() == "allow" and public:
                    findings.append(_finding("cfn-public-bucket-policy", "critical", "S3 bucket policy allows a public principal",
                                             source="cloudformation", object=identity))
        if typ in {"AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"}:
            rules = props.get("SecurityGroupIngress", []) if typ.endswith("SecurityGroup") else [props]
            for rule in rules if isinstance(rules, list) else []:
                if isinstance(rule, dict) and (rule.get("CidrIp") == "0.0.0.0/0" or rule.get("CidrIpv6") == "::/0"):
                    findings.append(_finding("cfn-world-open-ingress", "high", "security group ingress is world-open", source="cloudformation", object=identity,
                                             from_port=rule.get("FromPort"), to_port=rule.get("ToPort"), protocol=rule.get("IpProtocol")))
        if typ.startswith("AWS::RDS::") and props.get("PubliclyAccessible") is True:
            findings.append(_finding("cfn-public-database", "high", "database is publicly accessible", source="cloudformation", object=identity))
        if typ in {"AWS::IAM::Role", "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}:
            for path, value in _walk(props):
                wildcard = value == "*" or (isinstance(value, list) and "*" in value)
                if path.endswith(".Action") and wildcard:
                    findings.append(_finding("cfn-iam-wildcard", "critical", "IAM policy grants wildcard actions", source="cloudformation", object=identity, path=path))
        if typ == "AWS::Lambda::Function" and props.get("Environment"):
            findings.extend(_secret_values(props.get("Environment"), identity))
        if props.get("UserData"):
            findings.append(_finding("cfn-userdata", "medium", "instance user-data is embedded in the template", source="cloudformation", object=identity))
    return findings


def _pod_spec(obj: dict):
    spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else None
    if not spec:
        return None
    if obj.get("kind") == "Pod":
        return spec
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    return template.get("spec") if isinstance(template.get("spec"), dict) else None


def analyze_k8s_manifests(documents: list) -> list[dict]:
    findings = []
    queue = list(documents) if isinstance(documents, list) else []
    while queue:
        obj = queue.pop(0)
        if not isinstance(obj, dict):
            continue
        if str(obj.get("kind", "")).endswith("List") and isinstance(obj.get("items"), list):
            queue.extend(obj["items"]); continue
        kind = str(obj.get("kind", "")); meta = obj.get("metadata", {}) if isinstance(obj.get("metadata"), dict) else {}
        identity = f"{kind}/{meta.get('namespace', 'default')}/{meta.get('name', '')}"
        if kind == "Secret":
            for field in ("data", "stringData"):
                values = obj.get(field, {}) if isinstance(obj.get(field), dict) else {}
                for key, value in values.items():
                    decoded = None
                    if field == "data" and isinstance(value, str):
                        try:
                            decoded = base64.b64decode(value, validate=True).decode("utf-8", "replace")
                        except Exception:
                            decoded = None
                    findings.append(_finding("k8s-secret-in-manifest", "high", "Kubernetes Secret value is present in a supplied manifest",
                                             source="kubernetes", object=identity, key=key,
                                             value=decoded if decoded is not None else value, encoding="base64" if field == "data" else "plain"))
        if kind == "ConfigMap":
            findings.extend(_secret_values(obj.get("data", {}), identity))
        spec = _pod_spec(obj)
        if not spec:
            continue
        if spec.get("hostNetwork") or spec.get("hostPID") or spec.get("hostIPC"):
            findings.append(_finding("k8s-host-namespace", "high", "workload shares a host namespace", source="kubernetes", object=identity))
        if spec.get("automountServiceAccountToken") is not False:
            findings.append(_finding("k8s-token-automount", "low", "service-account token automount is not disabled", source="kubernetes", object=identity))
        for volume in spec.get("volumes", []) if isinstance(spec.get("volumes"), list) else []:
            if isinstance(volume, dict) and isinstance(volume.get("hostPath"), dict):
                findings.append(_finding("k8s-hostpath", "critical" if volume["hostPath"].get("path") in {"/", "/var/run/docker.sock", "/run/containerd/containerd.sock"} else "high",
                                         "workload mounts a host path", source="kubernetes", object=identity,
                                         path=volume["hostPath"].get("path")))
        for field in ("initContainers", "containers", "ephemeralContainers"):
            for container in spec.get(field, []) if isinstance(spec.get(field), list) else []:
                if not isinstance(container, dict):
                    continue
                label = f"{identity}:{field}/{container.get('name', '')}"
                context = container.get("securityContext", {}) if isinstance(container.get("securityContext"), dict) else {}
                if context.get("privileged") is True:
                    findings.append(_finding("k8s-privileged-container", "critical", "container is privileged", source="kubernetes", object=label))
                if context.get("allowPrivilegeEscalation") is not False:
                    findings.append(_finding("k8s-escalation-not-disabled", "medium", "allowPrivilegeEscalation is not disabled", source="kubernetes", object=label))
                for env in container.get("env", []) if isinstance(container.get("env"), list) else []:
                    if isinstance(env, dict) and env.get("value") and re.search(r"(?i)(?:pass|secret|token|key)", str(env.get("name", ""))):
                        findings.append(_finding("k8s-env-secret", "high", "secret-named environment variable has a literal value",
                                                 source="kubernetes", object=label, key=env.get("name"), value=env.get("value")))
    return findings


def _strip_hcl_comments(text: str) -> str:
    """Mask HCL comments without treating // or # inside quoted strings as comments."""
    out = list(text)
    state, quote, index = "code", "", 0
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "#" or (char == "/" and following == "/"):
                out[index] = " "
                if char == "/":
                    out[index + 1] = " "
                    index += 1
                state = "line"
            elif char == "/" and following == "*":
                out[index] = out[index + 1] = " "
                index += 1
                state = "block"
            elif char in "'\"":
                quote, state = char, "string"
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
        elif state == "block":
            if char == "*" and following == "/":
                out[index] = out[index + 1] = " "
                index += 1
                state = "code"
            elif char != "\n":
                out[index] = " "
        else:
            if char == "\\" and index + 1 < len(text):
                index += 1
            elif char == quote:
                state = "code"
        index += 1
    return "".join(out)


def analyze_terraform_text(text: str) -> list[dict]:
    findings = []
    masked = _strip_hcl_comments(text)
    patterns = (
        ("terraform-provider-credential", "critical", r"(?i)\b(?:access_key|secret_key|token|client_secret)\s*=\s*\"([^\"]+)\"", "provider/backend embeds a credential"),
        ("terraform-public-acl", "high", r"(?i)\bacl\s*=\s*\"(?:public-read|public-read-write)\"", "resource uses a public ACL"),
        ("terraform-world-open", "high", r"(?i)(?:0\.0\.0\.0/0|::/0)", "resource includes a world-open network CIDR"),
        ("terraform-iam-wildcard", "critical", r"(?i)\"Action\"\s*:\s*(?:\"\*\"|\[\s*\"\*\")", "embedded IAM policy grants wildcard actions"),
        ("terraform-k8s-privileged", "critical", r"(?im)^\s*privileged\s*=\s*true\b", "Kubernetes container is privileged"),
        ("terraform-k8s-hostpath", "high", r"(?im)^\s*host_path\s*\{", "Kubernetes workload declares a hostPath volume"),
    )
    for kind, severity, pattern, message in patterns:
        for match in re.finditer(pattern, masked):
            findings.append(_finding(kind, severity, message, source="terraform-hcl",
                                     line=masked.count("\n", 0, match.start()) + 1,
                                     value=match.group(1) if match.lastindex else None))
    return findings


def analyze_terraform_json(document: dict) -> list[dict]:
    findings = _secret_values(document, "terraform-json")
    if isinstance(document.get("resource_changes"), list):
        for change in document["resource_changes"]:
            if not isinstance(change, dict):
                continue
            address = change.get("address")
            change_block = change.get("change")
            values = change_block.get("after") if isinstance(change_block, dict) else None
            if values is not None:
                findings.extend(_secret_values(values, str(address)))
    if isinstance(document.get("resources"), list):  # state
        for resource in document["resources"]:
            if not isinstance(resource, dict):
                continue
            identity = f"{resource.get('type')}.{resource.get('name')}"
            for instance in resource.get("instances", []) if isinstance(resource.get("instances"), list) else []:
                if isinstance(instance, dict):
                    findings.extend(_secret_values(instance.get("attributes", {}), identity))
    return findings


def analyze_iac_artifact(data: bytes, name: str = "") -> dict:
    if len(data) > MAX_MEMBER:
        raise ValueError("IaC artifact exceeds cap")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("IaC artifact is not valid UTF-8") from exc
    documents = []
    try:
        parsed = json.loads(text)
        documents = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        documents = _yaml_documents(text)
    findings: list[dict] = []
    kinds = set()
    for document in documents:
        if not isinstance(document, dict):
            continue
        resources = document.get("Resources", {})
        has_aws_resources = isinstance(resources, dict) and any(
            isinstance(value, dict) and str(value.get("Type", "")).startswith("AWS::")
            for value in resources.values())
        if "AWSTemplateFormatVersion" in document or has_aws_resources:
            kinds.add("cloudformation"); findings.extend(analyze_cloudformation(document))
        if document.get("apiVersion") and document.get("kind"):
            kinds.add("kubernetes"); findings.extend(analyze_k8s_manifests([document]))
        if any(key in document for key in ("terraform_version", "resource_changes", "planned_values")):
            kinds.add("terraform-json"); findings.extend(analyze_terraform_json(document))
    if name.lower().endswith(".tf") or re.search(r"(?m)^\s*(?:resource|provider|terraform|module)\s+\"", text):
        kinds.add("terraform-hcl"); findings.extend(analyze_terraform_text(text))
    if not kinds:
        kinds.add("generic-structured" if documents else "generic-text")
        findings.extend(_secret_values(documents, "structured") if documents else scan_secret_bytes(data, source="text", path=name or "artifact"))
    return {"formats": sorted(kinds), "document_count": len(documents), "findings": _sort(findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline OCI/Docker forensics and IaC exposure analysis")
    parser.add_argument("mode", choices=("image", "iac"))
    parser.add_argument("artifact", type=Path,
                        help="image: a docker-save or OCI-layout tar, an unpacked layout folder, or its "
                             "oci-layout / index.json / manifest.json file; iac: the artifact")
    parser.add_argument("--dump", type=Path, metavar="DIR",
                        help="image: write every file version per layer, config, report and index.md "
                             "under DIR/image-<id>/")
    parser.add_argument("--pretty", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0
    try:
        if args.mode == "image":
            image = analyze_image_path(args.artifact)
            if args.dump is not None:
                dump_image(image, args.dump)
            report = image.report()
        else:
            if args.dump is not None:
                parser.error("--dump applies to image mode only")
            report = analyze_iac_artifact(args.artifact.read_bytes(), args.artifact.name)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0
    except (ValueError, OSError) as exc:
        print(f"container_iac: {args.mode} {args.artifact}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
