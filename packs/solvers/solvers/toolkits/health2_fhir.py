#!/usr/bin/env python3
"""Offline FHIR R4 JSON evidence: local references, attachments and SampledData.

Complements healthcare.py's text/XML scanner. This is deliberately not a FHIR
schema validator, a server, or a clinical interpreter. No URLs are fetched.
Reference resolution follows R4 Bundle 2.36.4.1, with ambiguity surfaced rather
than guessed. XML, conditional/identifier references and R5 SampledData interval
are outside this module's supported profile.

  ./.venv/bin/python solvers/toolkits/health2_fhir.py bundle.json --extract-dir out

Public functions raise only FHIRFormatError for malformed/unsupported input.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import math
import re
import sys
from functools import wraps
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 32 * 1024 * 1024
MAX_NODES = 100_000
MAX_SAMPLES = 1_000_000
MAX_DEPTH = 64
_ID = r"[A-Za-z0-9\-.]{1,64}"
_RELATIVE = re.compile(rf"[A-Z][A-Za-z0-9]*/{_ID}(?:/_history/{_ID})?")
_REST = re.compile(rf"(https?://[^?#]+/)[A-Z][A-Za-z0-9]*/{_ID}")
_DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_FLAGS = flagfmt.BYTES


class FHIRFormatError(ValueError):
    """Malformed, unsupported or over-limit FHIR evidence."""


def _guard(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except FHIRFormatError:
            raise
        except Exception as exc:
            raise FHIRFormatError(f"{function.__name__}: invalid input ({type(exc).__name__})") from None
    return wrapped


def _string(value, name, allow_empty=False):
    if not isinstance(value, str) or (not value and not allow_empty):
        raise FHIRFormatError(f"{name} must be a string")
    return value


def _finite(value, name):
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise FHIRFormatError(f"{name} must be a number")
    out = float(value)
    if not math.isfinite(out):
        raise FHIRFormatError(f"{name} must be finite")
    return out


@_guard
def decode_base64(value):
    """Decode standard Base64, allowing only ASCII transport whitespace.

    Padding, alphabet and unused pad bits are checked; URL-safe input and guessed
    padding are rejected. Decoding never executes the resulting bytes.
    """
    value = _string(value, "base64", allow_empty=True)
    if len(value) > MAX_INPUT:
        raise FHIRFormatError("base64 exceeds input limit")
    compact = re.sub(r"[ \t\r\n]", "", value)
    decoded = base64.b64decode(compact, validate=True)
    if base64.b64encode(decoded).decode("ascii") != compact:
        raise FHIRFormatError("non-canonical base64 padding or pad bits")
    return decoded


@_guard
def decode_sampled_data(value):
    """Decode R4 time-interleaved samples as rows, preserving E/L/U markers.

    Numeric values are raw * factor + origin.value, in origin units. Markers
    remain strings; no substitute number or clinical interpretation is invented.
    """
    if not isinstance(value, dict) or not isinstance(value.get("origin"), dict):
        raise FHIRFormatError("SampledData needs origin")
    origin = _finite(value["origin"].get("value"), "origin.value")
    unit = value["origin"].get("unit")
    if "unit" in value["origin"]:
        _string(unit, "origin.unit")
    factor = _finite(value.get("factor", 1), "factor")
    period = _finite(value.get("period"), "period")
    dimensions = value.get("dimensions")
    if type(dimensions) is not int or not 1 <= dimensions <= 1024 or period <= 0:
        raise FHIRFormatError("invalid dimensions or period")
    lower = None if "lowerLimit" not in value else _finite(value["lowerLimit"], "lowerLimit")
    upper = None if "upperLimit" not in value else _finite(value["upperLimit"], "upperLimit")
    if lower is not None and upper is not None and lower > upper:
        raise FHIRFormatError("inverted SampledData limits")
    data = _string(value.get("data", ""), "SampledData.data", allow_empty=True)
    if len(data) > MAX_INPUT:
        raise FHIRFormatError("sample text exceeds input limit")
    tokens = data.split(" ") if data else []
    if len(tokens) > MAX_SAMPLES or len(tokens) % dimensions:
        raise FHIRFormatError("sample count exceeds limit or is not divisible by dimensions")
    samples = []
    for token in tokens:
        if token in ("E", "L", "U"):
            samples.append(token)
        else:
            if not _DECIMAL.fullmatch(token):
                raise FHIRFormatError("invalid sample token")
            number = float(token) * factor + origin
            if not math.isfinite(number):
                raise FHIRFormatError("non-finite scaled sample")
            samples.append(number)
    rows = [samples[i:i + dimensions] for i in range(0, len(samples), dimensions)]
    if rows and not math.isfinite((len(rows) - 1) * period):
        raise FHIRFormatError("sample timestamps overflow")
    return {"dimensions": dimensions, "period_ms": period, "origin": origin,
            "factor": factor, "unit": unit,
            "lower_limit": lower, "upper_limit": upper,
            "sample_count": len(rows), "rows": rows}


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise FHIRFormatError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _reject_constant(_):
    raise FHIRFormatError("non-finite JSON number")


def _load(data):
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_INPUT:
            raise FHIRFormatError("file exceeds input limit")
        data = bytes(data).decode("utf-8")
    if isinstance(data, str):
        if len(data.encode("utf-8")) > MAX_INPUT:
            raise FHIRFormatError("file exceeds input limit")
        data = json.loads(data, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    if not isinstance(data, dict):
        raise FHIRFormatError("expected a FHIR JSON resource object")
    # Bound dict callers as well as files; cycles fail by depth/node limits.
    stack, count, text_bytes = [(data, 0)], 0, 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise FHIRFormatError("JSON tree exceeds node or depth limit")
        if isinstance(node, dict):
            for key, item in node.items():
                if not isinstance(key, str):
                    raise FHIRFormatError("JSON keys must be strings")
                text_bytes += len(key.encode("utf-8"))
                stack.append((item, depth + 1))
        elif isinstance(node, list):
            stack.extend((item, depth + 1) for item in node)
        elif isinstance(node, str):
            text_bytes += len(node.encode("utf-8"))
        elif node is not None and type(node) not in (bool, int, float):
            raise FHIRFormatError("non-JSON object")
        elif isinstance(node, (int, float)) and not math.isfinite(float(node)):
            raise FHIRFormatError("non-finite JSON number")
        if text_bytes > MAX_INPUT:
            raise FHIRFormatError("JSON text exceeds input limit")
    return data


def _resource(resource):
    if not isinstance(resource, dict) or not re.fullmatch(r"[A-Z][A-Za-z0-9]+", resource.get("resourceType", "")):
        raise FHIRFormatError("missing or invalid resourceType")
    if "id" in resource and not re.fullmatch(_ID, _string(resource["id"], "id")):
        raise FHIRFormatError("invalid resource id")
    if "meta" in resource and not isinstance(resource["meta"], dict):
        raise FHIRFormatError("meta must be an object")


def _entries(root):
    records = []

    def add(resource, path, full_url, scope, container=None):
        _resource(resource)
        record = {"resource": resource, "path": path, "fullUrl": full_url,
                  "scope": scope, "container": container}
        records.append(record)
        if resource["resourceType"] == "Bundle":
            if container is not None:
                raise FHIRFormatError("contained Bundle unsupported")
            entries = resource.get("entry", [])
            if not isinstance(entries, list):
                raise FHIRFormatError("Bundle.entry must be an array")
            for i, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    raise FHIRFormatError("Bundle entry must be an object")
                url = entry.get("fullUrl")
                if url is not None:
                    _string(url, "fullUrl")
                    if "/_history/" in url:
                        raise FHIRFormatError("fullUrl cannot contain a version")
                if "resource" in entry:
                    add(entry["resource"], f"{path}/entry/{i}/resource", url, path)
        contained = resource.get("contained", [])
        if not isinstance(contained, list):
            raise FHIRFormatError("contained must be an array")
        if container is not None and contained:
            raise FHIRFormatError("nested contained resources are not allowed")
        ids = set()
        for i, item in enumerate(contained):
            if not isinstance(item, dict) or not item.get("id") or item["id"] in ids:
                raise FHIRFormatError("contained resource needs a unique id")
            ids.add(item["id"])
            add(item, f"{path}/contained/{i}", None, scope, path)

    add(root, "", None, None)
    return records


def _resolve(reference, source, index, contained_index, by_path):
    _string(reference, "reference")
    if reference.startswith("#"):
        owner = source["container"] if source["container"] is not None else source["path"]
        if reference == "#":
            matches = [by_path[owner]] if source["container"] is not None else []
        else:
            matches = contained_index.get((owner, reference[1:]), [])
    else:
        target = reference
        if _RELATIVE.fullmatch(target):
            owner = by_path[source["container"]] if source["container"] is not None else source
            base = _REST.fullmatch(owner["fullUrl"] or "")
            if not base:
                return {"status": "unresolved", "reason": "relative reference has no RESTful base", "targets": []}
            target = base[1] + target
        version = None
        if "/_history/" in target:
            target, version = target.rsplit("/_history/", 1)
        matches = list(index.get((source["scope"], target), []))
        if version is not None:
            matches = [r for r in matches if r["resource"].get("meta", {}).get("versionId") == version]
    return {"status": "resolved" if len(matches) == 1 else "ambiguous" if matches else "unresolved",
            "targets": [r["path"] for r in matches]}


@_guard
def parse_fhir(data):
    """Inspect a JSON resource/Bundle supplied as UTF-8 bytes, text or a dict.

    Returns resources, reference results, blobs (with original bytes), decoded
    SampledData and flag-format hits from those decoded blobs only. All JSON
    Pointer paths refer to the supplied artifact. No network access is attempted.
    """
    root = _load(data)
    records = _entries(root)
    index, contained_index, by_path = {}, {}, {r["path"]: r for r in records}
    for record in records:
        if record["fullUrl"] is not None:
            index.setdefault((record["scope"], record["fullUrl"]), []).append(record)
        if record["container"] is not None:
            contained_index.setdefault((record["container"], record["resource"]["id"]), []).append(record)
    report = {"kind": "fhir-r4-json", "resources": [], "references": [],
              "blobs": [], "sampled_data": [], "flags": []}
    total_samples = 0
    for record in records:
        resource = record["resource"]
        report["resources"].append({"path": record["path"], "resourceType": resource["resourceType"],
                                    "id": resource.get("id"), "fullUrl": record["fullUrl"],
                                    "version": resource.get("meta", {}).get("versionId")})
        stack = [(resource, record["path"], "")]
        while stack:
            node, path, key = stack.pop()
            if isinstance(node, dict):
                if path != record["path"] and "resourceType" in node:
                    continue  # separately indexed resource, never scan twice
                if "reference" in node:
                    result = _resolve(node["reference"], record, index, contained_index, by_path)
                    report["references"].append({"path": path + "/reference", "reference": node["reference"], **result})
                attachment = (key in {"attachment", "valueAttachment", "presentedForm", "photo"} or
                              ("contentType" in node and ("data" in node or "url" in node)))
                if resource["resourceType"] == "Binary" and node is resource:
                    attachment = True
                if attachment:
                    if "url" in node:
                        result = _resolve(node["url"], record, index, contained_index, by_path)
                        report["references"].append({"path": path + "/url", "reference": node["url"],
                                                     "kind": "attachment-url", **result})
                    if "data" in node:
                        mime = _string(node.get("contentType"), "attachment.contentType")
                        payload = decode_base64(node["data"])
                        if "size" in node and (type(node["size"]) is not int or node["size"] != len(payload)):
                            raise FHIRFormatError("attachment size does not match decoded bytes")
                        if "hash" in node and decode_base64(node["hash"]) != hashlib.sha1(payload).digest():
                            raise FHIRFormatError("attachment SHA-1 does not match decoded bytes")
                        report["blobs"].append({"path": path, "contentType": mime, "data": payload,
                                                "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
                        report["flags"].extend(hit.decode("ascii", "replace") for hit in _FLAGS.findall(payload))
                if key == "valueSampledData":
                    samples = decode_sampled_data(node)
                    total_samples += samples["sample_count"] * samples["dimensions"]
                    if total_samples > MAX_SAMPLES:
                        raise FHIRFormatError("combined sample count exceeds limit")
                    report["sampled_data"].append({"path": path, **samples})
                for child_key, child in reversed(list(node.items())):
                    if node is resource and (child_key == "contained" or
                                              (child_key == "entry" and resource["resourceType"] == "Bundle")):
                        continue
                    escaped = child_key.replace("~", "~0").replace("/", "~1")
                    stack.append((child, path + "/" + escaped, child_key))
            elif isinstance(node, list):
                stack.extend((child, f"{path}/{i}", key) for i, child in reversed(list(enumerate(node))))
    report["flags"] = list(dict.fromkeys(report["flags"]))
    return report


@_guard
def extract_report(report, directory):
    """Write numbered inert blobs and sample CSVs; refuse existing output names."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    output = []
    for i, blob in enumerate(report["blobs"]):
        target = directory / f"blob-{i:04d}.bin"
        with target.open("xb") as stream:
            stream.write(blob["data"])
        output.append(str(target))
    for i, sample in enumerate(report["sampled_data"]):
        target = directory / f"samples-{i:04d}.csv"
        with target.open("x", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["time_ms"] + [f"dimension_{n}" for n in range(sample["dimensions"])])
            for n, row in enumerate(sample["rows"]):
                writer.writerow([n * sample["period_ms"], *row])
        output.append(str(target))
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="FHIR R4 JSON resource or Bundle")
    parser.add_argument("--extract-dir", help="write decoded blobs and waveform CSVs here")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.file).open("rb") as stream:
            data = stream.read(MAX_INPUT + 1)
        report = parse_fhir(data)
        if args.extract_dir:
            report["written"] = extract_report(report, args.extract_dir)
        for blob in report["blobs"]:
            del blob["data"]
        for sample in report["sampled_data"]:
            sample["preview_rows"] = sample.pop("rows")[:16]
        print(json.dumps(report, indent=2, allow_nan=False))
        return 0
    except (FHIRFormatError, OSError) as exc:
        print(f"health2_fhir: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
