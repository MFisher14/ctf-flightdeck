#!/usr/bin/env python3
"""Strict offline Solana IDL 0.1.0 and program-account analysis.

The engine consumes only caller-supplied JSON and bytes.  It deliberately does
not fetch an IDL, query RPC, derive a PDA, verify a signature, or execute a
program.  IDL discriminators are variable-length byte strings; values published
by the IDL always take precedence over framework conventions.
"""
from __future__ import annotations

import argparse
import functools
import json
import math
import re
import struct
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable

import blockchain as _chain


MAX_IDL_BYTES = 8 * 1024 * 1024
MAX_DATA_BYTES = 16 * 1024 * 1024
MAX_TREE_NODES = 200_000
MAX_ITEMS = 10_000
MAX_ACCOUNTS = 256
MAX_NESTING = 64
MAX_DISCRIMINATOR = 64
MAX_DYNAMIC_ITEMS = 100_000
MAX_DYNAMIC_BYTES = 8 * 1024 * 1024

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PATH = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_PRIMITIVES = {
    "bool", "u8", "i8", "u16", "i16", "u32", "i32", "f32", "u64", "i64",
    "f64", "u128", "i128", "u256", "i256", "bytes", "string", "pubkey",
}
_INT_WIDTHS = {
    "u8": (1, False), "i8": (1, True), "u16": (2, False), "i16": (2, True),
    "u32": (4, False), "i32": (4, True), "u64": (8, False), "i64": (8, True),
    "u128": (16, False), "i128": (16, True), "u256": (32, False),
    "i256": (32, True),
}


class SolanaIDLAnalysisError(ValueError):
    """The sole exception raised by public analysis APIs."""


def _public_api(function: Callable[..., Any]) -> Callable[..., Any]:
    """Translate all ordinary implementation/parser failures to the contract error."""

    @functools.wraps(function)
    def wrapped(*args: object, **kwargs: object) -> Any:
        try:
            return function(*args, **kwargs)
        except SolanaIDLAnalysisError:
            raise
        except Exception as exc:  # fail closed at the public boundary
            raise SolanaIDLAnalysisError(f"{function.__name__}: invalid input") from exc

    return wrapped


def _fail(message: str) -> None:
    raise SolanaIDLAnalysisError(message)


def _check_tree(root: object) -> None:
    """Bound an in-memory JSON-shaped tree before recursive validation."""

    stack = [root]
    seen: set[int] = set()
    nodes = 0
    size = 0
    while stack:
        value = stack.pop()
        nodes += 1
        if nodes > MAX_TREE_NODES:
            _fail("IDL tree exceeds node cap")
        if isinstance(value, str):
            size += len(value.encode("utf-8", "strict"))
        elif value is None or type(value) in (bool, int, float):
            size += 16
        elif isinstance(value, Mapping):
            identity = id(value)
            if identity in seen:
                _fail("IDL contains a cyclic or shared container")
            seen.add(identity)
            if len(value) > MAX_ITEMS:
                _fail("IDL object exceeds item cap")
            for key, child in value.items():
                if not isinstance(key, str):
                    _fail("IDL object keys must be strings")
                stack.extend((key, child))
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            identity = id(value)
            if identity in seen:
                _fail("IDL contains a cyclic or shared container")
            seen.add(identity)
            if len(value) > MAX_ITEMS:
                _fail("IDL array exceeds item cap")
            stack.extend(value)
        else:
            _fail("IDL must contain JSON-compatible values")
        if size > MAX_IDL_BYTES:
            _fail("IDL exceeds size cap")


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _fail(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        _fail(f"{label} keys must be strings")
    return value


def _array(value: object, label: str, limit: int = MAX_ITEMS) -> list[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _fail(f"{label} must be an array")
    if len(value) > limit:
        _fail(f"{label} exceeds item cap")
    return list(value)


def _keys(value: Mapping[str, object], *, required: set[str], allowed: set[str], label: str) -> None:
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing:
        _fail(f"{label} is missing {', '.join(sorted(missing))}")
    if unknown:
        _fail(f"{label} has unknown fields: {', '.join(sorted(unknown))}")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        _fail(f"{label} must be non-empty bounded text")
    return value


def _name(value: object, label: str) -> str:
    text = _text(value, label)
    if not _NAME.fullmatch(text):
        _fail(f"{label} is not an identifier")
    return text


def _docs(value: object, label: str) -> list[str]:
    rows = _array(value, label)
    if any(not isinstance(row, str) or len(row.encode("utf-8")) > 65536 for row in rows):
        _fail(f"{label} must contain bounded strings")
    return list(rows)  # type: ignore[return-value]


def _bool_field(value: Mapping[str, object], key: str, label: str) -> bool:
    result = value.get(key, False)
    if type(result) is not bool:
        _fail(f"{label}.{key} must be boolean")
    return result


def _pubkey(value: object, label: str) -> str:
    text = _text(value, label)
    raw = _chain.b58decode(text)
    if raw is None or len(raw) != 32 or _chain.b58encode(raw) != text:
        _fail(f"{label} must be a canonical 32-byte base58 public key")
    return text


def _discriminator(value: object, label: str) -> bytes:
    rows = _array(value, label, MAX_DISCRIMINATOR)
    if not rows:
        _fail(f"{label} must not be empty")
    if any(type(byte) is not int or not 0 <= byte <= 255 for byte in rows):
        _fail(f"{label} must contain byte integers")
    return bytes(rows)


def _unique_name(rows: list[Mapping[str, object]], label: str) -> None:
    names: set[str] = set()
    for row in rows:
        name = str(row["name"])
        if name in names:
            _fail(f"duplicate {label} name {name!r}")
        names.add(name)


def _validate_type_ref(value: object, label: str, depth: int = 0) -> object:
    if depth > MAX_NESTING:
        _fail(f"{label} nesting exceeds cap")
    if isinstance(value, str):
        if value not in _PRIMITIVES:
            _fail(f"{label} has unknown primitive {value!r}")
        return value
    row = _object(value, label)
    if len(row) != 1:
        _fail(f"{label} container type must have exactly one tag")
    tag, payload = next(iter(row.items()))
    if tag in {"option", "vec"}:
        return {tag: _validate_type_ref(payload, f"{label}.{tag}", depth + 1)}
    if tag == "array":
        pair = _array(payload, f"{label}.array", 2)
        if len(pair) != 2:
            _fail(f"{label}.array requires a type and length")
        item_type = _validate_type_ref(pair[0], f"{label}.array.type", depth + 1)
        length = pair[1]
        if type(length) is int:
            if not 0 <= length <= MAX_DYNAMIC_ITEMS:
                _fail(f"{label}.array length is out of range")
        else:
            generic = _object(length, f"{label}.array.length")
            _keys(generic, required={"generic"}, allowed={"generic"}, label=f"{label}.array.length")
            _name(generic["generic"], f"{label}.array.length.generic")
            length = {"generic": generic["generic"]}
        return {"array": [item_type, length]}
    if tag == "generic":
        return {"generic": _name(payload, f"{label}.generic")}
    if tag == "defined":
        defined = _object(payload, f"{label}.defined")
        _keys(defined, required={"name"}, allowed={"name", "generics"}, label=f"{label}.defined")
        name = _name(defined["name"], f"{label}.defined.name")
        generics = []
        for index, item in enumerate(_array(defined.get("generics", []), f"{label}.defined.generics")):
            arg = _object(item, f"{label}.defined.generics[{index}]")
            kind = arg.get("kind")
            if kind == "type":
                _keys(arg, required={"kind", "type"}, allowed={"kind", "type"},
                      label=f"{label}.defined.generics[{index}]")
                generics.append({"kind": "type", "type": _validate_type_ref(
                    arg["type"], f"{label}.defined.generics[{index}].type", depth + 1)})
            elif kind == "const":
                _keys(arg, required={"kind", "value"}, allowed={"kind", "value"},
                      label=f"{label}.defined.generics[{index}]")
                generics.append({"kind": "const", "value": _text(
                    arg["value"], f"{label}.defined.generics[{index}].value")})
            else:
                _fail(f"{label}.defined generic has unknown kind")
        result: dict[str, object] = {"name": name}
        if generics:
            result["generics"] = generics
        return {"defined": result}
    _fail(f"{label} has unknown type tag {tag!r}")


def _validate_fields(value: object, label: str) -> list[object]:
    rows = _array(value, label)
    if not rows:
        return []
    named = isinstance(rows[0], Mapping) and "name" in rows[0]
    normalized: list[object] = []
    names: set[str] = set()
    for index, item in enumerate(rows):
        if named:
            row = _object(item, f"{label}[{index}]")
            _keys(row, required={"name", "type"}, allowed={"name", "type", "docs"},
                  label=f"{label}[{index}]")
            name = _name(row["name"], f"{label}[{index}].name")
            if name in names:
                _fail(f"{label} contains duplicate field {name!r}")
            names.add(name)
            if "docs" in row:
                _docs(row["docs"], f"{label}[{index}].docs")
            normalized.append({"name": name, "type": _validate_type_ref(
                row["type"], f"{label}[{index}].type")})
        else:
            if isinstance(item, Mapping) and "name" in item:
                _fail(f"{label} mixes named and tuple fields")
            normalized.append(_validate_type_ref(item, f"{label}[{index}]"))
    return normalized


def _validate_serialization(value: object, label: str) -> object:
    if isinstance(value, str) and value in {"borsh", "bytemuck", "bytemuckunsafe"}:
        return value
    if isinstance(value, Mapping):
        _keys(value, required={"custom"}, allowed={"custom"}, label=label)
        return {"custom": _text(value["custom"], f"{label}.custom")}
    _fail(f"{label} is not a recognized serialization")


def _validate_repr(value: object, label: str) -> dict[str, object]:
    row = _object(value, label)
    kind = row.get("kind")
    if kind == "transparent":
        _keys(row, required={"kind"}, allowed={"kind"}, label=label)
        return {"kind": kind}
    if kind not in {"rust", "c"}:
        _fail(f"{label} has unknown representation")
    _keys(row, required={"kind"}, allowed={"kind", "packed", "align"}, label=label)
    result: dict[str, object] = {"kind": kind}
    if "packed" in row:
        if type(row["packed"]) is not bool:
            _fail(f"{label}.packed must be boolean")
        result["packed"] = row["packed"]
    if "align" in row:
        align = row["align"]
        if type(align) is not int or align <= 0 or align > 65536:
            _fail(f"{label}.align is invalid")
        result["align"] = align
    return result


def _validate_type_defs(value: object) -> list[dict[str, object]]:
    rows = _array(value, "types")
    normalized: list[dict[str, object]] = []
    for index, item in enumerate(rows):
        row = _object(item, f"types[{index}]")
        _keys(row, required={"name", "type"},
              allowed={"name", "type", "docs", "serialization", "repr", "generics"},
              label=f"types[{index}]")
        name = _name(row["name"], f"types[{index}].name")
        if "docs" in row:
            _docs(row["docs"], f"types[{index}].docs")
        serialization = _validate_serialization(row.get("serialization", "borsh"),
                                                f"types[{index}].serialization")
        generics = []
        for gindex, item_generic in enumerate(_array(row.get("generics", []),
                                                      f"types[{index}].generics")):
            generic = _object(item_generic, f"types[{index}].generics[{gindex}]")
            kind = generic.get("kind")
            if kind == "type":
                _keys(generic, required={"kind", "name"}, allowed={"kind", "name"},
                      label=f"types[{index}].generics[{gindex}]")
                generics.append({"kind": "type", "name": _name(
                    generic["name"], f"types[{index}].generics[{gindex}].name")})
            elif kind == "const":
                _keys(generic, required={"kind", "name", "type"},
                      allowed={"kind", "name", "type"},
                      label=f"types[{index}].generics[{gindex}]")
                generics.append({"kind": "const", "name": _name(
                    generic["name"], f"types[{index}].generics[{gindex}].name"),
                    "type": _text(generic["type"], f"types[{index}].generics[{gindex}].type")})
            else:
                _fail(f"types[{index}] generic has unknown kind")
        shape = _object(row["type"], f"types[{index}].type")
        kind = shape.get("kind")
        if kind == "struct":
            _keys(shape, required={"kind"}, allowed={"kind", "fields"}, label=f"types[{index}].type")
            normalized_shape = {"kind": "struct", "fields": _validate_fields(
                shape.get("fields", []), f"types[{index}].type.fields")}
        elif kind == "enum":
            _keys(shape, required={"kind", "variants"}, allowed={"kind", "variants"},
                  label=f"types[{index}].type")
            variants = []
            for vindex, variant_value in enumerate(_array(shape["variants"],
                                                           f"types[{index}].type.variants", 256)):
                variant = _object(variant_value, f"types[{index}].type.variants[{vindex}]")
                _keys(variant, required={"name"}, allowed={"name", "fields"},
                      label=f"types[{index}].type.variants[{vindex}]")
                variants.append({"name": _name(variant["name"],
                                                 f"types[{index}].type.variants[{vindex}].name"),
                                 "fields": _validate_fields(variant.get("fields", []),
                                                             f"types[{index}].type.variants[{vindex}].fields")})
            if len({str(item["name"]) for item in variants}) != len(variants):
                _fail(f"types[{index}] has duplicate enum variants")
            normalized_shape = {"kind": "enum", "variants": variants}
        elif kind == "type":
            _keys(shape, required={"kind", "alias"}, allowed={"kind", "alias"},
                  label=f"types[{index}].type")
            normalized_shape = {"kind": "type", "alias": _validate_type_ref(
                shape["alias"], f"types[{index}].type.alias")}
        else:
            _fail(f"types[{index}] has unknown kind")
        normalized.append({"name": name, "serialization": serialization,
                           "generics": generics, "repr": _validate_repr(
                               row["repr"], f"types[{index}].repr") if "repr" in row else None,
                           "type": normalized_shape})
    _unique_name(normalized, "type")
    return normalized


def _validate_seed(value: object, label: str) -> dict[str, object]:
    row = _object(value, label)
    kind = row.get("kind")
    if kind == "const":
        _keys(row, required={"kind", "value"}, allowed={"kind", "value"}, label=label)
        raw = _array(row["value"], f"{label}.value", 32)
        if any(type(byte) is not int or not 0 <= byte <= 255 for byte in raw):
            _fail(f"{label}.value must contain byte integers")
        return {"kind": "const", "value_hex": bytes(raw).hex(), "resolved": True}
    if kind == "arg":
        _keys(row, required={"kind", "path"}, allowed={"kind", "path"}, label=label)
        path = _text(row["path"], f"{label}.path")
        if not _PATH.fullmatch(path):
            _fail(f"{label}.path is invalid")
        return {"kind": "arg", "path": path, "resolved": False}
    if kind == "account":
        _keys(row, required={"kind", "path"}, allowed={"kind", "path", "account"}, label=label)
        path = _text(row["path"], f"{label}.path")
        if not _PATH.fullmatch(path):
            _fail(f"{label}.path is invalid")
        result: dict[str, object] = {"kind": "account", "path": path, "resolved": False}
        if "account" in row:
            result["account_type"] = _name(row["account"], f"{label}.account")
        return result
    _fail(f"{label} has unknown seed kind")


def _validate_pda(value: object, label: str) -> dict[str, object]:
    row = _object(value, label)
    _keys(row, required={"seeds"}, allowed={"seeds", "program"}, label=label)
    seeds = [_validate_seed(seed, f"{label}.seeds[{index}]")
             for index, seed in enumerate(_array(row["seeds"], f"{label}.seeds", 16))]
    result: dict[str, object] = {"seeds": seeds, "derivable_offline": False,
                                "seed_framing_ambiguous": len(seeds) > 1}
    if "program" in row:
        result["program"] = _validate_seed(row["program"], f"{label}.program")
    return result


def _flatten_accounts(value: object, label: str, depth: int = 0,
                      groups: tuple[str, ...] = ()) -> list[dict[str, object]]:
    if depth > MAX_NESTING:
        _fail(f"{label} nesting exceeds cap")
    rows = _array(value, label, MAX_ACCOUNTS)
    flattened: list[dict[str, object]] = []
    for index, item in enumerate(rows):
        row = _object(item, f"{label}[{index}]")
        if "accounts" in row:
            _keys(row, required={"name", "accounts"}, allowed={"name", "accounts"},
                  label=f"{label}[{index}]")
            group = _name(row["name"], f"{label}[{index}].name")
            flattened.extend(_flatten_accounts(row["accounts"], f"{label}[{index}].accounts",
                                               depth + 1, groups + (group,)))
            continue
        _keys(row, required={"name"},
              allowed={"name", "docs", "writable", "signer", "optional", "address", "pda", "relations"},
              label=f"{label}[{index}]")
        name = _name(row["name"], f"{label}[{index}].name")
        if "docs" in row:
            _docs(row["docs"], f"{label}[{index}].docs")
        relations = _array(row.get("relations", []), f"{label}[{index}].relations")
        if any(not isinstance(relation, str) or not _PATH.fullmatch(relation) for relation in relations):
            _fail(f"{label}[{index}].relations contains an invalid path")
        flattened.append({
            "name": name, "path": ".".join(groups + (name,)), "groups": list(groups),
            "writable": _bool_field(row, "writable", f"{label}[{index}]"),
            "signer": _bool_field(row, "signer", f"{label}[{index}]"),
            "optional": _bool_field(row, "optional", f"{label}[{index}]"),
            "address": _pubkey(row["address"], f"{label}[{index}].address") if "address" in row else None,
            "pda": _validate_pda(row["pda"], f"{label}[{index}].pda") if "pda" in row else None,
            "relations": list(relations),
        })
    if len(flattened) > MAX_ACCOUNTS:
        _fail(f"{label} flattened account list exceeds cap")
    return flattened


def _validate_named_discriminated(value: object, section: str) -> list[dict[str, object]]:
    rows = _array(value, section)
    normalized = []
    for index, item in enumerate(rows):
        row = _object(item, f"{section}[{index}]")
        _keys(row, required={"name", "discriminator"}, allowed={"name", "discriminator"},
              label=f"{section}[{index}]")
        normalized.append({"name": _name(row["name"], f"{section}[{index}].name"),
                           "discriminator": _discriminator(row["discriminator"],
                                                           f"{section}[{index}].discriminator")})
    _unique_name(normalized, section[:-1] if section.endswith("s") else section)
    return normalized


def _references(type_ref: object) -> set[str]:
    if isinstance(type_ref, str):
        return set()
    row = _object(type_ref, "normalized type")
    tag, payload = next(iter(row.items()))
    if tag in {"option", "vec"}:
        return _references(payload)
    if tag == "array":
        return _references(payload[0])  # type: ignore[index]
    if tag == "defined":
        result = {str(payload["name"])}  # type: ignore[index]
        for argument in payload.get("generics", []):  # type: ignore[union-attr]
            if argument["kind"] == "type":
                result |= _references(argument["type"])
        return result
    return set()


def _shape_references(shape: Mapping[str, object]) -> set[str]:
    refs: set[str] = set()
    kind = shape["kind"]
    if kind == "type":
        return _references(shape["alias"])
    groups = [shape.get("fields", [])] if kind == "struct" else [
        variant["fields"] for variant in shape["variants"]  # type: ignore[index]
    ]
    for fields in groups:
        for field in fields:  # type: ignore[union-attr]
            refs |= _references(field["type"] if isinstance(field, Mapping) and "name" in field else field)
    return refs


def _discriminator_issues(namespace: str, rows: list[dict[str, object]]) -> list[dict[str, object]]:
    ordered = sorted(((bytes(row["discriminator"]), str(row["name"])) for row in rows),
                     key=lambda pair: (pair[0], pair[1]))
    issues: list[dict[str, object]] = []
    for (left, left_name), (right, right_name) in zip(ordered, ordered[1:]):
        if left == right:
            issues.append({"namespace": namespace, "kind": "duplicate", "names": [left_name, right_name],
                           "discriminator_hex": left.hex()})
        elif right.startswith(left):
            issues.append({"namespace": namespace, "kind": "prefix-ambiguity",
                           "names": [left_name, right_name], "prefix_hex": left.hex(),
                           "longer_hex": right.hex()})
    return issues


def _validate_idl(idl: object) -> dict[str, object]:
    _check_tree(idl)
    root = _object(idl, "IDL")
    _keys(root, required={"address", "metadata", "instructions"},
          allowed={"$schema", "address", "metadata", "docs", "instructions", "accounts", "events",
                   "errors", "types", "constants"}, label="IDL")
    address = _pubkey(root["address"], "IDL.address")
    if "docs" in root:
        _docs(root["docs"], "IDL.docs")
    metadata = _object(root["metadata"], "IDL.metadata")
    _keys(metadata, required={"name", "version", "spec"},
          allowed={"name", "version", "spec", "description", "repository", "dependencies", "contact",
                   "deployments"}, label="IDL.metadata")
    metadata_name = _name(metadata["name"], "IDL.metadata.name")
    metadata_version = _text(metadata["version"], "IDL.metadata.version")
    if metadata.get("spec") != "0.1.0":
        _fail("only IDL spec 0.1.0 is supported")
    for field in ("description", "repository", "contact"):
        if field in metadata:
            _text(metadata[field], f"IDL.metadata.{field}")
    dependencies = _array(metadata.get("dependencies", []), "IDL.metadata.dependencies")
    for index, dependency_value in enumerate(dependencies):
        dependency = _object(dependency_value, f"IDL.metadata.dependencies[{index}]")
        _keys(dependency, required={"name", "version"}, allowed={"name", "version"},
              label=f"IDL.metadata.dependencies[{index}]")
        _name(dependency["name"], f"IDL.metadata.dependencies[{index}].name")
        _text(dependency["version"], f"IDL.metadata.dependencies[{index}].version")
    if "deployments" in metadata:
        deployments = _object(metadata["deployments"], "IDL.metadata.deployments")
        cluster_keys = {"mainnet", "testnet", "devnet", "localnet"}
        _keys(deployments, required=cluster_keys, allowed=cluster_keys, label="IDL.metadata.deployments")
        for cluster, deployed in deployments.items():
            if deployed is not None:
                _pubkey(deployed, f"IDL.metadata.deployments.{cluster}")

    types = _validate_type_defs(root.get("types", []))
    type_map = {str(row["name"]): row for row in types}
    for row in types:
        missing = _shape_references(row["type"]) - set(type_map)  # type: ignore[arg-type]
        if missing:
            _fail(f"type {row['name']!r} references undefined types: {', '.join(sorted(missing))}")

    instructions = []
    for index, item in enumerate(_array(root["instructions"], "instructions")):
        row = _object(item, f"instructions[{index}]")
        _keys(row, required={"name", "discriminator", "accounts", "args"},
              allowed={"name", "docs", "discriminator", "accounts", "args", "returns"},
              label=f"instructions[{index}]")
        name = _name(row["name"], f"instructions[{index}].name")
        if "docs" in row:
            _docs(row["docs"], f"instructions[{index}].docs")
        args = _validate_fields(row["args"], f"instructions[{index}].args")
        if args and not isinstance(args[0], Mapping):
            _fail(f"instructions[{index}].args must be named fields")
        for arg in args:
            missing = _references(arg["type"]) - set(type_map)  # type: ignore[index]
            if missing:
                _fail(f"instruction {name!r} references undefined types")
        returns = None
        if "returns" in row:
            returns = _validate_type_ref(row["returns"], f"instructions[{index}].returns")
            if _references(returns) - set(type_map):
                _fail(f"instruction {name!r} return type is undefined")
        instructions.append({"name": name, "discriminator": _discriminator(
            row["discriminator"], f"instructions[{index}].discriminator"),
            "accounts": _flatten_accounts(row["accounts"], f"instructions[{index}].accounts"),
            "args": args, "returns": returns})
    _unique_name(instructions, "instruction")

    accounts = _validate_named_discriminated(root.get("accounts", []), "accounts")
    events = _validate_named_discriminated(root.get("events", []), "events")
    for section, rows in (("account", accounts), ("event", events)):
        for row in rows:
            if row["name"] not in type_map:
                _fail(f"{section} {row['name']!r} has no same-named type definition")

    errors = []
    for index, item in enumerate(_array(root.get("errors", []), "errors")):
        row = _object(item, f"errors[{index}]")
        _keys(row, required={"code", "name"}, allowed={"code", "name", "msg"}, label=f"errors[{index}]")
        code = row["code"]
        if type(code) is not int or not 0 <= code <= 0xFFFFFFFF:
            _fail(f"errors[{index}].code must be u32")
        errors.append({"code": code, "name": _name(row["name"], f"errors[{index}].name"),
                       "message": _text(row["msg"], f"errors[{index}].msg") if "msg" in row else None})
    if len({row["code"] for row in errors}) != len(errors) or len({row["name"] for row in errors}) != len(errors):
        _fail("errors contain duplicate code or name")

    constants = []
    for index, item in enumerate(_array(root.get("constants", []), "constants")):
        row = _object(item, f"constants[{index}]")
        _keys(row, required={"name", "type", "value"}, allowed={"name", "docs", "type", "value"},
              label=f"constants[{index}]")
        if "docs" in row:
            _docs(row["docs"], f"constants[{index}].docs")
        type_ref = _validate_type_ref(row["type"], f"constants[{index}].type")
        if _references(type_ref) - set(type_map):
            _fail(f"constant {row['name']!r} references an undefined type")
        constants.append({"name": _name(row["name"], f"constants[{index}].name"),
                          "type": type_ref, "value": _text(row["value"], f"constants[{index}].value")})
    if len({row["name"] for row in constants}) != len(constants):
        _fail("constants contain duplicate names")

    issues = (_discriminator_issues("instruction", instructions)
              + _discriminator_issues("account", accounts)
              + _discriminator_issues("event", events))
    declines = []
    for row in types:
        reasons = []
        if row["serialization"] != "borsh":
            reasons.append(f"serialization={row['serialization']!r}")
        if row["generics"]:
            reasons.append("generic type")
        if reasons:
            declines.append({"type": row["name"], "reasons": reasons})
    return {"address": address, "metadata": {"name": metadata_name, "version": metadata_version,
                                               "spec": "0.1.0"},
            "instructions": instructions, "accounts": accounts, "events": events, "types": types,
            "type_map": type_map, "errors": errors, "constants": constants,
            "discriminator_issues": issues, "decoding_declines": declines}


def _json_type_ref(type_ref: object) -> object:
    return type_ref


@_public_api
def analyze_idl(idl: Mapping[str, object]) -> dict[str, object]:
    """Validate and catalog one current IDL 0.1.0 document."""

    context = _validate_idl(idl)
    return {
        "kind": "solana-idl-0.1.0", "program_address": context["address"],
        "metadata": context["metadata"],
        "instructions": [{
            "name": row["name"], "discriminator_hex": bytes(row["discriminator"]).hex(),
            "accounts": row["accounts"], "args": row["args"], "returns": row["returns"],
        } for row in context["instructions"]],
        "accounts": [{"name": row["name"], "discriminator_hex": bytes(row["discriminator"]).hex()}
                     for row in context["accounts"]],
        "events": [{"name": row["name"], "discriminator_hex": bytes(row["discriminator"]).hex()}
                   for row in context["events"]],
        "types": [{"name": row["name"], "kind": row["type"]["kind"],
                   "serialization": row["serialization"], "generic": bool(row["generics"]),
                   "borsh_decodable": row["serialization"] == "borsh" and not row["generics"]}
                  for row in context["types"]],
        "errors": context["errors"], "constants": context["constants"],
        "discriminator_issues": context["discriminator_issues"],
        "decoding_declines": context["decoding_declines"],
        "authenticity_verified": False,
    }


class _Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self.nodes = 0

    def take(self, size: int) -> bytes:
        if type(size) is not int or size < 0 or self.offset + size > len(self.data):
            _fail("truncated Borsh value")
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_TREE_NODES:
            _fail("Borsh value exceeds node cap")


def _decode_fields(fields: list[object], cursor: _Cursor, context: Mapping[str, object],
                   depth: int) -> object:
    if not fields:
        return {}
    if isinstance(fields[0], Mapping) and "name" in fields[0]:
        result = {}
        for field in fields:
            result[str(field["name"])] = _decode_type(field["type"], cursor, context, depth + 1)
        return result
    return [_decode_type(field, cursor, context, depth + 1) for field in fields]


def _decode_defined(name: str, cursor: _Cursor, context: Mapping[str, object], depth: int) -> object:
    type_map = context["type_map"]
    definition = type_map.get(name)  # type: ignore[union-attr]
    if not isinstance(definition, Mapping):
        _fail(f"undefined type {name!r}")
    if definition["serialization"] != "borsh":
        _fail(f"type {name!r} uses unsupported non-Borsh serialization")
    if definition["generics"]:
        _fail(f"type {name!r} is generic and cannot be decoded")
    shape = definition["type"]
    kind = shape["kind"]
    if kind == "struct":
        return _decode_fields(shape["fields"], cursor, context, depth + 1)
    if kind == "type":
        return _decode_type(shape["alias"], cursor, context, depth + 1)
    variants = shape["variants"]
    tag = cursor.take(1)[0]
    if tag >= len(variants):
        _fail(f"enum {name!r} tag is out of range")
    variant = variants[tag]
    return {"variant": variant["name"],
            "value": _decode_fields(variant["fields"], cursor, context, depth + 1)}


def _decode_type(type_ref: object, cursor: _Cursor, context: Mapping[str, object], depth: int = 0) -> object:
    if depth > MAX_NESTING:
        _fail("Borsh type nesting exceeds cap")
    cursor.node()
    if isinstance(type_ref, str):
        if type_ref == "bool":
            value = cursor.take(1)[0]
            if value not in (0, 1):
                _fail("Borsh bool tag must be zero or one")
            return bool(value)
        if type_ref in _INT_WIDTHS:
            width, signed = _INT_WIDTHS[type_ref]
            return int.from_bytes(cursor.take(width), "little", signed=signed)
        if type_ref in {"f32", "f64"}:
            value = struct.unpack("<f" if type_ref == "f32" else "<d",
                                  cursor.take(4 if type_ref == "f32" else 8))[0]
            if math.isnan(value):
                _fail("Borsh forbids NaN floats")
            return value
        if type_ref in {"bytes", "string"}:
            length = int.from_bytes(cursor.take(4), "little")
            if length > MAX_DYNAMIC_BYTES:
                _fail("Borsh dynamic byte field exceeds cap")
            raw = cursor.take(length)
            if type_ref == "bytes":
                return "0x" + raw.hex()
            try:
                return raw.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise SolanaIDLAnalysisError("Borsh string is not UTF-8") from exc
        if type_ref == "pubkey":
            encoded = _chain.b58encode(cursor.take(32))
            if not isinstance(encoded, str):
                _fail("could not encode public key")
            return encoded
        _fail(f"unsupported primitive {type_ref!r}")
    row = _object(type_ref, "normalized Borsh type")
    tag, payload = next(iter(row.items()))
    if tag == "option":
        marker = cursor.take(1)[0]
        if marker == 0:
            return None
        if marker != 1:
            _fail("Borsh option tag must be zero or one")
        return _decode_type(payload, cursor, context, depth + 1)
    if tag == "vec":
        count = int.from_bytes(cursor.take(4), "little")
        if count > MAX_DYNAMIC_ITEMS:
            _fail("Borsh vector exceeds item cap")
        return [_decode_type(payload, cursor, context, depth + 1) for _ in range(count)]
    if tag == "array":
        item_type, count = payload
        if not isinstance(count, int):
            _fail("generic Borsh array length is unsupported")
        return [_decode_type(item_type, cursor, context, depth + 1) for _ in range(count)]
    if tag == "defined":
        if payload.get("generics"):
            _fail("generic defined types are unsupported")
        return _decode_defined(str(payload["name"]), cursor, context, depth + 1)
    if tag == "generic":
        _fail("generic type parameters are unsupported")
    _fail(f"unsupported Borsh type tag {tag!r}")


def _data(value: object, label: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        _fail(f"{label} must be bytes")
    result = bytes(value)
    if len(result) > MAX_DATA_BYTES:
        _fail(f"{label} exceeds size cap")
    return result


@_public_api
def decode_borsh(idl: Mapping[str, object], type_name: str, data: bytes) -> dict[str, object]:
    """Decode exactly one same-named IDL type; reject trailing bytes."""

    context = _validate_idl(idl)
    name = _name(type_name, "type_name")
    if name not in context["type_map"]:
        _fail(f"unknown IDL type {name!r}")
    raw = _data(data, "Borsh data")
    cursor = _Cursor(raw)
    value = _decode_defined(name, cursor, context, 0)
    if cursor.offset != len(raw):
        _fail("trailing bytes after Borsh value")
    return {"kind": "borsh-value", "type": name, "value": value,
            "consumed": cursor.offset, "trailing": 0}


def _namespace_safe(context: Mapping[str, object], namespace: str) -> None:
    if any(issue["namespace"] == namespace for issue in context["discriminator_issues"]):
        _fail(f"{namespace} discriminator namespace is ambiguous")


def _match_discriminator(rows: list[dict[str, object]], data: bytes) -> dict[str, object] | None:
    matches = [row for row in rows if data.startswith(bytes(row["discriminator"]))]
    if not matches:
        return None
    if len(matches) != 1:
        _fail("data matches multiple discriminators")
    return matches[0]


def _account_checks(expected: list[dict[str, object]], supplied: object) -> list[dict[str, object]]:
    rows = _array(supplied, "account_metas", MAX_ACCOUNTS)
    if len(rows) != len(expected):
        _fail("account_metas length must equal the flattened IDL account count")
    findings = []
    for index, (want, actual_value) in enumerate(zip(expected, rows)):
        if actual_value is None:
            if not want["optional"]:
                findings.append({"kind": "missing-required-account", "index": index, "name": want["name"]})
            continue
        if isinstance(actual_value, str):
            address, signer, writable = _pubkey(actual_value, f"account_metas[{index}]"), None, None
        else:
            actual = _object(actual_value, f"account_metas[{index}]")
            raw_address = actual.get("pubkey", actual.get("address"))
            address = _pubkey(raw_address, f"account_metas[{index}].address")
            signer = actual.get("signer", actual.get("isSigner"))
            writable = actual.get("writable", actual.get("isWritable"))
            if signer is not None and type(signer) is not bool:
                _fail(f"account_metas[{index}].signer must be boolean")
            if writable is not None and type(writable) is not bool:
                _fail(f"account_metas[{index}].writable must be boolean")
        if want["address"] and address != want["address"]:
            findings.append({"kind": "fixed-address-mismatch", "index": index, "name": want["name"],
                             "expected": want["address"], "actual": address})
        if signer is False and want["signer"]:
            findings.append({"kind": "missing-signer-privilege", "index": index, "name": want["name"]})
        elif signer is True and not want["signer"]:
            findings.append({"kind": "unexpected-signer-privilege", "index": index, "name": want["name"]})
        if writable is False and want["writable"]:
            findings.append({"kind": "missing-writable-privilege", "index": index, "name": want["name"]})
        elif writable is True and not want["writable"]:
            findings.append({"kind": "unexpected-writable-privilege", "index": index, "name": want["name"]})
    return findings


@_public_api
def match_instruction(idl: Mapping[str, object], data: bytes,
                      account_metas: Sequence[object] | None = None) -> dict[str, object] | None:
    """Match an IDL-published discriminator and Borsh-decode all arguments.

    Unknown well-formed instruction data returns ``None``.  Supplied account metas
    are compared structurally; this does not prove runtime ownership or execution.
    """

    context = _validate_idl(idl)
    _namespace_safe(context, "instruction")
    raw = _data(data, "instruction data")
    matched = _match_discriminator(context["instructions"], raw)
    if matched is None:
        return None
    discriminator = bytes(matched["discriminator"])
    cursor = _Cursor(raw[len(discriminator):])
    args = {}
    for field in matched["args"]:
        args[str(field["name"])] = _decode_type(field["type"], cursor, context, 0)
    if cursor.offset != len(cursor.data):
        _fail("trailing bytes after instruction arguments")
    checks = _account_checks(matched["accounts"], account_metas) if account_metas is not None else []
    return {"kind": "solana-idl-instruction", "program_address": context["address"],
            "instruction": matched["name"], "discriminator_hex": discriminator.hex(),
            "arguments": args, "accounts": matched["accounts"], "account_findings": checks,
            "consumed": len(raw), "execution_verified": False}


@_public_api
def analyze_program_account(idl: Mapping[str, object], data: bytes, *,
                            account_name: str | None = None, owner: str | None = None,
                            expected_program: str | None = None,
                            executable: bool | None = None) -> dict[str, object]:
    """Match and decode caller-supplied program-account data under an IDL.

    The caller supplies envelope facts separately because Solana has no universal
    raw account-file framing.  Owner/executable mismatches are evidence findings;
    the IDL's authenticity and the account's existence remain unverified.
    """

    context = _validate_idl(idl)
    _namespace_safe(context, "account")
    raw = _data(data, "program account data")
    actual_owner = _pubkey(owner, "owner") if owner is not None else None
    expected_owner = (_pubkey(expected_program, "expected_program")
                      if expected_program is not None else str(context["address"]))
    if executable is not None and type(executable) is not bool:
        _fail("executable must be boolean or None")
    selected = None
    if account_name is not None:
        wanted = _name(account_name, "account_name")
        selected = next((row for row in context["accounts"] if row["name"] == wanted), None)
        if selected is None:
            _fail(f"unknown IDL account {wanted!r}")
        if not raw.startswith(bytes(selected["discriminator"])):
            selected = None
    else:
        selected = _match_discriminator(context["accounts"], raw)

    findings: list[dict[str, object]] = []
    if actual_owner is not None and actual_owner != expected_owner:
        findings.append({"kind": "owner-mismatch", "expected": expected_owner, "actual": actual_owner})
    if executable is True:
        findings.append({"kind": "unexpected-executable-data-account"})
    if selected is None:
        findings.append({"kind": "unknown-account-discriminator"})
        return {"kind": "solana-program-account", "program_address": context["address"],
                "owner": actual_owner, "expected_owner": expected_owner, "owner_matches":
                actual_owner == expected_owner if actual_owner is not None else None,
                "executable": executable, "account_type": None, "value": None,
                "findings": findings, "authenticity_verified": False}

    discriminator = bytes(selected["discriminator"])
    cursor = _Cursor(raw[len(discriminator):])
    value = _decode_defined(str(selected["name"]), cursor, context, 0)
    if cursor.offset != len(cursor.data):
        _fail("trailing bytes after program account value")
    return {"kind": "solana-program-account", "program_address": context["address"],
            "owner": actual_owner, "expected_owner": expected_owner,
            "owner_matches": actual_owner == expected_owner if actual_owner is not None else None,
            "executable": executable, "account_type": selected["name"],
            "discriminator_hex": discriminator.hex(), "value": value,
            "findings": findings, "authenticity_verified": False}


def _load_json(path: str) -> Mapping[str, object]:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_IDL_BYTES:
        _fail("JSON file exceeds size cap")
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SolanaIDLAnalysisError("invalid JSON input") from exc
    return _object(value, "JSON input")


def _load_data(value: str, hexadecimal: bool) -> bytes:
    if hexadecimal:
        text = value[2:] if value.startswith(("0x", "0X")) else value
        if len(text) > MAX_DATA_BYTES * 2 or len(text) % 2 or not re.fullmatch(r"[0-9A-Fa-f]*", text):
            _fail("--hex data must be bounded even-length hexadecimal")
        return bytes.fromhex(text)
    raw = Path(value).read_bytes()
    if len(raw) > MAX_DATA_BYTES:
        _fail("data file exceeds size cap")
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline Solana IDL/account analyzer; no RPC")
    parser.add_argument("operation", choices=("catalog", "instruction", "account"))
    parser.add_argument("idl", help="IDL 0.1.0 JSON file")
    parser.add_argument("artifact", nargs="?", help="binary path, or hexadecimal with --hex")
    parser.add_argument("--hex", action="store_true", help="interpret artifact itself as hexadecimal")
    parser.add_argument("--metas", help="JSON file containing positional instruction account metas")
    parser.add_argument("--account-name")
    parser.add_argument("--owner")
    parser.add_argument("--expected-program")
    parser.add_argument("--executable", action="store_true")
    try:
        args = parser.parse_args(argv)
        idl = _load_json(args.idl)
        if args.operation == "catalog":
            if args.artifact is not None:
                _fail("catalog does not accept an artifact")
            result = analyze_idl(idl)
        else:
            if args.artifact is None:
                _fail(f"{args.operation} requires an artifact")
            data = _load_data(args.artifact, args.hex)
            if args.operation == "instruction":
                metas = None
                if args.metas:
                    raw_metas = Path(args.metas).read_bytes()
                    if len(raw_metas) > MAX_IDL_BYTES:
                        _fail("account meta JSON exceeds size cap")
                    metas = json.loads(raw_metas.decode("utf-8", "strict"))
                result = match_instruction(idl, data, metas)
            else:
                result = analyze_program_account(
                    idl, data, account_name=args.account_name, owner=args.owner,
                    expected_program=args.expected_program,
                    executable=True if args.executable else None,
                )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (SolanaIDLAnalysisError, OSError, UnicodeError, json.JSONDecodeError,
            TypeError, ValueError, OverflowError, struct.error, RecursionError) as exc:
        print(f"chain2_solana_idl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
