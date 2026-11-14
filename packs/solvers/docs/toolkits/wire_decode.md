# Toolkit `wire_decode`: schema-less protobuf / CBOR / MessagePack / BSON

Built 2026-10-23 (gap-analysis ticket **C3**, `docs/retro/ctf-solver-gap-analysis.md`). Binary serialization was
covered only where a library already knew the schema; there was no generic wire-format walker. This decodes the
**structure** of a serialized blob with no schema. Offline, standard library only — every format here is
self-describing on the wire, so no `cbor2`/`msgpack`/`bson` dependency is needed.

## Run first

```bash
.venv/bin/python solvers/toolkits/wire_decode.py <file>...          # the decoded structure per file
.venv/bin/python solvers/toolkits/wire_decode.py <file> --json      # as JSON
```

As a solver: `solvers/toolkits/wire_decode.py` has `solve_set` and `signals(questions, files)` (0..1,
0.0 when nothing decodes cleanly) for running the whole file set at once.

By hand, from Python:

```python
sys.path.insert(0, "solvers/toolkits"); import wire_decode as T
T.classify(data)          # {"format": "protobuf"|"cbor"|"msgpack"|"bson", "fields"|"value": ...} or None
T.decode_protobuf(data)   # [{field, wire_type, wire_name, value}]  (value of a wt=2 field: str/message/hex)
T.decode_cbor(data)       # the CBOR value tree
T.decode_msgpack(data)    # the MessagePack value tree
T.decode_bson(data)       # a BSON document as a dict
```

## What it reads

| Format | Detected by | Structural facts |
| --- | --- | --- |
| bson | an int32 length prefix equal to the buffer length + a `0x00` terminator (least ambiguous) | number of keys, the scalar value at a named key |
| cbor | a clean RFC 8949 decode that consumes the whole buffer and is a map/array | number of keys/elements, the value at a named key |
| msgpack | a clean MessagePack decode that consumes the whole buffer and is a map/array | number of keys/elements, the value at a named key |
| protobuf | a clean parse that consumes the whole buffer, all field numbers sane, every length-delimited value a string or sub-message | field count, wire type of a field, the scalar value at a named field number |

A buffer that does not decode cleanly (not fully consumed, an invalid tag) is **`None`** for every question —
never a partial guess. When more than one format decodes cleanly the report is marked `ambiguous`. Bounded:
16 MiB file, ≤200000 nodes, ≤32 deep.

## Never-guess

Field numbers, wire types, lengths and a scalar value read at a named field/key are **deterministic**, so a
structural value the question asks for is **high-confidence**: returned as `labels.pick(key, options)` of its
renderings (decimal/hex for an int, true/false spellings for a bool), a ranked list you read and reason to one
value. A **semantic field name** has no schema here, so it is `None`; a protobuf length-delimited field is
ambiguous (string vs bytes vs sub-message), so its string reading is offered as a **candidate**, never decided
by itself. Keys are `wire_decode.<field>/<shape>` (`wire_decode.field2/protobuf`, `wire_decode.count/cbor`,
`wire_decode.key_user/bson`). The flag is `None`.
