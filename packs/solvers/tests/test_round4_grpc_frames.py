"""Blind gRPC/gRPC-Web framing over the existing schema-less protobuf reader."""
from __future__ import annotations

import base64
import gzip
import json
import random
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import wire_decode as wire  # noqa: E402


def _frame(data, flag=0):
    return bytes([flag]) + len(data).to_bytes(4, "big") + data


def _message(flag=b"CSCTF{grpc_blind}"):
    return b"\x08\x96\x01" + b"\x12" + bytes([len(flag)]) + flag


def test_grpc_messages_schema_less_protobuf_and_multiple_frames():
    stream = _frame(_message()) + _frame(b"\x08\x01")
    rows = wire.decode_grpc_frames(stream)
    assert len(rows) == 2 and rows[0]["protobuf"][0]["value"] == 150
    assert rows[0]["protobuf"][1]["value"]["string"] == "CSCTF{grpc_blind}"
    assert rows[1]["protobuf"][0]["value"] == 1


def test_grpc_compression_requires_declared_encoding_and_is_bounded():
    packed = gzip.compress(_message(b"CSCTF{grpc_gzip}"), mtime=0)
    opaque = wire.decode_grpc_frames(_frame(packed, 1))
    assert opaque[0]["protobuf"] is None and opaque[0]["raw"] == packed
    decoded = wire.decode_grpc_frames(_frame(packed, 1), compression="gzip")
    assert decoded[0]["protobuf"][1]["value"]["string"] == "CSCTF{grpc_gzip}"
    with pytest.raises(wire._WireError, match="compression"):
        wire.decode_grpc_frames(_frame(packed, 1), compression="snappy")


def test_grpc_web_binary_base64_and_trailers():
    trailers = b"grpc-status: 0\r\ngrpc-message: all%20good\r\n"
    stream = _frame(_message(), 0) + _frame(trailers, 0x80)
    rows = wire.decode_grpc_frames(base64.b64encode(stream), grpc_web=True, base64_encoded=True)
    assert rows[0]["protobuf"] and rows[1]["trailers"] is True
    assert rows[1]["headers"] == {"grpc-status": ["0"], "grpc-message": ["all%20good"]}
    with pytest.raises(wire._WireError):
        wire.decode_grpc_frames(_frame(b"bad trailer", 0x80), grpc_web=True)


def test_complete_consumption_and_guarded_cli(tmp_path, capsys):
    with pytest.raises(wire._WireError):
        wire.decode_grpc_frames(_frame(_message()) + b"\x00")
    with pytest.raises(wire._WireError):
        wire.decode_grpc_frames(b"\x02\x00\x00\x00\x00")
    path = tmp_path / "body.grpc"
    path.write_bytes(_frame(_message()))
    assert wire.main([str(path), "--grpc", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)[0]
    assert report["format"] == "grpc"
    assert wire.main([]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_seeded_frame_mutations_are_contained():
    rng = random.Random(0x67_72_70_63)
    seed = _frame(_message()) + _frame(b"grpc-status: 0\r\n", 0x80)
    for _ in range(1500):
        blob = bytearray(seed)
        for _ in range(rng.randrange(1, 10)):
            action = rng.randrange(3)
            if action == 0 and blob:
                blob[rng.randrange(len(blob))] ^= 1 << rng.randrange(8)
            elif action == 1 and blob:
                del blob[rng.randrange(len(blob))]
            elif len(blob) < 2048:
                blob.insert(rng.randrange(len(blob) + 1), rng.randrange(256))
        try:
            rows = wire.decode_grpc_frames(bytes(blob), grpc_web=True)
            assert all(row["length"] <= wire.MAX_FILE for row in rows)
        except wire._WireError:
            pass
