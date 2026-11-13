"""Static model readers, using real writers as independent format oracles.

References: https://onnx.ai/onnx/repo-docs/IR.html
https://numpy.org/doc/stable/reference/generated/numpy.lib.format.html
https://github.com/safetensors/safetensors#format
No serialized callable is loaded or executed by these tests.
"""
import io
import os
import pickle
import posix
import random
import socket
import subprocess
import _pickle

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper
from safetensors.numpy import save as save_safetensors
import pytest
from pathlib import Path

from _shadowed import module_at

# the toolkit face by path: a flat `import ai_model_files` gets solvers/common's reader of the same
# name when another test imported that first (R-10)
engine = module_at(Path(__file__).resolve().parents[1] / "solvers/toolkits/ai_model_files.py",
                   "toolkits_ai_model_files")


def _blocked(*args, **kwargs):
    raise AssertionError("model analysis attempted execution or network access")


@pytest.fixture(autouse=True)
def static_only(monkeypatch):
    for module, names in ((pickle, ("load", "loads", "Unpickler")), (_pickle, ("load", "loads", "Unpickler")),
                          (np, ("load",)), (os, ("system", "popen")),
                          (posix, ("system",)),
                          (subprocess, ("Popen", "run", "call", "check_call", "check_output")),
                          (socket, ("create_connection", "getaddrinfo"))):
        for name in names:
            monkeypatch.setattr(module, name, _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)


def _npy(array, version=(1, 0)):
    out = io.BytesIO()
    np.lib.format.write_array(out, array, version=version, allow_pickle=True)
    return out.getvalue()


def _onnx(axis=1):
    node = helper.make_node("Softmax", ["X"], ["Y"], name="softmax", axis=axis)
    graph = helper.make_graph([node], "known_graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [2, 3])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [2, 3])],
        [numpy_helper.from_array(np.arange(6, dtype=np.float32).reshape(2, 3), "weights")])
    model = helper.make_model(graph, producer_name="oracle", producer_version="1.0",
                              opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    helper.set_model_props(model, {"note": "CSCTF{model_metadata}"})
    return model


@pytest.mark.parametrize("version", [(1, 0), (2, 0), (3, 0)])
@pytest.mark.parametrize("fortran", [False, True])
def test_npy_real_numpy_writer(version, fortran):
    data = np.arange(6, dtype="<i2").reshape(2, 3)
    if fortran:
        data = np.asfortranarray(data)
    rep = engine.read_npy(_npy(data, version))
    assert rep["shape"] == [2, 3]
    assert rep["descr"] == "<i2"
    assert rep["fortran_order"] is fortran
    assert rep["format_version"] == "%d.%d" % version
    assert rep["error"] is None and rep["object_array"] is False


def test_npy_object_pickle_is_static():
    rep = engine.read_npy(_npy(np.array(["CSCTF{object_data}"], dtype=object)))
    assert rep["object_array"] is True
    assert rep["shape"] == [1]
    assert "CSCTF{object_data}" in rep["strings"]
    assert rep["pickle"]["complete"] is True
    assert any(g.endswith("._reconstruct") for g in rep["globals"])


def test_npz_real_numpy_writer():
    out = io.BytesIO()
    np.savez_compressed(out, counts=np.arange(4, dtype="<u2"), matrix=np.zeros((2, 3), dtype="<f4"))
    rep = engine.read_npz(out.getvalue())
    assert rep["members"] == ["counts.npy", "matrix.npy"]
    assert rep["tensors"] == [{"name": "counts", "shape": [4], "dtype": "<u2"},
                              {"name": "matrix", "shape": [2, 3], "dtype": "<f4"}]
    assert rep["object_array"] is False and rep["calls"] == []


def test_safetensors_real_writer_and_trailing_bytes():
    raw = save_safetensors({"weights": np.arange(6, dtype=np.float32).reshape(2, 3)},
                           metadata={"note": "CSCTF{safe_metadata}"})
    rep = engine.read_safetensors(raw)
    assert rep["tensors"] == [{"name": "weights", "shape": [2, 3], "dtype": "F32", "data_offsets": [0, 24]}]
    assert rep["metadata"] == {"note": "CSCTF{safe_metadata}"}
    assert rep["unused_data_bytes"] == 0 and rep["offsets_past_end"] is False
    assert engine.read_safetensors(raw + b"TRAIL")["unused_data_bytes"] == 5
    assert engine.read_safetensors(raw[:-1])["offsets_past_end"] is True


def test_onnx_real_writer_metadata_and_external_reference():
    model = _onnx()
    tensor = model.graph.initializer[0]
    tensor.ClearField("raw_data")
    tensor.data_location = TensorProto.EXTERNAL
    item = tensor.external_data.add()
    item.key, item.value = "location", "../weights.bin"
    rep = engine.read_onnx(model.SerializeToString())
    assert rep["ir_version"] == 8 and rep["producer_name"] == "oracle"
    assert rep["graph_name"] == "known_graph"
    assert rep["inputs"] == ["X"] and rep["outputs"] == ["Y"]
    assert rep["opsets"] == [{"domain": "", "version": 13}]
    assert rep["metadata"] == {"note": "CSCTF{model_metadata}"}
    assert rep["external_locations"] == ["../weights.bin"]
    assert rep["tensors"][0]["shape"] == [2, 3]
    assert rep["tensors"][0]["dtype"] == "FLOAT"
    assert rep["nodes"][0]["attributes"] == [{"name": "axis", "ints": [1]}]


def test_onnx_negative_singular_attribute():
    rep = engine.read_onnx(_onnx(axis=-1).SerializeToString())
    assert rep["nodes"][0]["attributes"] == [{"name": "axis", "ints": [-1]}]


def test_onnx_negative_repeated_attribute():
    model = _onnx()
    model.graph.node[0].attribute.append(helper.make_attribute("axes", [-1, -2]))
    rep = engine.read_onnx(model.SerializeToString())
    assert rep["nodes"][0]["attributes"][1] == {"name": "axes", "ints": [-1, -2]}


@pytest.mark.parametrize("protocol", [0, 1, 2, 3, 4, 5])
def test_pickle_real_writer(protocol):
    raw = pickle.dumps({"label": "CSCTF{pickle_metadata}", "numbers": [1, 2, 3]}, protocol=protocol)
    rep = engine.read_pickle(raw)
    assert rep["complete"] is True and rep["error"] is None
    assert rep["pickles"] == 1 and rep["calls"] == [] and rep["globals"] == []
    assert "CSCTF{pickle_metadata}" in rep["strings"]
    if protocol >= 2:
        assert rep["protocol"] == protocol


def test_pickle_reduce_risk_without_execution():
    # Protocol 0 GLOBAL + tuple + REDUCE, as documented by pickletools.
    # Inert text; every actual subprocess/network/unpickle function is blocked.
    raw = b"cposix\nsystem\n(S'CSCTF_INERT_ONLY'\ntR."
    rep = engine.read_pickle(raw)
    assert rep["complete"] is True
    assert rep["globals"] == ["posix.system"]
    assert rep["calls"][0]["callable"] == "posix.system"
    assert rep["calls"][0]["args"] == ["CSCTF_INERT_ONLY"]
    assert engine.runs_code("posix.system") is True
    assert engine.is_loader("pickle.loads") is True
    assert engine.runs_code("numpy.dtype") is False


def test_wrapper_analysis_reports_and_file_cap(monkeypatch):
    raw = _npy(np.arange(4, dtype=np.int8))
    assert engine.analyze(raw, "weights.npy")["file"] == "weights.npy"
    assert engine.reports({"weights.npy": raw})[0][2]["shape"] == [4]
    monkeypatch.setattr(engine, "MAX_FILE", len(raw) - 1)
    assert engine.reports({"weights.npy": raw}) == []
    assert engine.public({"a": {"_hidden": 1, "b": 2}, "_secret": 3}) == {"a": {"b": 2}}


def test_pickle_opcode_budget(monkeypatch):
    monkeypatch.setattr(engine.reader, "MAX_OPS", 5)
    rep = engine.read_pickle(pickle.dumps(list(range(100)), protocol=4))
    assert rep["complete"] is False and rep["truncated"] is True
    assert rep["error"] and rep["ops"] <= 6


@pytest.mark.parametrize("name", ["read_pickle", "read_npy", "read_npz", "read_safetensors", "read_onnx",
                                  "read_gguf", "read_torch_zip", "read_keras_zip", "read_hdf5", "analyze"])
def test_static_readers_seeded_binary_fuzz(name):
    rng = random.Random(0xA1F11E)
    seeds = [_npy(np.arange(2, dtype=np.int8)), _onnx().SerializeToString(),
             save_safetensors({"x": np.zeros(2, dtype=np.float32)}), pickle.dumps([1, 2, 3], protocol=4),
             b"GGUF\x03\x00\x00\x00", b"PK\x03\x04", b"\x89HDF\r\n\x1a\n"]
    corpus = [b"", b"\xff" * 256, bytes(rng.randrange(256) for _ in range(256))]
    for seed in seeds:
        corpus.extend(seed[:n] for n in sorted({1, 4, 8, len(seed) // 2, len(seed) - 1}))
        changed = bytearray(seed)
        changed[len(changed) // 2] ^= 0x80
        corpus.append(bytes(changed))
    for raw in corpus:
        rep = getattr(engine, name)(raw)
        assert rep is None or isinstance(rep, dict)


@pytest.mark.parametrize("name", ["read_pickle", "read_npy", "read_safetensors", "read_onnx"])
def test_static_reader_wrong_type_contract(name):
    assert getattr(engine, name)(None) is None
