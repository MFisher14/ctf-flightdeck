"""B-116: tensor values sliced out of saved model files without unpickling (solvers/toolkits/_model_tensors.py).

Every file is written inside the test (tests/b116_models.py): npz, npy, safetensors, a hand-assembled
PyTorch zip and JSON. No real model, no torch.
"""
from __future__ import annotations

import io
import json
import pickle
import struct
import sys
import zipfile
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import b116_models as fx  # noqa: E402

from solvers.toolkits import _model_tensors as mt  # noqa: E402

pytestmark = pytest.mark.needs_tool("py:numpy")

W = np.arange(12, dtype=np.float32).reshape(3, 4) / 7.0
B = np.array([0.5, -1.25, 3.0])


# ---------------------------------------------------------------- numpy files

def test_npz_values_shapes_and_dtypes_survive():
    ts = mt.load_bytes(fx.npz_bytes({"W1": W, "b1": B, "scalar": np.float64(2.5)}), "net.npz")
    assert ts.kind == "npz" and list(ts.tensors) == ["W1", "b1", "scalar"] and not ts.skipped
    assert ts.tensors["W1"].dtype == np.float32 and np.array_equal(ts.tensors["W1"], W)
    assert ts.tensors["b1"].dtype == np.float64 and np.array_equal(ts.tensors["b1"], B)
    assert ts.tensors["scalar"].shape == () and float(ts.tensors["scalar"]) == 2.5


def test_fortran_order_npy_is_read_in_its_own_order():
    buf = io.BytesIO()
    np.save(buf, np.asfortranarray(W))
    raw = buf.getvalue()
    assert b"'fortran_order': True" in raw                      # the fixture really is column-major
    ts = mt.load_bytes(raw, "W1.npy")
    assert ts.kind == "npy" and np.array_equal(ts.tensors["W1"], W)


def test_object_array_is_refused_not_unpickled():
    buf = io.BytesIO()
    np.save(buf, np.array([{"a": 1}, [2, 3]], dtype=object), allow_pickle=True)
    with pytest.raises(mt.TensorError, match="object array is a pickle"):
        mt.load_bytes(buf.getvalue(), "obj.npy")


def test_object_member_of_an_npz_is_skipped_with_its_reason_and_the_rest_is_read():
    buf = io.BytesIO()
    np.savez(buf, good=W, bad=np.array([{"a": 1}], dtype=object))
    ts = mt.load_bytes(buf.getvalue(), "mixed.npz")
    assert list(ts.tensors) == ["good"] and np.array_equal(ts.tensors["good"], W)
    assert [name for name, _why in ts.skipped] == ["bad"] and "pickle" in ts.skipped[0][1]


def test_truncated_npy_names_the_shortfall():
    buf = io.BytesIO()
    np.save(buf, W)
    with pytest.raises(mt.TensorError, match="do not hold shape"):
        mt.load_bytes(buf.getvalue()[:-8], "cut.npy")


# ---------------------------------------------------------------- safetensors

def test_safetensors_values_for_each_dtype():
    half = (W * 4).astype(np.float16)
    ints = np.array([[1, -2], [3, 4]], dtype=np.int64)
    ts = mt.load_bytes(fx.safetensors_bytes({"h": half, "f": W, "i": ints}, metadata={"format": "pt"}), "m.safetensors")
    assert ts.kind == "safetensors" and ts.metadata == {"format": "pt"}
    assert ts.tensors["h"].dtype == np.float16 and np.array_equal(ts.tensors["h"], half)
    assert np.array_equal(ts.tensors["f"], W) and np.array_equal(ts.tensors["i"], ints)


def test_bfloat16_bit_patterns_become_the_right_float32():
    want = np.array([[1.5, -2.0], [0.15625, 96.0]], dtype=np.float32)       # exactly representable in 16 bits
    patterns = (want.view(np.uint32) >> 16).astype(np.uint16)
    ts = mt.load_bytes(fx.safetensors_bytes({"w": patterns}, codes={"w": "BF16"}), "bf.safetensors")
    assert ts.tensors["w"].dtype == np.float32 and np.array_equal(ts.tensors["w"], want)


def _raw_safetensors(header: dict, blob: bytes) -> bytes:
    head = json.dumps(header).encode()
    return struct.pack("<Q", len(head)) + head + blob


@pytest.mark.parametrize("entry, blob, message", [
    ({"dtype": "F32", "shape": [2], "data_offsets": [0, 16]}, b"\0" * 8, "lie outside"),
    ({"dtype": "F32", "shape": [3], "data_offsets": [0, 8]}, b"\0" * 8, "do not hold shape"),
    ({"dtype": "Q9", "shape": [2], "data_offsets": [0, 8]}, b"\0" * 8, "dtype 'Q9'"),
    ({"dtype": "F32", "shape": [-2], "data_offsets": [0, 8]}, b"\0" * 8, "non-negative"),
    ({"dtype": "F32", "shape": [2], "data_offsets": [8, 0]}, b"\0" * 8, "lie outside"),
])
def test_safetensors_layout_faults_name_the_tensor(entry, blob, message):
    with pytest.raises(mt.TensorError, match=message) as err:
        mt.load_bytes(_raw_safetensors({"w": entry}, blob), "bad.safetensors")
    assert "'w'" in str(err.value) and "bad.safetensors" in str(err.value)


def test_safetensors_duplicate_names_are_refused():
    head = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"w":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}'
    with pytest.raises(mt.TensorError, match="duplicate tensor name"):
        mt.load_bytes(struct.pack("<Q", len(head)) + head + b"\0" * 8, "dup.safetensors")


def test_safetensors_header_longer_than_the_file_is_refused(tmp_path):
    p = tmp_path / "m.safetensors"
    p.write_bytes(struct.pack("<Q", 5000) + b'{"w":{}}')
    with pytest.raises(mt.TensorError, match="header length 5000"):
        mt.SafetensorsFile.open(p)


def test_safetensors_file_on_disk_reads_only_what_is_asked(tmp_path):
    p = tmp_path / "m.safetensors"
    p.write_bytes(fx.safetensors_bytes({"a": W.astype(np.float16), "b": B.astype(np.float32)}))
    sf = mt.SafetensorsFile.open(p)
    assert list(sf.layout) == ["a", "b"] and sf.layout["a"]["shape"] == [3, 4] and sf.layout["a"]["dtype"] == "F16"
    got = sf.read(["b"], astype="float32")
    assert list(got) == ["b"] and got["b"].dtype == np.float32 and np.array_equal(got["b"], B.astype(np.float32))
    assert sf.nbytes(["a"]) == 24 and sf.nbytes(["a"], astype="float32") == 48 and sf.nbytes() == 24 + 12
    with pytest.raises(mt.TensorError, match="no tensor named 'zz'"):
        sf.read(["zz"])


@pytest.mark.parametrize("compress", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_safetensors_inside_a_zip_is_read_in_place(tmp_path, compress):
    half = (W * 4).astype(np.float16)
    z = tmp_path / "dist.zip"
    with zipfile.ZipFile(z, "w", compress) as zf:
        zf.writestr("model/readme.txt", "x")
        zf.writestr("model/model.safetensors", fx.safetensors_bytes({"a": half, "skip": np.zeros(50, np.float32),
                                                                     "b": B.astype(np.float32)}))
    sf = mt.SafetensorsFile.open(z, member="model/model.safetensors")
    assert sf.label == "dist.zip!model/model.safetensors"
    got = sf.read(["b", "a"], astype="float32")                # asked out of file order, a gap in between
    assert list(got) == ["b", "a"]
    assert np.array_equal(got["a"], half.astype(np.float32)) and np.array_equal(got["b"], B.astype(np.float32))
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dist.zip"]          # nothing was extracted
    with pytest.raises(mt.TensorError, match="cannot be opened"):
        mt.SafetensorsFile.open(z, member="model/absent.safetensors")


def test_aliased_tensors_read_from_disk_but_not_as_a_forward_zip_stream(tmp_path):
    """Two names over the same bytes: fine for a mapped file, not for a one-pass read of a zip member."""
    raw = _raw_safetensors({"a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
                            "b": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}},
                           np.array([1.5, -2.0], np.float32).tobytes())
    p = tmp_path / "alias.safetensors"
    p.write_bytes(raw)
    got = mt.SafetensorsFile.open(p).read()
    assert np.array_equal(got["a"], [1.5, -2.0]) and np.array_equal(got["b"], [1.5, -2.0])
    z = tmp_path / "alias.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("alias.safetensors", raw)
    with pytest.raises(mt.TensorError, match="tensor 'b' overlaps an earlier one"):
        mt.SafetensorsFile.open(z, member="alias.safetensors").read()


# ---------------------------------------------------------------- PyTorch zip

def test_torch_zip_state_dict_is_sliced_from_its_storages():
    raw = fx.torch_zip_bytes({"fc1.weight": W, "fc1.bias": B, "fc2.weight": np.ones((1, 3))})
    pkl = zipfile.ZipFile(io.BytesIO(raw)).read("model/data.pkl")
    assert b"torch._utils\n_rebuild_tensor_v2" in pkl and b"FloatStorage" in pkl   # the layout is inside a pickle
    ts = mt.load_bytes(raw, "net.pt")
    assert ts.kind == "torch_zip" and not ts.skipped
    assert list(ts.tensors) == ["fc1.weight", "fc1.bias", "fc2.weight"]
    assert ts.tensors["fc1.weight"].dtype == np.float32 and np.array_equal(ts.tensors["fc1.weight"], W)
    assert np.array_equal(ts.tensors["fc1.bias"], B.astype(np.float32))


def test_torch_zip_strided_view_is_read_by_stride_and_offset():
    """A transposed weight is saved as a view: storage in the original order, stride swapped."""
    storage = np.concatenate([[99.0, 98.0], W.T.reshape(-1)]).astype(np.float32)   # two junk values, then W.T
    raw = fx.torch_zip_bytes({"w": W}, views={"w": (storage, 2, [1, 3])})
    ts = mt.load_bytes(raw, "view.pt")
    assert np.array_equal(ts.tensors["w"], W), ts.skipped
    assert not np.array_equal(storage[2:14].reshape(3, 4), W)                  # a contiguous read would be wrong


def test_torch_zip_contiguous_tensor_starts_at_its_storage_offset():
    storage = np.concatenate([[7.0, 8.0, 9.0], W.reshape(-1)]).astype(np.float32)   # three other values first
    ts = mt.load_bytes(fx.torch_zip_bytes({"w": W}, views={"w": (storage, 3, [4, 1])}), "shared.pt")
    assert np.array_equal(ts.tensors["w"], W), ts.skipped


def test_reader_records_the_stride_the_slicer_needs():
    raw = fx.torch_zip_bytes({"w": W}, views={"w": (np.zeros(20, np.float32), 2, [1, 3])})
    rep = mt.reader().read_torch_zip(raw)
    assert rep["tensors"][0]["stride"] == [1, 3] and rep["tensors"][0]["offset"] == 2
    assert rep["tensors"][0]["shape"] == [3, 4]


def test_torch_zip_tensor_past_its_storage_is_skipped_with_the_reason():
    raw = fx.torch_zip_bytes({"ok": B, "w": W}, views={"w": (np.zeros(5, np.float32), 0, [4, 1])})
    ts = mt.load_bytes(raw, "short.pt")
    assert list(ts.tensors) == ["ok"]
    assert ts.skipped[0][0] == "w" and "reaches element 11 of a 5 element storage" in ts.skipped[0][1]


def test_torch_zip_zero_stride_cannot_claim_a_huge_tensor():
    """A zero stride makes every element the same storage value, so a four-value storage can declare
    any shape. It is refused before an index of that size is built."""
    view = {"w": (np.ones(4, np.float32), 0, [0, 0])}
    small = mt.load_bytes(fx.torch_zip_bytes({"ok": B, "w": np.zeros((2, 3))}, views=view), "small.pt")
    assert np.array_equal(small.tensors["w"], np.ones((2, 3)))                 # a modest zero-stride view is read
    huge = fx.torch_zip_bytes({"ok": B, "w": np.zeros((2, 3))}, views=view, declared={"w": (2 ** 30, 16)})
    ts = mt.load_bytes(huge, "huge.pt")
    assert list(ts.tensors) == ["ok"]
    assert ts.skipped == [("w", "huge.pt: tensor 'w': 17179869184 values is over the 64000000 value small-net cap")]


def test_many_zero_stride_tensors_are_refused_before_they_add_up(monkeypatch):
    """Each tensor under the per-tensor cap, together far over it, from a file of a few kB: the file is
    refused at the first tensor that would pass the cap, before that tensor is built."""
    import tracemalloc
    monkeypatch.setattr(mt, "MAX_ELEMENTS", 1_000_000)
    names = [f"w{i}" for i in range(12)]
    raw = fx.torch_zip_bytes({n: np.zeros((1, 1)) for n in names},
                             views={n: (np.ones(1, np.float32), 0, [0, 0]) for n in names},
                             declared={n: (1000, 1000) for n in names})
    assert len(raw) < 8000
    tracemalloc.start()
    try:
        with pytest.raises(mt.OverCap, match=r"2000000 values is over the 1000000 value small-net cap "
                                             r"\(refused at tensor 'w1', before it was built\)"):
            mt.load_bytes(raw, "many.pt")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 3 * 4_000_000                         # one 1000 x 1000 float32 tensor was built, not twelve


def test_npz_and_safetensors_values_are_counted_across_tensors(monkeypatch):
    monkeypatch.setattr(mt, "MAX_ELEMENTS", 15)                                # W alone (12) fits, W + B (15) fits
    assert sorted(mt.load_bytes(fx.npz_bytes({"W": W, "B": B}), "ok.npz").tensors) == ["B", "W"]
    monkeypatch.setattr(mt, "MAX_ELEMENTS", 14)
    with pytest.raises(mt.OverCap, match="15 values is over the 14 value small-net cap"):
        mt.load_bytes(fx.npz_bytes({"W": W, "B": B}), "two.npz")
    with pytest.raises(mt.OverCap, match="15 values is over the 14 value small-net cap"):
        mt.load_bytes(fx.safetensors_bytes({"W": W, "B": B.astype(np.float32)}), "two.safetensors")


def test_torch_zip_missing_storage_member_is_named():
    raw = fx.torch_zip_bytes({"w": W})
    src = zipfile.ZipFile(io.BytesIO(raw))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        for name in src.namelist():
            if not name.endswith("data/0"):
                zf.writestr(name, src.read(name))
    ts = mt.load_bytes(out.getvalue(), "gone.pt")
    assert not ts.tensors and "storage member data/0 is missing" in ts.skipped[0][1]


def test_plain_pickle_is_refused_by_name():
    with pytest.raises(mt.TensorError, match="is a pickle; it is never loaded"):
        mt.load_bytes(pickle.dumps({"W1": [[1.0, 2.0]], "b1": [0.5]}, protocol=4), "model.pkl")


# ---------------------------------------------------------------- JSON and the caps

def test_json_weights_nested_keys_become_dotted_names():
    doc = {"layer1": {"weight": W.tolist(), "bias": B.tolist()}, "note": "text", "ragged": [[1, 2], [3]]}
    ts = mt.load_bytes(json.dumps(doc).encode(), "weights.json")
    assert ts.kind == "json" and sorted(ts.tensors) == ["layer1.bias", "layer1.weight"]
    assert np.allclose(ts.tensors["layer1.weight"], W) and ts.tensors["layer1.weight"].shape == (3, 4)
    assert any(name == "ragged" for name, _why in ts.skipped)


def test_json_without_number_lists_is_not_a_model():
    with pytest.raises(mt.TensorError, match="not a model file"):
        mt.load_bytes(json.dumps({"name": "challenge", "points": 500}).encode(), "challenge.json")


def test_non_finite_tensor_is_dropped_with_the_reason():
    bad = W.copy()
    bad[1, 2] = np.nan
    ts = mt.load_bytes(fx.npz_bytes({"good": B, "bad": bad}), "nan.npz")
    assert list(ts.tensors) == ["good"]
    assert ("bad", "nan.npz: tensor 'bad' holds a non-finite value") in ts.skipped


def test_size_caps_are_named(tmp_path, monkeypatch):
    p = tmp_path / "net.npz"
    p.write_bytes(fx.npz_bytes({"W1": W}))
    monkeypatch.setattr(mt, "MAX_ELEMENTS", 11)
    with pytest.raises(mt.TensorError, match="12 values is over the 11 value small-net cap"):
        mt.load_file(p)
    monkeypatch.setattr(mt, "MAX_FILE", 64)
    with pytest.raises(mt.TensorError, match="over the 64 byte small-net cap"):
        mt.load_file(p)


def test_unreadable_path_is_a_tensor_error(tmp_path):
    with pytest.raises(mt.TensorError, match="cannot be read"):
        mt.load_file(tmp_path / "absent.npz")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
