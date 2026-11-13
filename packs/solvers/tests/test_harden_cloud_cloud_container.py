"""Container and IaC reader oracles: stdlib tar/JSON/hashlib, documented fields.

https://github.com/opencontainers/image-spec/blob/main/layer.md
https://github.com/opencontainers/image-spec/blob/main/image-layout.md
https://docs.docker.com/reference/compose-file/services/
https://kubernetes.io/docs/concepts/configuration/secret/
All image commands and manifests remain inert bytes; no container is run.
"""
import base64
import gzip
import hashlib
import io
import json
import os
import random
import socket
import subprocess
import tarfile

import pytest
import yaml
import cloud_container as engine


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("static container analysis attempted execution, extraction, or network")
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, blocked)
    monkeypatch.setattr(os, "system", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(tarfile.TarFile, "extract", blocked)
    monkeypatch.setattr(tarfile.TarFile, "extractall", blocked)


def _json(doc):
    return json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()


def _tar(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in files:
            item = tarfile.TarInfo(name)
            item.mode, item.mtime = 0o640, 0
            item.size = len(body)
            archive.addfile(item, io.BytesIO(body))
    return out.getvalue()


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _docker(layers):
    config = _json({"architecture": "amd64", "os": "linux",
        "config": {"Env": ["TOKEN=CSCTF{image_env}", "A=one=two"],
                   "Entrypoint": ["/bin/inert"], "Cmd": ["--never-run"], "User": "1000"},
        "rootfs": {"type": "layers", "diff_ids": [_digest(blob) for blob in layers]},
        "history": [{"created_by": "layer " + str(i)} for i in range(len(layers))]})
    names = [f"{i:064x}/layer.tar" for i in range(len(layers))]
    manifest = _json([{"Config": "config.json", "RepoTags": ["fixture:v1"], "Layers": names}])
    return {"manifest.json": manifest, "config.json": config, **dict(zip(names, layers))}


def _oci(layer):
    compressed = gzip.compress(layer, mtime=0)
    config = _json({"architecture": "arm64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": [_digest(layer)]},
                    "config": {"Env": ["TOKEN=CSCTF{oci_env}"], "Entrypoint": ["inert"]}})
    def desc(raw, media):
        return {"mediaType": media, "digest": _digest(raw), "size": len(raw)}
    manifest = _json({"schemaVersion": 2,
        "config": desc(config, "application/vnd.oci.image.config.v1+json"),
        "layers": [desc(compressed, "application/vnd.oci.image.layer.v1.tar+gzip")]})
    root = desc(manifest, "application/vnd.oci.image.manifest.v1+json")
    root["annotations"] = {"org.opencontainers.image.ref.name": "fixture:oci"}
    store = {"oci-layout": _json({"imageLayoutVersion": "1.0.0"}),
             "index.json": _json({"schemaVersion": 2, "manifests": [root]})}
    for raw in (config, manifest, compressed):
        store["blobs/sha256/" + hashlib.sha256(raw).hexdigest()] = raw
    return store, compressed, config, manifest


def test_docker_save_tar_whiteouts_and_recovered_content():
    first = _tar([("etc/secret", b"CSCTF{deleted_layer_secret}"), ("cache/old", b"old"), ("keep", b"first")])
    second = _tar([("etc/.wh.secret", b""), ("cache/.wh..wh..opq", b""), ("cache/new", b"new"), ("keep", b"second")])
    store = _docker([first, second])
    ev = engine.load({"fixture.tar": _tar(list(store.items()))})
    assert not ev.cut and len(ev.images) == 1
    image = ev.images[0]
    assert image.layout == "docker_save" and image.tags == ["fixture:v1"]
    assert image.env == {"TOKEN": "CSCTF{image_env}", "A": "one=two"}
    assert image.entrypoint == ["/bin/inert"] and image.cmd == ["--never-run"]
    assert image.config_digest == _digest(store["config.json"])
    assert image.layers[0].tar_sha256 == _digest(first)
    assert image.layers[0].declared_diff_id == _digest(first)
    assert image.layers[1].created_by == "layer 1"
    assert set(engine.final_listing(image)) == {"keep", "cache/new"}
    assert engine.final_listing(image)["keep"][0].data == b"second"
    assert [r["action"] for r in engine.find_path(image, "/etc/secret")] == ["add", "delete"]
    deleted = {row["path"]: row for row in engine.deleted_files(image)}
    assert set(deleted) == {"etc/secret", "cache/old"}
    assert deleted["etc/secret"]["entry"].data == b"CSCTF{deleted_layer_secret}"
    assert deleted["etc/secret"]["entry"].sha256 == hashlib.sha256(b"CSCTF{deleted_layer_secret}").hexdigest()
    assert "CSCTF{image_env}" in engine.render(engine.summary(ev))


def test_oci_tar_descriptor_and_decompression_hashes():
    layer = _tar([("app/settings", b"CSCTF{oci_file}")])
    store, compressed, config, manifest = _oci(layer)
    ev = engine.load({"oci.tar": _tar(list(store.items()))})
    assert not ev.cut and len(ev.images) == 1
    image = ev.images[0]
    assert image.layout == "oci" and image.tags == ["fixture:oci"]
    assert image.config_digest == _digest(config) and image.manifest_digest == _digest(manifest)
    assert image.layers[0].declared_digest == image.layers[0].blob_sha256 == _digest(compressed)
    assert image.layers[0].tar_sha256 == image.layers[0].declared_diff_id == _digest(layer)
    assert engine.final_listing(image)["app/settings"][0].data == b"CSCTF{oci_file}"


def test_deleted_files_excludes_recreated_paths():
    image = engine.read_image(_docker([_tar([("secret", b"old")]), _tar([(".wh.secret", b"")]),
                                       _tar([("secret", b"new")])]))[0]
    assert engine.deleted_files(image) == []


def test_tar_path_inventory_and_keep_cap():
    entries, problems = engine.read_tar(_tar([("../outside", b"secret"), ("./safe", b"12345678")]), keep=4)
    assert entries["../outside"].unsafe is True
    assert problems and "unsafe path" in problems[0]
    assert entries["safe"].data is None and entries["safe"].size == 8
    assert entries["safe"].sha256 == hashlib.sha256(b"12345678").hexdigest()


def test_tar_total_and_member_caps(monkeypatch):
    raw = _tar([("one", b"12345"), ("two", b"67890")])
    ev = engine.load({"fixture.tar": raw}, max_total=7)
    assert {"image", "logs", "tf", "files"} <= ev.cut
    monkeypatch.setitem(engine.read_tar.__globals__, "MAX_MEMBERS", 1)
    with pytest.raises(engine.Cut):
        engine.read_tar(raw)


def test_tar_oversize_member_is_never_read(monkeypatch):
    raw = _tar([("large", b"X" * 100)])
    monkeypatch.setitem(engine.read_tar.__globals__, "MAX_FILE", 16)
    def forbidden(*args, **kwargs):
        raise AssertionError("oversize member was read")
    monkeypatch.setattr(tarfile.TarFile, "extractfile", forbidden)
    entries, problems = engine.read_tar(raw)
    assert entries["large"].data is None and entries["large"].sha256 is None
    assert any("larger than the limit" in p for p in problems)


def test_gzip_known_payload_and_small_output_cap():
    raw = gzip.compress(b"A" * 20, mtime=0) + gzip.compress(b"B" * 20, mtime=0)
    assert engine.gunzip(raw) == b"A" * 20 + b"B" * 20
    with pytest.raises(engine.Cut):
        engine.gunzip(raw, limit=32)


def _manifest_docs():
    return [{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "credentials", "namespace": "fixture"},
             "data": {"token": base64.b64encode(b"CSCTF{k8s_data}").decode()},
             "stringData": {"password": "CSCTF{k8s_plain}"}},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "worker", "namespace": "fixture"},
             "spec": {"serviceAccountName": "fixture-sa", "hostNetwork": True,
                      "containers": [{"name": "app", "image": "fixture:v1", "env": [{"name": "TOKEN", "value": "abc"}],
                                      "securityContext": {"privileged": True}, "command": ["inert"]}],
                      "volumes": [{"name": "host", "hostPath": {"path": "/host/data"}}]}}]


def test_k8s_json_yaml_secrets_and_pod_fields():
    docs = _manifest_docs()
    rows = engine.read_k8s_manifests([{"kind": "List", "apiVersion": "v1", "items": docs}])
    assert rows[0]["secret"]["token"] == (base64.b64encode(b"CSCTF{k8s_data}").decode(), "CSCTF{k8s_data}")
    assert rows[0]["secret"]["password"] == (None, "CSCTF{k8s_plain}")
    assert rows[1]["service_account"] == "fixture-sa" and rows[1]["host_network"] is True
    assert rows[1]["host_paths"] == ["/host/data"]
    assert rows[1]["containers"][0]["privileged"] is True
    assert rows[1]["containers"][0]["env"] == {"TOKEN": "abc"}
    ev = engine.load({"fixture.yaml": yaml.safe_dump_all(docs).encode()})
    assert [r["name"] for r in ev.k8s] == ["credentials", "worker"] and not ev.cut


def test_compose_real_yaml_writer_fields():
    doc = {"services": {"app": {"image": "fixture:v1", "environment": ["TOKEN=CSCTF{compose}", "INHERITED"],
        "ports": ["127.0.0.1:8080:80"], "volumes": ["./data:/data:ro"], "privileged": True,
        "entrypoint": ["inert"], "command": ["argument"], "cap_add": ["NET_ADMIN"]}}}
    row = engine.read_compose(doc)[0]
    assert row["service"] == "app" and row["image"] == "fixture:v1"
    assert row["env"] == {"TOKEN": "CSCTF{compose}", "INHERITED": None}
    assert row["ports"] == ["127.0.0.1:8080:80"] and row["volumes"] == ["./data:/data:ro"]
    assert row["privileged"] is True and row["cap_add"] == ["NET_ADMIN"]
    assert engine.load({"compose.yaml": yaml.safe_dump(doc).encode()}).compose[0]["env"] == row["env"]


def _state():
    return {"version": 4, "terraform_version": "1.5.0", "serial": 1, "lineage": "fixture",
        "resources": [{"mode": "managed", "type": "example_service", "name": "app", "module": "module.fixture",
            "instances": [{"index_key": "blue", "attributes": {"id": "service-1", "password": "CSCTF{tf_secret}", "ports": [80]},
                "sensitive_attributes": [[{"type": "get_attr", "value": "password"}]]}]}],
        "outputs": {"endpoint": {"value": "internal.example", "sensitive": False},
                    "opaque": {"value": "CSCTF{output_secret}", "sensitive": True}}}


def test_terraform_known_state_and_sensitivity():
    state = _state()
    rows = engine.tf_leaves(state)
    password = next(r for r in rows if r["path"] == "password")
    assert password["address"] == 'module.fixture.example_service.app["blue"]'
    assert password["value"] == "CSCTF{tf_secret}" and password["sensitive"] is True
    assert [(r["address"], r["value"]) for r in engine.tf_sensitive(state, by_name=False)] == [
        ('module.fixture.example_service.app["blue"]', "CSCTF{tf_secret}"), ("output.opaque", "CSCTF{output_secret}")]
    assert len(engine.load({"state.tfstate": _json(state)}).tf_rows) == 5


def test_terraform_node_cap(monkeypatch):
    monkeypatch.setitem(engine.tf_leaves.__globals__, "MAX_NODES", 3)
    with pytest.raises(engine.Cut):
        engine.tf_leaves(_state())


def test_dockerfile_inert_instructions():
    text = 'FROM fixture:v1 AS build\nENV TOKEN="CSCTF{dockerfile}" A=two\nRUN never-execute\n' \
           'FROM scratch\nCOPY --from=build /out /app\nENTRYPOINT ["/app"]\nCMD ["--help"]\n'
    rows = engine.parse_dockerfile(text)["stages"]
    assert rows[0]["name"] == "build" and rows[0]["env"] == {"TOKEN": "CSCTF{dockerfile}", "A": "two"}
    assert rows[0]["runs"] == ["never-execute"]
    assert rows[1]["copies"] == ["--from=build /out /app"] and rows[1]["entrypoint"] == ["/app"]
    assert rows[1]["cmd"] == ["--help"]


def test_yaml_alias_budget_and_unsafe_tag_are_rejected():
    aliases = "services: &shared {}\nvalues: [" + ",".join(["*shared"] * 65) + "]\n"
    ev = engine.load({"compose.yaml": aliases.encode()})
    assert "files" in ev.cut and ev.compose == []
    unsafe = b'services: !!python/object/apply:os.system ["NEVER_EXECUTE"]\n'
    ev = engine.load({"compose.yaml": unsafe})
    assert "files" in ev.cut and ev.compose == []


@pytest.mark.parametrize("value", [None, "", "garbage", "2024-99-99T25:61:99Z", float("inf"), float("nan"), 10**1000])
def test_parse_time_malformed(value):
    assert engine.parse_time(value) is None


def test_static_binary_fuzz_through_safe_wrappers():
    rng = random.Random(0xC10D)
    seeds = [_tar([("known", b"value")]), gzip.compress(b'{"Records":[]}', mtime=0),
             _json(_state()), yaml.safe_dump_all(_manifest_docs()).encode()]
    corpus = [b"", b"\xff" * 512, bytes(rng.randrange(256) for _ in range(1024))]
    for seed in seeds:
        corpus += [seed[:n] for n in (1, 4, 16, len(seed) // 2, len(seed) - 1)]
        mutation = bytearray(seed)
        mutation[len(mutation) // 2] ^= 0x80
        corpus.append(bytes(mutation))
    for raw in corpus:
        assert isinstance(engine.load({"fixture": raw}), engine.Evidence)
        assert isinstance(engine.load_records(raw), tuple)
        assert isinstance(engine.read_layer(raw, 0, "fixture"), engine.Layer)
        assert isinstance(engine.parse_dockerfile(raw.decode("latin1")), dict)


@pytest.mark.parametrize("raw", [b"", b"\xff" * 512, b"ustar", _tar([("known", b"value")])[:514]])
def test_read_tar_malformed_contract(raw):
    try:
        engine.read_tar(raw)
    except engine.Cut:
        pass


@pytest.mark.parametrize("raw", [b"\x1f\x8b", b"\x1f\x8b" + b"\xff" * 20,
                                 gzip.compress(b"known", mtime=0)[:-3]])
def test_gunzip_malformed_contract(raw):
    try:
        engine.gunzip(raw)
    except engine.Cut:
        pass


@pytest.mark.parametrize("call", [
    lambda: engine.read_image({"manifest.json": b'[{"Layers":1}]'}),
    lambda: engine.read_image({"index.json": b'{"manifests":[{"digest":"sha256:abc"}]}',
                              "oci-layout": b'{}', "blobs/sha256/abc": b'[]'}),
    lambda: engine.read_compose({"services": {"app": {"ports": 7}}}),
    lambda: engine.read_k8s_manifests([{"apiVersion": "v1", "kind": "Pod", "subjects": 7}]),
    lambda: engine.tf_leaves({"resources": [{"instances": 7}]}),
    lambda: engine.load_records(None),
    lambda: engine.parse_dockerfile(None),
])
def test_malformed_structure_contract(call):
    try:
        call()
    except engine.Cut:
        pass


def test_terraform_depth_bound():
    nested = "leaf"
    for _ in range(1500):
        nested = {"x": nested}
    leaked = None
    try:
        engine.tf_leaves({"outputs": {"nested": {"value": nested}}})
    except engine.Cut:
        pass
    except Exception as exc:
        # Keep pytest from rendering 1,000 recursive engine stack frames.
        leaked = type(exc).__name__
    assert leaked is None, f"leaked {leaked}"


def test_cli_usage_is_guarded(capsys):
    assert engine.main([]) == 2
    assert engine.main(["--unknown"]) == 2
