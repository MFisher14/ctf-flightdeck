import base64
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import unicodedata
from pathlib import Path

import pytest
import zstandard

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import container_iac as ci


def tar_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, body in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(body))
    return stream.getvalue()


def docker_save_fixture():
    layer0 = tar_bytes({"app/.env": b"API_TOKEN=first-secret", "app/keep.txt": b"old"})
    layer1 = tar_bytes({"app/.wh..env": b"", "app/keep.txt": b"new",
                        "app/live.txt": b"AKIAABCDEFGHIJKLMNOP"})  # secret-scan: allow
    config = {"architecture": "amd64", "os": "linux", "config": {
        "Env": ["PASSWORD=config-secret", "NORMAL=value"]},
        "history": [{"created_by": "RUN token=history-secret"}]}
    manifest = [{"Config": "config.json", "RepoTags": ["demo:latest"],
                 "Layers": ["l0/layer.tar", "l1/layer.tar"]}]
    return tar_bytes({"manifest.json": json.dumps(manifest).encode(), "config.json": json.dumps(config).encode(),
                      "l0/layer.tar": layer0, "l1/layer.tar": layer1})


def test_docker_whiteout_overwrite_and_secret_recovery():
    image = ci.analyze_image_archive(docker_save_fixture())
    assert image.format == "docker-save"
    assert "app/.env" not in image.files and image.files["app/keep.txt"].content == b"new"
    reasons = {item.path: item.reason for item in image.recovered}
    assert reasons["app/.env"] == "whiteout@layer-1"
    assert reasons["app/keep.txt"] == "overwritten@layer-1"
    report = image.report()
    assert report["config"]["environment_names"] == ["NORMAL", "PASSWORD"]
    assert {item["kind"] for item in report["findings"]} >= {"embedded-secret", "config-env-secret"}
    assert any(item.get("recovered") and item.get("value") == "first-secret" for item in report["findings"])
    assert any(item.get("secret_type") == "aws-access-key" for item in report["findings"])


def test_oci_layout_digest_validation_and_opaque_whiteout():
    layer0 = tar_bytes({"dir/a": b"a", "dir/sub/b": b"b", "outside": b"c"})
    layer1 = tar_bytes({"dir/.wh..wh..opq": b"", "dir/new": b"n"})
    config = json.dumps({"architecture": "arm64", "os": "linux", "config": {}}).encode()
    descriptors = []
    store = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}'}
    for body, media in [(layer0, "application/vnd.oci.image.layer.v1.tar"),
                        (layer1, "application/vnd.oci.image.layer.v1.tar")]:
        digest = hashlib.sha256(body).hexdigest(); store[f"blobs/sha256/{digest}"] = body
        descriptors.append({"mediaType": media, "digest": "sha256:" + digest, "size": len(body)})
    cfg_digest = hashlib.sha256(config).hexdigest(); store[f"blobs/sha256/{cfg_digest}"] = config
    manifest = json.dumps({"schemaVersion": 2,
                           "config": {"digest": "sha256:" + cfg_digest, "size": len(config)},
                           "layers": descriptors}).encode()
    manifest_digest = hashlib.sha256(manifest).hexdigest(); store[f"blobs/sha256/{manifest_digest}"] = manifest
    store["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [{
        "digest": "sha256:" + manifest_digest, "size": len(manifest)}]}).encode()
    image = ci.analyze_image_archive(tar_bytes(store))
    assert image.format == "oci-layout"
    assert set(image.files) == {"dir/new", "outside"}
    assert {item.path for item in image.recovered} == {"dir/a", "dir/sub/b"}


def test_directory_whiteout_removes_all_lower_descendants():
    layer0 = tar_bytes({"tree/a": b"a", "tree/sub/b": b"b", "tree2/c": b"c"})
    layer1 = tar_bytes({".wh.tree": b"", "new": b"n"})
    config = {"config": {}}
    manifest = [{"Config": "config.json", "Layers": ["0.tar", "1.tar"]}]
    outer = tar_bytes({"manifest.json": json.dumps(manifest).encode(), "config.json": json.dumps(config).encode(),
                       "0.tar": layer0, "1.tar": layer1})
    image = ci.analyze_image_archive(outer)
    assert set(image.files) == {"tree2/c", "new"}
    assert {item.path for item in image.recovered} == {"tree/a", "tree/sub/b"}


def test_zstd_layer_is_read_without_execution_or_extraction():
    raw_layer = tar_bytes({"compressed/file": b"value"})
    layer = zstandard.ZstdCompressor().compress(raw_layer)
    config = {"config": {}}
    manifest = [{"Config": "config.json", "Layers": ["layer.tar.zst"]}]
    outer = tar_bytes({"manifest.json": json.dumps(manifest).encode(), "config.json": json.dumps(config).encode(),
                       "layer.tar.zst": layer})
    image = ci.analyze_image_archive(outer)
    assert image.files["compressed/file"].content == b"value"


def test_cloudformation_kubernetes_and_terraform_exposures():
    cfn = {"AWSTemplateFormatVersion": "2010-09-09",
           "Parameters": {"DbPassword": {"Type": "String", "Default": "p@ssword"}},
           "Resources": {
               "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}},
               "BucketPolicy": {"Type": "AWS::S3::BucketPolicy", "Properties": {"PolicyDocument": {
                   "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject"}]}}},
               "SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": [
                   {"CidrIp": "0.0.0.0/0", "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}]}},
               "Role": {"Type": "AWS::IAM::Role", "Properties": {"Policies": [{"PolicyDocument": {
                   "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}}}}
    report = ci.analyze_iac_artifact(json.dumps(cfn).encode(), "template.json")
    kinds = {item["kind"] for item in report["findings"]}
    assert {"cfn-sensitive-parameter-visible", "cfn-sensitive-default", "cfn-public-bucket",
            "cfn-public-bucket-policy", "cfn-world-open-ingress", "cfn-iam-wildcard"} <= kinds

    k8s = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "bad"},
           "spec": {"template": {"spec": {"volumes": [{"name": "root", "hostPath": {"path": "/"}}],
               "containers": [{"name": "app", "securityContext": {"privileged": True},
                               "env": [{"name": "API_TOKEN", "value": "literal-secret"}]}]}}}}
    report = ci.analyze_iac_artifact(json.dumps(k8s).encode(), "pod.json")
    kinds = {item["kind"] for item in report["findings"]}
    assert {"k8s-hostpath", "k8s-privileged-container", "k8s-env-secret", "k8s-token-automount"} <= kinds

    hcl = b'''provider "aws" { access_key = "AKIAABCDEFGHIJKLMNOP"\n secret_key = "literal-secret" }  # secret-scan: allow
resource "aws_s3_bucket_acl" "x" { acl = "public-read" }
resource "aws_security_group" "x" { cidr_blocks = ["0.0.0.0/0"] }
'''
    report = ci.analyze_iac_artifact(hcl, "main.tf")
    kinds = {item["kind"] for item in report["findings"]}
    assert {"terraform-provider-credential", "terraform-public-acl", "terraform-world-open"} <= kinds

    comments = b'''# access_key = "comment-secret"
/* acl = "public-read" */
resource "x" "y" { cidr_blocks = ["0.0.0.0/0"] } // secret_key = "comment-secret"
provider "x" { endpoint = "https://example.test/api" }
access_key = "real-secret"
'''
    report = ci.analyze_iac_artifact(comments, "comments.tf")
    kinds = {item["kind"] for item in report["findings"]}
    assert "terraform-world-open" in kinds
    assert "terraform-provider-credential" in kinds and "terraform-public-acl" not in kinds
    credentials = [item for item in report["findings"] if item["kind"] == "terraform-provider-credential"]
    assert [item["value"] for item in credentials] == ["real-secret"]


def test_k8s_secret_decode_generic_text_and_path_guard():
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "s"},
              "data": {"password": base64.b64encode(b"decoded-value").decode()}}
    report = ci.analyze_iac_artifact(json.dumps(secret).encode(), "secret.json")
    item = next(item for item in report["findings"] if item["kind"] == "k8s-secret-in-manifest")
    assert item["value"] == "decoded-value"
    generic = ci.analyze_iac_artifact(b"token=generic-secret", "settings.env")
    assert any(item.get("value") == "generic-secret" for item in generic["findings"])
    with pytest.raises(ValueError):
        ci._path("../escape")


def test_malformed_archives_decline_deterministically():
    with pytest.raises(ValueError):
        ci.analyze_image_archive(b"not a tar")
    outer = tar_bytes({"manifest.json": b"[]"})
    with pytest.raises(ValueError):
        ci.analyze_image_archive(outer)


def test_compressed_layer_expansion_bound(monkeypatch):
    monkeypatch.setattr(ci, "MAX_ARCHIVE", 32)
    with pytest.raises(ValueError, match="cap"):
        ci._decompress_layer(gzip.compress(b"A" * 1000))


# ---------------------------------------------------------------- B-072: the layer dumper

def layer_tar(entries):
    """A layer tar: {name: bytes} regular files, {name: ("sym", target)} symbolic links,
    {name: ("lnk", target)} hard links, {name: ("dir",)} directories."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, body in entries.items():
            info = tarfile.TarInfo(name)
            if isinstance(body, tuple):
                if body[0] == "dir":
                    info.type, info.mode = tarfile.DIRTYPE, 0o755
                else:
                    info.type = tarfile.SYMTYPE if body[0] == "sym" else tarfile.LNKTYPE
                    info.linkname = body[1]
                archive.addfile(info)
                continue
            info.size, info.mode = len(body), 0o644
            archive.addfile(info, io.BytesIO(body))
    return stream.getvalue()


def _blob(store, body):
    digest = hashlib.sha256(body).hexdigest()
    store[f"blobs/sha256/{digest}"] = body
    return {"digest": "sha256:" + digest, "size": len(body)}


SEAL_COMMENT = "seal: HMAC-SHA256 of the sealed key, keyed by the build.seal label"


def sealed_layout(*, diff_ids="right", nested=False, docker_manifest=False, clash=False):
    """A synthetic OCI layout shaped like the B-072 case: a marker file written twice, then whited
    out, with a LABEL step (an empty layer) and the recipe in a history comment."""
    raw = [layer_tar({"etc/os-release": b"ID=demo\n", "bin/sh": ("sym", "/bin/busybox")}),
           layer_tar({"app/.sealed_marker": b"revision-A", "app/key.sealed": b"\x01\x02\x03"}),
           layer_tar({"app/.sealed_marker": b"revision-B"}),
           layer_tar({"app/.wh..sealed_marker": b""})]
    store = {"oci-layout": b'{"imageLayoutVersion": "1.0.0"}'}
    layers = [_blob(store, gzip.compress(body, mtime=0)) | {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}
              for body in raw]
    ids = ["sha256:" + hashlib.sha256(body).hexdigest() for body in raw]
    if diff_ids == "swapped":
        ids[1], ids[2] = ids[2], ids[1]
    elif diff_ids == "short":
        ids = ids[:3]
    config = {"architecture": "amd64", "os": "linux",
              "config": {"Labels": {"build.seal": "s3al-label", "org.opencontainers.image.title": "demo"}},
              "rootfs": {"type": "layers", "diff_ids": ids},
              "history": [{"created_by": "ADD rootfs.tar /"},
                          {"created_by": "COPY app /app"},
                          {"created_by": "LABEL build.seal=s3al-label", "empty_layer": True},
                          {"created_by": "RUN reseal", "comment": SEAL_COMMENT,
                           "created": "2026-11-07T10:00:00Z", "author": "builder@demo"},
                          {"created_by": "RUN rm /app/.sealed_marker"}]}
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": _blob(store, json.dumps(config).encode()), "layers": layers,
                "annotations": {"org.opencontainers.image.created": "2026-11-07"}}
    index_notes = {"org.opencontainers.image.ref.name": "latest"}
    descriptor_notes = {}
    if clash:   # one key at all three levels, one at the index and its descriptor only
        manifest["annotations"]["clash.all"] = "from-manifest"
        descriptor_notes = {"clash.all": "from-descriptor", "clash.two": "from-descriptor"}
        index_notes |= {"clash.all": "from-index", "clash.two": "from-index"}
    image = _blob(store, json.dumps(manifest).encode()) | {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "platform": {"architecture": "amd64", "os": "linux"}}
    if descriptor_notes:
        image["annotations"] = descriptor_notes
    top = [image]
    if nested:
        attestation = _blob(store, json.dumps({"schemaVersion": 2, "config": _blob(store, b"{}"), "layers": []}).encode())
        inner = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                 "manifests": [attestation | {"platform": {"architecture": "unknown", "os": "unknown"}}, image]}
        top = [_blob(store, json.dumps(inner).encode()) | {"mediaType": "application/vnd.oci.image.index.v1+json",
                                                          "annotations": {"io.containerd.image.name": "demo:1"}}]
    store["index.json"] = json.dumps({"schemaVersion": 2, "manifests": top, "annotations": index_notes}).encode()
    if docker_manifest:   # Docker 25+ saves both; this one names a layer that is not there
        store["manifest.json"] = json.dumps([{"Config": "missing.json", "Layers": ["nope/layer.tar"]}]).encode()
    return store


def write_tree(root, store):
    for name, body in store.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    return root


def test_report_has_labels_history_comments_and_every_version():
    report = ci.analyze_image_archive(tar_bytes(sealed_layout())).report()
    assert report["format"] == "oci-layout"
    assert report["labels"] == {"build.seal": "s3al-label", "org.opencontainers.image.title": "demo"}
    assert report["annotations"] == {"org.opencontainers.image.created": "2026-11-07",
                                     "org.opencontainers.image.ref.name": "latest"}
    assert report["platform"] == {"architecture": "amd64", "os": "linux"}
    # The LABEL step made no layer; the steps around it map in order onto layers 0..3.
    assert [(row["layer"], row["empty_layer"]) for row in report["history"]] == [
        (0, False), (1, False), (None, True), (2, False), (3, False)]
    assert report["history"][3]["comment"] == SEAL_COMMENT
    assert (report["history"][3]["created"], report["history"][3]["author"]) == ("2026-11-07T10:00:00Z", "builder@demo")
    assert not {"comment", "created", "author"} & set(report["history"][0])
    marker = [(row["layer"], row["created_by"], row["reason"]) for row in report["versions"]
              if row["path"] == "app/.sealed_marker"]
    assert marker == [(1, "COPY app /app", "overwritten@layer-2"), (2, "RUN reseal", "whiteout@layer-3")]
    sealed = next(row for row in report["versions"] if row["path"] == "app/.sealed_marker" and row["layer"] == 2)
    assert sealed["comment"] == SEAL_COMMENT
    assert sealed["sha256"] == hashlib.sha256(b"revision-B").hexdigest()
    assert report["layers"][2]["created_by"] == "RUN reseal" and report["layers"][2]["comment"] == SEAL_COMMENT
    assert report["layers"][3]["whiteouts"] == [{"path": "app/.sealed_marker", "opaque": False,
                                                 "deleted": ["app/.sealed_marker"]}]
    assert [layer["media_type"] for layer in report["layers"]] == ["application/vnd.oci.image.layer.v1.tar+gzip"] * 4
    assert all(layer["diff_id_ok"] for layer in report["layers"])
    assert not any(item["kind"].startswith("layer-") for item in report["findings"])
    assert len(report["versions"]) == 5   # every file version, the link included


def test_history_past_the_last_layer_maps_to_no_layer():
    config = {"history": [{"created_by": "a"}, {"created_by": "b"}, {"created_by": "c", "empty_layer": True}]}
    rows = ci.image_history(config, 1)
    assert [row["layer"] for row in rows] == [0, None, None]
    assert ci.layer_history(rows) == {0: rows[0]}


def test_diff_ids_out_of_order_or_short_are_flagged():
    report = ci.analyze_image_archive(tar_bytes(sealed_layout(diff_ids="swapped"))).report()
    assert [layer["diff_id_ok"] for layer in report["layers"]] == [True, False, False, True]
    flagged = sorted(item["layer"] for item in report["findings"] if item["kind"] == "layer-diff-id-mismatch")
    assert flagged == [1, 2]
    assert report["layers"][1]["diff_id_expected"] == report["layers"][2]["diff_id"]
    short = ci.analyze_image_archive(tar_bytes(sealed_layout(diff_ids="short"))).report()
    assert [layer["diff_id_ok"] for layer in short["layers"]] == [True, True, True, False]
    assert {item["kind"] for item in short["findings"]} >= {"layer-count-mismatch", "layer-diff-id-mismatch"}


def test_nested_index_skips_the_attestation_and_merges_annotations():
    report = ci.analyze_image_archive(tar_bytes(sealed_layout(nested=True))).report()
    assert report["layer_count"] == 4
    assert report["platform"] == {"architecture": "amd64", "os": "linux"}
    assert report["annotations"]["io.containerd.image.name"] == "demo:1"
    assert report["annotations"]["org.opencontainers.image.ref.name"] == "latest"


def test_index_nesting_is_capped():
    store = {"oci-layout": b"{}"}
    child = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []}
    for _ in range(ci.MAX_INDEX_DEPTH + 1):
        child = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                 "manifests": [_blob(store, json.dumps(child).encode())]}
    store["index.json"] = json.dumps(child).encode()
    with pytest.raises(ValueError, match="depth cap"):
        ci.analyze_image_archive(tar_bytes(store))


def test_oci_layout_marker_wins_over_a_docker_manifest():
    image = ci.analyze_image_archive(tar_bytes(sealed_layout(docker_manifest=True)))
    assert image.format == "oci-layout" and image.files["app/key.sealed"].content == b"\x01\x02\x03"


def test_folder_marker_file_and_tar_read_the_same(tmp_path):
    store = sealed_layout()
    root = write_tree(tmp_path / "layout", store)
    archive = tmp_path / "image.tar"
    archive.write_bytes(tar_bytes(store))
    reports = [ci.analyze_image_path(target).report() for target in
               (root, root / "oci-layout", root / "index.json", archive)]
    assert all(report == reports[0] for report in reports[1:])
    assert ci.image_root(root / "oci-layout") == root and ci.image_root(archive) == archive
    with pytest.raises(ValueError, match="no such image input"):
        ci.analyze_image_path(tmp_path / "absent")


def test_layout_folder_never_follows_a_link(tmp_path):
    store = sealed_layout()
    root = write_tree(tmp_path / "layout", store)
    victim = next(name for name in store if name.startswith("blobs/") and store[name].startswith(b"\x1f\x8b"))
    outside = tmp_path / "outside-blob"
    outside.write_bytes(store[victim])
    (root / victim).unlink()
    (root / victim).symlink_to(outside)
    with pytest.raises(ValueError, match="missing OCI blob"):
        ci.analyze_layout_dir(root)
    linked = tmp_path / "linked"
    linked.symlink_to(root)
    with pytest.raises(ValueError, match="not an image folder"):
        ci.LayoutDir(linked)
    assert "../oci-layout" not in ci.LayoutDir(root)
    assert "oci-layout" in ci.LayoutDir(root)


def test_layout_folder_read_is_capped(tmp_path, monkeypatch):
    root = write_tree(tmp_path / "layout", sealed_layout())
    monkeypatch.setattr(ci, "MAX_TOTAL", 600)
    with pytest.raises(ValueError, match="total cap"):
        ci.analyze_layout_dir(root)


def test_dump_writes_each_version_per_layer_and_an_index(tmp_path):
    image = ci.analyze_image_archive(tar_bytes(sealed_layout()))
    folder = ci.dump_image(image, tmp_path / "out")
    assert folder.parent == tmp_path / "out" and folder.name == "image-" + image.identity()[:12]
    assert (folder / "layers/01/app/.sealed_marker").read_bytes() == b"revision-A"
    assert (folder / "layers/02/app/.sealed_marker").read_bytes() == b"revision-B"
    assert (folder / "layers/01/app/key.sealed").read_bytes() == b"\x01\x02\x03"
    assert (folder / "layers/00/etc/os-release").read_bytes() == b"ID=demo\n"
    assert not (folder / "layers/03/app/.sealed_marker").exists()       # whited out, not re-added
    assert not os.path.lexists(folder / "layers/00/bin/sh")             # links are listed, never made
    assert json.loads((folder / "config.json").read_text())["config"]["Labels"]["build.seal"] == "s3al-label"
    saved = json.loads((folder / "report.json").read_text())
    assert saved["dump"] == {"folder": str(folder), "errors": [], "renamed": []}
    assert saved["versions"] == image.report()["versions"]
    index = (folder / "index.md").read_text()
    assert "- `build.seal` = `s3al-label`" in index
    assert "- `org.opencontainers.image.ref.name` = `latest`" in index
    assert f"| 3 | 2 | RUN reseal | {SEAL_COMMENT} |" in index
    assert "| 2 | empty | LABEL build.seal=s3al-label |  |" in index
    assert "- whiteout of `app/.sealed_marker`, deleting `app/.sealed_marker`" in index
    assert "| `bin/sh` | 0 |" in index and "-> `/bin/busybox`" in index
    assert f"- comment: {SEAL_COMMENT}" in index.split("## Layer 02")[1].split("## Layer 03")[0]
    assert "## Not written" not in index
    # The same image dumps to the same folder again; a different one does not.
    assert ci.dump_image(ci.analyze_image_archive(tar_bytes(sealed_layout())), tmp_path / "out") == folder
    assert ci.dump_image(ci.analyze_image_archive(tar_bytes(sealed_layout(diff_ids="short"))),
                         tmp_path / "out") != folder


def test_dump_refuses_to_write_through_a_link(tmp_path):
    image = ci.analyze_image_archive(tar_bytes(sealed_layout()))
    folder = tmp_path / "out" / f"image-{image.identity()[:12]}"
    (folder / "layers").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (folder / "layers" / "01").symlink_to(elsewhere)
    ci.dump_image(image, tmp_path / "out")
    assert list(elsewhere.iterdir()) == []
    errors = json.loads((folder / "report.json").read_text())["dump"]["errors"]
    assert sorted(item.split(":")[0] for item in errors) == ["layers/01/app/.sealed_marker", "layers/01/app/key.sealed"]
    assert "## Not written" in (folder / "index.md").read_text()
    assert (folder / "layers/02/app/.sealed_marker").read_bytes() == b"revision-B"


def test_dump_refuses_a_planted_file_link(tmp_path):
    image = ci.analyze_image_archive(tar_bytes(sealed_layout()))
    folder = tmp_path / "out" / f"image-{image.identity()[:12]}"
    (folder / "layers/02/app").mkdir(parents=True)
    target = tmp_path / "target.txt"
    target.write_bytes(b"untouched")
    (folder / "layers/02/app/.sealed_marker").symlink_to(target)
    ci.dump_image(image, tmp_path / "out")
    assert target.read_bytes() == b"untouched"
    errors = json.loads((folder / "report.json").read_text())["dump"]["errors"]
    assert [item.split(":")[0] for item in errors] == ["layers/02/app/.sealed_marker"]


def test_index_cells_cannot_break_the_table():
    assert ci._md_cell("a|b\nc") == "a\\|b c"
    # A backslash is escaped first, so a literal `\|` cannot turn the pipe escape back off.
    assert ci._md_cell("a\\|b") == "a\\\\\\|b"


def test_manifest_annotation_wins_over_its_descriptor_and_the_index():
    report = ci.analyze_image_archive(tar_bytes(sealed_layout(clash=True))).report()
    assert report["annotations"]["clash.all"] == "from-manifest"
    assert report["annotations"]["clash.two"] == "from-descriptor"


def test_layout_folder_caps_each_member(tmp_path, monkeypatch):
    root = write_tree(tmp_path / "layout", sealed_layout())
    size = (root / "index.json").stat().st_size
    store = ci.LayoutDir(root)
    monkeypatch.setattr(ci, "MAX_ARCHIVE", size)
    assert store["index.json"] == (root / "index.json").read_bytes()     # at the cap: read
    monkeypatch.setattr(ci, "MAX_ARCHIVE", size - 1)
    with pytest.raises(ValueError, match="image member exceeds input cap: index.json"):
        store["index.json"]
    assert store.total == size     # the refused member was not counted


def docker_image(*layers, config=None):
    """A docker-save tar of the given layer tars."""
    names = [f"{n}/layer.tar" for n in range(len(layers))]
    manifest = [{"Config": "config.json", "Layers": names}]
    return tar_bytes({"manifest.json": json.dumps(manifest).encode(),
                      "config.json": json.dumps(config or {"config": {}}).encode(), **dict(zip(names, layers))})


def test_a_layer_made_from_its_root_folder_dumps(tmp_path):
    # `tar -C rootfs -cf layer.tar .` writes a `./` root entry and `./`-prefixed names.
    rootfs = tmp_path / "rootfs"
    (rootfs / "app").mkdir(parents=True)
    (rootfs / "app" / "flag.txt").write_bytes(b"from-a-dot-layer")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        archive.add(rootfs, arcname=".")
        assert archive.getnames()[0] == "."
    dotted = layer_tar({"./": ("dir",), "./etc/": ("dir",), "./etc/hostname": b"box"})
    image = ci.analyze_image_archive(docker_image(stream.getvalue(), dotted))
    assert image.files["app/flag.txt"].content == b"from-a-dot-layer" and image.files["etc/hostname"].content == b"box"
    folder = ci.dump_image(image, tmp_path / "out")
    assert (folder / "layers/00/app/flag.txt").read_bytes() == b"from-a-dot-layer"
    # Only directories are let past unchecked: a file that climbs out of the layer still fails the image.
    with pytest.raises(ValueError, match="unsafe archive path"):
        ci.analyze_image_archive(docker_image(layer_tar({"./": ("dir",), "../escape": b"x"})))
    with pytest.raises(ValueError, match="unsafe"):
        ci.analyze_image_archive(docker_image(layer_tar({"../up": ("lnk", "etc/passwd")})))


def test_hard_links_carry_their_targets_bytes(tmp_path):
    # app/real is replaced in layer 1 before the link to it: the link carries the new bytes.
    lower = layer_tar({"lower/secret": b"from-layer-0", "app/real": b"OLD"})
    upper = layer_tar({"app/real": b"FLAG-BYTES", "app/same-layer": ("lnk", "app/real"),
                       "app/lower-layer": ("lnk", "./lower/secret"), "app/dangling": ("lnk", "nowhere"),
                       "app/sym": ("sym", "real"), "app/chain": ("lnk", "app/same-layer")})
    image = ci.analyze_image_archive(docker_image(lower, upper))
    rows = {row["path"]: row for row in image.report()["versions"] if row["layer"] == 1}
    assert {path: row["kind"] for path, row in rows.items()} == {
        "app/real": "file", "app/same-layer": "hardlink", "app/lower-layer": "hardlink",
        "app/dangling": "hardlink-unresolved", "app/sym": "symlink", "app/chain": "hardlink"}
    assert image.files["app/same-layer"].content == b"FLAG-BYTES"
    assert image.files["app/chain"].content == b"FLAG-BYTES"      # a link to a link reaches the file
    assert image.files["app/lower-layer"].content == b"from-layer-0"
    assert rows["app/same-layer"]["sha256"] == hashlib.sha256(b"FLAG-BYTES").hexdigest()
    assert rows["app/dangling"]["size"] == 0
    folder = ci.dump_image(image, tmp_path / "out")
    assert (folder / "layers/01/app/same-layer").read_bytes() == b"FLAG-BYTES"
    assert (folder / "layers/01/app/lower-layer").read_bytes() == b"from-layer-0"
    assert (folder / "layers/01/app/chain").read_bytes() == b"FLAG-BYTES"
    assert not (folder / "layers/01/app/same-layer").is_symlink()
    assert not os.path.lexists(folder / "layers/01/app/dangling")
    assert not os.path.lexists(folder / "layers/01/app/sym")
    index = (folder / "index.md").read_text()
    assert "hard link to `app/real` (written as its bytes)" in index
    assert "hard link to `nowhere`: target not found, not written" in index
    # A hard link to a lower file that this layer whites out first has nothing to carry.
    gone = ci.analyze_image_archive(docker_image(lower, layer_tar({"lower/.wh.secret": b"",
                                                                   "kept": ("lnk", "lower/secret")})))
    assert gone.files["kept"].kind == "hardlink-unresolved" and gone.files["kept"].content == b""


def test_hard_links_past_the_linked_cap_are_refused(monkeypatch, tmp_path):
    # Many links to one file: each carries (and the dump writes) its bytes, so they count, image-wide.
    big = b"B" * 1000
    lower = layer_tar({"big": big, "l1": ("lnk", "big"), "l2": ("lnk", "big")})
    upper = layer_tar({"l3": ("lnk", "big"), "l4": ("lnk", "l1")})
    monkeypatch.setattr(ci, "MAX_LINKED", 4 * len(big))       # exactly four links' worth: read
    image = ci.analyze_image_archive(docker_image(lower, upper))
    assert [image.files[name].content for name in ("l1", "l2", "l3", "l4")] == [big] * 4
    folder = ci.dump_image(image, tmp_path / "out")
    written = sum(path.stat().st_size for path in (folder / "layers").rglob("*") if path.is_file())
    assert written == 5 * len(big)
    monkeypatch.setattr(ci, "MAX_LINKED", 4 * len(big) - 1)   # one byte less: the image is refused
    with pytest.raises(ValueError, match="hard links expand past the linked-bytes cap at l4"):
        ci.analyze_image_archive(docker_image(lower, upper))


def test_a_hard_linked_secret_is_scanned_once():
    secret = b"password=hunter2-very-secret\n"
    lower = layer_tar({"etc/app.conf": secret, **{f"copy{n}": ("lnk", "etc/app.conf") for n in range(5)}})
    upper = layer_tar({".wh.copy0": b"", "etc/.wh.app.conf": b""})   # a link and its target, both deleted
    image = ci.analyze_image_archive(docker_image(lower, upper))
    assert image.files["copy1"].content == secret and {item.path for item in image.recovered} == {
        "copy0", "etc/app.conf"}
    findings = [item for item in image.findings if item["kind"] == "embedded-secret"]
    assert sorted((item["source"], item["path"]) for item in findings) == [
        ("layer", "etc/app.conf"), ("recovered-layer", "etc/app.conf")]


def test_dump_keeps_versions_whose_paths_differ_only_in_case(tmp_path):
    image = ci.analyze_image_archive(docker_image(layer_tar({
        "app/Flag.txt": b"upper", "app/flag.txt": b"lower", "app/FLAG.txt~1": b"third",
        "app/café": b"nfc", "app/café": b"nfd"})))
    folder = ci.dump_image(image, tmp_path / "out")
    renamed = json.loads((folder / "report.json").read_text())["dump"]["renamed"]
    assert renamed == [
        {"path": "layers/00/app/flag.txt", "written_as": "layers/00/app/flag.txt~1",
         "clashes_with": "layers/00/app/Flag.txt"},
        {"path": "layers/00/app/FLAG.txt~1", "written_as": "layers/00/app/FLAG.txt~1~1",
         "clashes_with": "layers/00/app/flag.txt~1"},
        {"path": "layers/00/app/café", "written_as": "layers/00/app/café~1",
         "clashes_with": "layers/00/app/café"}]
    found = {unicodedata.normalize("NFC", item.name).casefold(): item.read_bytes()
             for item in (folder / "layers/00/app").iterdir()}
    assert found == {"flag.txt": b"upper", "flag.txt~1": b"lower", "flag.txt~1~1": b"third",
                     "café": b"nfc", "café~1": b"nfd"}
    index = (folder / "index.md").read_text()
    assert ("- `layers/00/app/flag.txt` is at `layers/00/app/flag.txt~1`: its name clashes with "
            "`layers/00/app/Flag.txt` on a case-insensitive disk") in index
    assert json.loads((folder / "report.json").read_text())["dump"]["errors"] == []


def test_cli_dumps_an_unpacked_layout_and_fails_loudly(tmp_path, capsys):
    root = write_tree(tmp_path / "layout", sealed_layout())
    assert ci.main(["image", str(root / "oci-layout"), "--dump", str(tmp_path / "out")]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["layer_count"] == 4 and report["dump"]["errors"] == []
    assert Path(report["dump"]["folder"], "index.md").is_file()
    assert ci.main(["image", str(root)]) == 0
    assert "dump" not in json.loads(capsys.readouterr().out)
    not_image = tmp_path / "notes.txt"
    not_image.write_text("hello")
    assert ci.main(["image", str(not_image)]) == 2
    assert "invalid tar archive" in capsys.readouterr().err
    assert ci.main(["iac", str(not_image), "--dump", str(tmp_path / "x")]) == 2
    assert "--dump applies to image mode only" in capsys.readouterr().err


def test_manifest_adapts_oci_layouts_for_intake():
    from ctf.engines import manifest
    from ctf.intake import engines as E
    m = {x.id: x for x in manifest.discover(ROOT)}["toolkits.container_iac"]
    assert m.intake.select == "files" and m.intake.run == "per-file" and m.cost_class == "cheap"
    assert m.intake.args[:2] == ("image", "{file}") and "{out}" in m.intake.args and "--dump" in m.intake.args
    assert E.files_matching(m.intake.match, [(Path("x/image/oci-layout"), b'{"imageLayoutVersion": "1.0.0"}')])
    assert not E.files_matching(m.intake.match, [(Path("x/index.json"), b"{}"), (Path("oci-layout.txt"), b"")])


def test_router_sends_container_image_briefs_here():
    from ctf.engines import router
    ids = [h.manifest.id for h in router.route("forensics", "a docker image whose layers hide a secret")]
    assert "toolkits.container_iac" in ids
    assert "toolkits.container_iac" not in [h.manifest.id for h in router.route("forensics", "a pcap of a login")]


class _Adapter:
    kind = "fake"

    def __init__(self, ch, files):
        self.ch, self.files = ch, files

    def get_challenge(self, cid):
        return self.ch

    def list_challenges(self):
        return [self.ch]

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.files.items():
            p = Path(dest) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            out.append(p)
        return out

    def submit(self, cid, flag):
        raise AssertionError("intake never submits")

    def team_solves(self):
        return []


def test_intake_dumps_an_oci_image_tar_with_no_model(tmp_path):
    from ctf import event
    from ctf import intake as I
    from ctf.platform.base import Challenge, FileRef
    prof = event.load("csctf")
    ch = Challenge(id="9001", name="Layered", category="forensics", points=100,
                   description="an image someone shipped", files=(FileRef("image.tar"),))
    rep = I.intake_one("9001", prof, adapter=_Adapter(ch, {"image.tar": tar_bytes(sealed_layout())}),
                       workdir=tmp_path / "wd", options=I.Options(net_guard="hook", record=False))
    runs = [r for r in rep.runs if r.engine == "toolkits.container_iac"]
    assert runs and runs[0].status == "ok", [(r.engine, r.status, r.note) for r in rep.runs]
    assert runs[0].inputs[0].endswith("oci-layout")
    dumps = list((rep.dir / "recon" / "engines" / "toolkits.container_iac").glob("image-*/index.md"))
    assert len(dumps) == 1 and SEAL_COMMENT in dumps[0].read_text()
    assert (dumps[0].parent / "layers/01/app/.sealed_marker").read_bytes() == b"revision-A"
