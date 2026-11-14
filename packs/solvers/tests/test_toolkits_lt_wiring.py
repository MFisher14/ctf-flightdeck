"""B-251: the long-tail readers are wired: manifests, routes, the contract runner entry, no-model intake.

One handout holds a synthetic file of every format, each with its own flag. Intake must plan the five
magic- or extension-selected readers from the files alone, plan the FlatBuffers / Cap'n Proto reader only
when the description routes there (it has no magic), run each as a child process with no model, and get
each reader's own flag back.
"""
import json
import struct
import sys
from pathlib import Path

import pytest

from ctf import event, flagfmt
from ctf.engines import manifest, router
from ctf.formats import corpus_longtail as L
from ctf.intake import engines as E
from ctf.intake import guard as G

REPO = Path(__file__).resolve().parent.parent
ENGINES = ("toolkits.lt_avro", "toolkits.lt_thrift_parquet", "toolkits.lt_flat_capnp", "toolkits.lt_model_meta",
           "toolkits.lt_tnef", "toolkits.lt_jxl")
PROFILE = event.load("csctf")
LEAD = flagfmt.for_profile(PROFILE).cribs()[0]
FLAGS = {e: f"{LEAD}{e.split('.')[1]}_at_intake}}" for e in ENGINES}


def handout(folder: Path):
    folder.mkdir(parents=True)
    f = {e: FLAGS[e].encode() for e in ENGINES}
    schema = {"type": "record", "name": "R", "fields": [{"name": "note", "type": "string"}]}
    (folder / "events.avro").write_bytes(L.avro_container(
        json.dumps(schema).encode(), [(1, L.avro_string(f["toolkits.lt_avro"]))], "deflate"))
    value = f["toolkits.lt_thrift_parquet"]
    (folder / "rows.parquet").write_bytes(L.parquet_plain(
        [(b"note", 6, struct.pack("<I", len(value)) + value)], 1, {b"owner": b"x"}, b"writer 1"))
    (folder / "state.bin").write_bytes(L.flat_buffer([("u32", 1), ("str", f["toolkits.lt_flat_capnp"])], b"SAVE"))
    (folder / "model.tflite").write_bytes(L.tflite_model(metadata=[(b"note", b"\x00\xff" + f["toolkits.lt_model_meta"])]))
    (folder / "winmail.dat").write_bytes(L.tnef_stream([
        L.tnef_attr(2, 0x00069002, bytes(14)), L.tnef_attr(2, 0x00018010, b"a.bin\x00"),
        L.tnef_attr(2, 0x0006800F, b"\xfe\xff" + f["toolkits.lt_tnef"])]))
    (folder / "picture.jxl").write_bytes(
        L.JXL_SIGNATURE + L.jxl_box(b"ftyp", b"jxl \x00\x00\x00\x00jxl ") + L.jxl_box(b"note", b"\x01" + f["toolkits.lt_jxl"])
        + L.jxl_box(b"jxlc", L.JXL_HEAD_100X50 + bytes(40)))


def test_manifests_are_contract_engines_with_intake():
    by_id = {m.id: m for m in manifest.discover()}
    for e in ENGINES:
        m = by_id[e]
        assert m.capabilities[0] == "executes" and m.status == "active" and m.cost_class == "cheap"
        assert (m.entry.kind, m.entry.function) == ("function", "solve")
        assert m.entry.target_file(REPO) == REPO / "solvers" / "toolkits" / f"{e.split('.')[1]}.py"
        assert m.intake is not None and m.intake.run == "challenge" and not m.intake.spawns
        assert m.routes and all(r.priority is not None for r in m.routes)
    assert by_id["toolkits.lt_flat_capnp"].intake.select == "route"            # no magic to select files by
    assert all(by_id[e].intake.select == "files" for e in ENGINES if e != "toolkits.lt_flat_capnp")
    pack = by_id["metadata_forensics.readers_longtail"]
    assert pack.capabilities[0] == "library" and pack.intake is None


@pytest.mark.parametrize("category,text,engine", [
    ("forensics", "the mail server kept a winmail.dat for us", "toolkits.lt_tnef"),
    ("misc", "a parquet export of the audit table", "toolkits.lt_thrift_parquet"),
    ("misc", "kafka topic dumped as avro", "toolkits.lt_avro"),
    ("stego", "something hides in this jpeg xl picture", "toolkits.lt_jxl"),
    ("ml", "inspect the tflite model", "toolkits.lt_model_meta"),
    ("rev", "the save file is a flatbuffer", "toolkits.lt_flat_capnp"),
])
def test_descriptions_route_to_the_reader(category, text, engine):
    hits = {h.manifest.id: h for h in router.route(category, text)}
    assert engine in hits and hits[engine].priority == 61 and hits[engine].reason.startswith("keyword")
    assert not set(ENGINES) & {h.manifest.id for h in router.route(category, "nothing about any format")}


def test_files_alone_route_and_intake_runs_every_reader_with_no_model(tmp_path):
    cd = tmp_path / "9001-longtail"
    handout(cd / "unpacked")
    ms = manifest.discover()
    guard = G.Guard("hook", (), "test: these readers start no program")
    plan = E.plan(ms, "forensics", "a mixed evidence folder", cd / "unpacked", guard=guard)
    planned = {j.engine for j in plan.jobs}
    assert set(ENGINES) - {"toolkits.lt_flat_capnp"} <= planned
    assert "toolkits.lt_flat_capnp" not in planned                # nothing names the format, and it has no magic
    routed = E.plan(ms, "forensics", "the state file is a flatbuffers table", cd / "unpacked", guard=guard)
    jobs = {j.engine: j for j in routed.jobs if j.engine in ENGINES}
    assert set(jobs) == set(ENGINES)
    ctx = E.Context(challenge_dir=cd, folder=cd / "unpacked", out_root=cd / "recon" / "engines", profile=PROFILE,
                    guard=guard, root=REPO, python=sys.executable, challenge_id="9001", record=False)
    for e in ENGINES:
        run = E.run_job(jobs[e], ctx)
        assert run.status == "ok", (e, (cd / run.errors).read_text()[-600:])
        assert run.result_status == "solved" and run.flags == (FLAGS[e],), (e, run.flags)


def test_a_bare_codestream_is_run_whatever_it_is_called_and_other_ff_0a_files_are_passed_over(tmp_path):
    import lt_jxl
    ms = manifest.discover()
    guard = G.Guard("hook", (), "test: these readers start no program")
    bare = tmp_path / "9002-bare" / "unpacked"
    bare.mkdir(parents=True)
    (bare / "frame.bin").write_bytes(L.JXL_HEAD_40X30 + bytes(60))        # a real cjxl header, no .jxl name
    assert "toolkits.lt_jxl" in {j.engine for j in E.plan(ms, "forensics", "one unnamed file", bare, guard=guard).jobs}
    r = lt_jxl.solve(bare)
    assert r.status == "unsure" and "width=40, height=30" in r.evidence[0].detail and r.evidence[0].path == "frame.bin"

    text = tmp_path / "9003-text" / "unpacked"
    text.mkdir(parents=True)
    (text / "notes.bin").write_bytes(b"\xff\x0a" + b"The quick brown fox jumps over the lazy dog. " * 4)
    assert lt_jxl.solve(text).status == "none"                           # started by its two bytes, then passed over
    other = tmp_path / "9004-other" / "unpacked"
    other.mkdir(parents=True)
    (other / "notes.bin").write_bytes(b"plain text, no magic at all")
    assert "toolkits.lt_jxl" not in {j.engine for j in E.plan(ms, "forensics", "one unnamed file", other, guard=guard).jobs}
