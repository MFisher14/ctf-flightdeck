"""World-folder walker (B-120): synthetic Java worlds built here, byte by byte; never a real save."""
from __future__ import annotations

import gzip
import json
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

import minecraft_world as mw
from ctf import dispatch, event, triage
from ctf.engines import manifest as engine_manifest
from ctf.engines import router
from ctf.intake import engines as intake_engines
from ctf.intake import guard as intake_guard
from ctf.result import SolverResult

REPO = Path(__file__).resolve().parents[1]
SECTOR = 4096


# --------------------------------------------------------------------------- NBT and region builders
def _name(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">H", len(raw)) + raw


def _tag(tag_id: int, name: str, payload: bytes) -> bytes:
    return bytes([tag_id]) + _name(name) + payload


def t_int(name, value):
    return _tag(3, name, struct.pack(">i", value))


def t_long(name, value):
    return _tag(4, name, struct.pack(">q", value))


def t_str(name, value):
    return _tag(8, name, _name(value))


def t_comp(name, *children):
    return _tag(10, name, b"".join(children) + b"\x00")


def t_list_comp(name, rows):
    """A list of compounds; each row is a list of child tags."""
    return _tag(9, name, b"\x0a" + struct.pack(">i", len(rows)) + b"".join(b"".join(r) + b"\x00" for r in rows))


def t_list_str(name, values):
    return _tag(9, name, b"\x08" + struct.pack(">i", len(values)) + b"".join(_name(v) for v in values))


def t_int_array(name, values):
    return _tag(11, name, struct.pack(">i", len(values)) + b"".join(struct.pack(">i", v) for v in values))


def t_list_double(name, values):
    return _tag(9, name, b"\x06" + struct.pack(">i", len(values)) + b"".join(struct.pack(">d", v) for v in values))


def nbt_root(*children):
    return b"\x0a\x00\x00" + b"".join(children) + b"\x00"


def J(obj) -> str:
    return json.dumps(obj, separators=(",", ":"))


def chunk(x, z, *, block_entities=(), extra=()):
    return nbt_root(t_int("DataVersion", 3700), t_int("xPos", x), t_int("zPos", z),
                    t_str("Status", "minecraft:full"), t_list_comp("block_entities", list(block_entities)),
                    *extra)


def sign(x, y, z, front, back=None):
    row = [t_str("id", "minecraft:sign"), t_int("x", x), t_int("y", y), t_int("z", z),
           t_comp("front_text", t_list_str("messages", list(front)))]
    if back is not None:
        row.append(t_comp("back_text", t_list_str("messages", list(back))))
    return row


def region(slots, *, orphans=(), slack=None, orphans_first=False, same_as=None) -> bytes:
    """slots: {index: chunk NBT bytes | (compression byte, stored payload)}.  ``orphans`` are chunk
    records written with no location entry, after the live chunks or (``orphans_first``) before them,
    from sector 2; ``slack`` is {index: bytes} put right after a record; ``same_as`` is {index: other
    index}: a location entry copied from another slot, so both point at the same sectors."""
    header = bytearray(2 * SECTOR)
    body = bytearray()

    def record(marker, payload, tail=b""):
        raw = struct.pack(">I", len(payload) + 1) + bytes([marker]) + payload + tail
        return raw + b"\x00" * (-len(raw) % SECTOR)

    orphaned = b"".join(record(2, zlib.compress(nbt)) for nbt in orphans)
    if orphans_first:
        body += orphaned
    sector = 2 + len(body) // SECTOR
    for index, value in sorted(slots.items()):
        marker, payload = value if isinstance(value, tuple) else (2, zlib.compress(value))
        raw = record(marker, payload, (slack or {}).get(index, b""))
        header[index * 4:index * 4 + 4] = struct.pack(">I", (sector << 8) | (len(raw) // SECTOR))
        body += raw
        sector += len(raw) // SECTOR
    for index, other in (same_as or {}).items():
        header[index * 4:index * 4 + 4] = header[other * 4:other * 4 + 4]
    if not orphans_first:
        body += orphaned
    return bytes(header) + bytes(body)


def level_dat(name="Test World", spawn=(0, 64, 0), extra=()):
    data = t_comp("Data", t_str("LevelName", name), t_int("SpawnX", spawn[0]), t_int("SpawnY", spawn[1]),
                  t_int("SpawnZ", spawn[2]), t_int("DataVersion", 3700), t_long("RandomSeed", 424242),
                  t_comp("Version", t_str("Name", "1.20.4")), *extra)
    return gzip.compress(nbt_root(data), mtime=0)


def write_world(root: Path, *, files=None, **level) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "level.dat").write_bytes(level_dat(**level))
    for rel, data in (files or {}).items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return root


def flags_of(report):
    return {row["flag"]: row["how"] for row in report["flags"]}


def records(report, surface):
    return [row for row in report["records"] if row["surface"] == surface]


class StepClock:
    """A clock that advances one second per reading: the walker's budget without real time."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        value, self.now = self.now, self.now + 1.0
        return value


# --------------------------------------------------------------------------- text components
def test_json_component_reads_text_then_with_then_extra():
    comp = {"text": "A", "with": ["W"], "extra": [{"text": "B", "extra": ["C"]}, "D", 7, True]}
    assert mw.json_component_text(comp) == "AWBCD7true"
    assert mw.json_component_text(["x", {"translate": "key.k", "with": [{"text": "y"}]}]) == "xkey.ky"
    assert mw.json_component_text({"translate": "k", "fallback": "shown"}) == "shown"
    assert mw.json_component_text({"score": {"name": "n"}}) == ""


def test_component_text_only_flattens_real_json():
    assert mw.component_text('{"text":"hello ","extra":[{"text":"world"}]}') == "hello world"
    assert mw.component_text('"quoted"') == "quoted"
    assert mw.component_text("[shop] 5 emeralds") == "[shop] 5 emeralds"      # not JSON: kept as it is
    assert mw.component_text("{not json}") == "{not json}"
    assert mw.component_text("plain") == "plain"


def test_strip_formatting_removes_section_codes_only():
    assert mw.strip_formatting("§aCS§lCTF{x}§r") == "CSCTF{x}"
    assert mw.strip_formatting("5§ off") == "5§ off"               # no code letter after it


# --------------------------------------------------------------------------- signs, books, names
def test_modern_sign_is_a_record_with_block_coordinates(tmp_path):
    lines = [J({"text": "Welcome"}), J({"text": "to the"}), J("temple"), J("")]
    world = write_world(tmp_path / "w", files={
        "region/r.1.-1.mca": region({65: chunk(33, -30, block_entities=[sign(530, 70, -470, lines)])})})
    report = mw.walk(world)
    (row,) = records(report, "sign")
    assert row["parts"] == ["Welcome", "to the", "temple", ""]
    assert row["text"] == "Welcome\nto the\ntemple"
    assert row["side"] == "front" and row["id"] == "minecraft:sign"
    # slot 65 (x 1, z 2) of r.1.-1 is chunk (32 + 1, -32 + 2); the block position is the block entity's
    assert row["where"] == {"dimension": "overworld", "chunk": [33, -30], "pos": [530, 70, -470]}
    assert row["file"] == "region/r.1.-1.mca"
    assert report["flags"] == []


def test_back_of_a_sign_is_its_own_record(tmp_path):
    front = [J("front")] + [J("")] * 3
    back = [J({"text": "CSCTF{on_the_back}"})] + [J("")] * 3
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[sign(1, 2, 3, front, back)])})})
    report = mw.walk(world)
    assert {row["side"] for row in records(report, "sign")} == {"front", "back"}
    assert flags_of(report) == {"CSCTF{on_the_back}": "direct"}


def test_flag_split_over_a_components_extra_is_a_component_hit(tmp_path):
    line = J({"text": "CSCTF{spl", "extra": [{"text": "it_in_"}, {"text": "three}"}]})
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[sign(8, 64, 8, [line, J(""), J(""), J("")])])})})
    report = mw.walk(world)
    # no stored string holds it whole, and nothing is read across the JSON syntax
    assert flags_of(report) == {"CSCTF{split_in_three}": "component"}
    assert mw.solve(world).status == "solved"


def test_flag_split_over_sign_lines_is_joined_and_only_a_candidate(tmp_path):
    lines = [J("CSCTF{two_"), J("lines}"), J(""), J("")]
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[sign(8, 64, 8, lines)])})})
    report = mw.walk(world)
    assert flags_of(report) == {"CSCTF{two_lines}": "joined"}
    result = mw.solve(world)
    assert result.status == "candidate" and result.flags == ("CSCTF{two_lines}",)


def test_legacy_sign_text_tags(tmp_path):
    row = [t_str("id", "Sign"), t_int("x", -5), t_int("y", 60), t_int("z", 9),
           t_str("Text1", J({"text": "old"})), t_str("Text2", J({"text": "CSCTF{legacy_sign}"})),
           t_str("Text3", ""), t_str("Text4", "")]
    legacy_chunk = nbt_root(t_comp("Level", t_int("xPos", -1), t_int("zPos", 0),
                                   t_list_comp("TileEntities", [row])))
    world = write_world(tmp_path / "w", files={"region/r.-1.0.mca": region({31: legacy_chunk})})
    report = mw.walk(world)
    (sign_row,) = records(report, "sign")
    assert sign_row["parts"] == ["old", "CSCTF{legacy_sign}", "", ""]
    assert sign_row["where"]["pos"] == [-5, 60, 9]
    assert flags_of(report) == {"CSCTF{legacy_sign}": "direct"}


def test_written_book_in_a_chest_old_and_new_layouts(tmp_path):
    old_book = [t_str("id", "minecraft:written_book"),
                t_comp("tag", t_str("title", "Diary"), t_str("author", "Steve"),
                       t_list_str("pages", [J({"text": "page one"}), J({"text": "CSCTF{book_"}),
                                            J({"text": "pages}"})]))]
    new_book = [t_str("id", "minecraft:written_book"),
                t_comp("components", t_comp("minecraft:written_book_content",
                                            t_comp("title", t_str("raw", "Ledger")), t_str("author", "Alex"),
                                            t_list_comp("pages", [[t_str("raw", J("first"))],
                                                                  [t_str("raw", J({"text": "second"}))]])))]
    chest = [t_str("id", "minecraft:chest"), t_int("x", 10), t_int("y", 11), t_int("z", 12),
             t_list_comp("Items", [old_book, new_book])]
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[chest])})})
    report = mw.walk(world)
    books = {row["title"]: row for row in records(report, "book")}
    assert books["Diary"]["parts"] == ["page one", "CSCTF{book_", "pages}"]
    assert books["Diary"]["author"] == "Steve"
    assert books["Diary"]["where"]["pos"] == [10, 11, 12]          # the chest's position
    assert books["Diary"]["id"] == "minecraft:written_book"
    assert books["Ledger"]["parts"] == ["first", "second"] and books["Ledger"]["author"] == "Alex"
    assert flags_of(report) == {"CSCTF{book_pages}": "joined"}     # only the pages together spell it


def test_item_names_and_lore_old_and_new_layouts(tmp_path):
    old_item = [t_str("id", "minecraft:stick"),
                t_comp("tag", t_comp("display", t_str("Name", J({"text": "Old Wand"})),
                                     t_list_str("Lore", [J("lore one"), J({"text": "CSCTF{in_the_lore}"})])))]
    new_item = [t_str("id", "minecraft:paper"),
                t_comp("components", t_str("minecraft:custom_name", J({"text": "CSCTF{named_item}"})),
                       t_str("minecraft:item_name", J("Ticket")),
                       t_list_str("minecraft:lore", [J("new lore")]))]
    barrel = [t_str("id", "minecraft:barrel"), t_int("x", 1), t_int("y", 1), t_int("z", 1),
              t_list_comp("Items", [old_item, new_item])]
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[barrel])})})
    report = mw.walk(world)
    assert {row["text"] for row in records(report, "item-name")} == {"Old Wand", "Ticket"}
    assert [row["text"] for row in records(report, "custom-name")] == ["CSCTF{named_item}"]
    assert {tuple(row["parts"]) for row in records(report, "lore")} == {
        ("lore one", "CSCTF{in_the_lore}"), ("new lore",)}
    assert flags_of(report) == {"CSCTF{in_the_lore}": "direct", "CSCTF{named_item}": "direct"}


def test_named_entity_in_an_entities_region_and_a_command_block(tmp_path):
    villager = [t_str("id", "minecraft:villager"), t_list_double("Pos", [-12.7, 64.0, 30.2]),
                t_str("CustomName", J({"text": "Keeper of CSCTF{npc_name}"}))]
    entity_chunk = nbt_root(t_int("DataVersion", 3700), t_list_comp("Entities", [villager]))
    command = [t_str("id", "minecraft:command_block"), t_int("x", 3), t_int("y", 4), t_int("z", 5),
               t_str("Command", "say the door opens"), t_str("LastOutput", J({"text": "ok"}))]
    world = write_world(tmp_path / "w", files={
        "entities/r.-1.0.mca": region({0: entity_chunk}),
        "DIM-1/region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[command])})})
    report = mw.walk(world)
    (name_row,) = records(report, "custom-name")
    assert name_row["where"] == {"dimension": "overworld", "chunk": [-32, 0], "pos": [-13, 64, 30]}
    assert name_row["file"] == "entities/r.-1.0.mca"
    (command_row,) = records(report, "command")
    assert command_row["text"] == "say the door opens" and command_row["where"]["dimension"] == "the_nether"
    assert [row["text"] for row in records(report, "command-output")] == ["ok"]
    assert report["worlds"][0]["dimensions"] == {"overworld": {"entities": 1}, "the_nether": {"region": 1}}
    assert flags_of(report) == {"CSCTF{npc_name}": "direct"}


def test_custom_dimension_is_named_from_its_folder(tmp_path):
    world = write_world(tmp_path / "w", files={
        "dimensions/pink/vault/region/r.0.0.mca": region({0: chunk(0, 0, extra=[t_str("note", "CSCTF{vault}")])})})
    report = mw.walk(world)
    (row,) = [r for r in report["records"] if r["flags"]]
    assert row["where"]["dimension"] == "pink:vault" and row["path"] == "$.note"


def test_the_three_vanilla_dimensions_are_named_from_their_folders(tmp_path):
    def noted(text):
        return region({0: chunk(0, 0, extra=[t_str("note", text)])})

    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": noted("CSCTF{in_the_overworld}"), "DIM-1/region/r.0.0.mca": noted("CSCTF{in_the_nether}"),
        "DIM1/region/r.0.0.mca": noted("CSCTF{in_the_end}")})
    report = mw.walk(world)
    where = {row["flags"][0]: row["where"]["dimension"] for row in report["records"] if row["flags"]}
    assert where == {"CSCTF{in_the_overworld}": "overworld", "CSCTF{in_the_nether}": "the_nether",
                     "CSCTF{in_the_end}": "the_end"}
    assert set(report["worlds"][0]["dimensions"]) == {"overworld", "the_nether", "the_end"}


def test_text_display_entity_text_is_a_record_and_only_that_entitys(tmp_path):
    display = [t_str("id", "minecraft:text_display"), t_list_double("Pos", [3.5, 80.0, -2.5]),
               t_str("text", J({"text": "floating ", "extra": [{"text": "words"}]}))]
    marker = [t_str("id", "minecraft:marker"), t_list_double("Pos", [0.0, 0.0, 0.0]), t_str("text", J("not shown"))]
    entity_chunk = nbt_root(t_int("DataVersion", 3700), t_list_comp("Entities", [display, marker]))
    world = write_world(tmp_path / "w", files={"entities/r.0.0.mca": region({0: entity_chunk})})
    report = mw.walk(world)
    (row,) = records(report, "text-display")
    assert row["text"] == "floating words" and row["where"]["pos"] == [3, 80, -3]
    assert row["id"] == "minecraft:text_display" and row["path"] == "$.Entities[0].text"


# --------------------------------------------------------------------------- level.dat and players
def test_level_dat_summary_and_single_player_inventory(tmp_path):
    book = [t_str("id", "minecraft:writable_book"), t_comp("tag", t_list_str("pages", ["CSCTF{own_notes}"]))]
    world = write_world(tmp_path / "w", name="Temple of Doom", spawn=(100, 70, -300),
                        extra=[t_comp("Player", t_list_comp("Inventory", [book]))])
    report = mw.walk(world)
    level = report["worlds"][0]["level"]
    assert level["name"] == "Temple of Doom" and level["spawn"] == [100, 70, -300]
    assert level["version"] == "1.20.4" and level["seed"] == 424242 and level["data_version"] == 3700
    assert level["single_player_inventory"] is True
    assert [row["text"] for row in records(report, "level-name")] == ["Temple of Doom"]
    assert flags_of(report) == {"CSCTF{own_notes}": "direct"}
    assert report["worlds"][0]["edition"] == "java"


def test_playerdata_records_carry_the_player(tmp_path):
    uuid = "069a79f4-44e9-4726-a5be-fca90e38aaf5"
    item = [t_str("id", "minecraft:name_tag"), t_comp("tag", t_comp("display", t_str("Name", J("CSCTF{in_a_pocket}"))))]
    player = gzip.compress(nbt_root(t_list_double("Pos", [8.5, 65.0, -3.5]),
                                    t_list_comp("EnderItems", [item])), mtime=0)
    world = write_world(tmp_path / "w", files={f"playerdata/{uuid}.dat": player})
    report = mw.walk(world)
    assert report["worlds"][0]["players"] == [
        {"file": f"playerdata/{uuid}.dat", "uuid": uuid, "pos": [8, 65, -4]}]
    (row,) = records(report, "item-name")
    assert row["where"]["player"] == uuid and row["text"] == "CSCTF{in_a_pocket}"


def test_data_folder_and_external_chunk_files_are_walked(tmp_path):
    scoreboard = gzip.compress(nbt_root(t_comp("data", t_list_comp("Objectives", [
        [t_str("Name", "kills"), t_str("DisplayName", J({"text": "CSCTF{scoreboard}"}))]]))), mtime=0)
    external = zlib.compress(chunk(0, 0, block_entities=[sign(1, 1, 1, [J("CSCTF{in_an_mcc}")] + [J("")] * 3)]))
    world = write_world(tmp_path / "w", files={"data/scoreboard.dat": scoreboard,
                                               "data/map_3.dat": gzip.compress(nbt_root(t_int("x", 1)), mtime=0),
                                               "region/c.0.0.mcc": external})
    report = mw.walk(world)
    assert [row["text"] for row in records(report, "display-name")] == ["CSCTF{scoreboard}"]
    assert flags_of(report) == {"CSCTF{scoreboard}": "direct", "CSCTF{in_an_mcc}": "direct"}
    assert report["stats"]["map_items"] == 1
    assert "map item" in mw.solve(world).notes


# --------------------------------------------------------------------------- which chunks are read
def test_a_chunk_is_parsed_for_a_flag_lead_or_a_text_tag_and_not_otherwise(tmp_path):
    plain = chunk(0, 0, extra=[t_str("note", "CSCTF{plain_string_tag}")])       # a lead, no text tag
    signed = chunk(1, 0, block_entities=[sign(20, 64, 4, [J("no flag here")] + [J("")] * 3)])
    dull = chunk(2, 0, extra=[t_str("note", "nothing to read")])
    world = write_world(tmp_path / "w", files={"region/r.0.0.mca": region({0: plain, 1: signed, 2: dull})})
    report = mw.walk(world)
    assert report["stats"]["chunks_scanned"] == 3 and report["stats"]["chunks_parsed"] == 2
    assert flags_of(report) == {"CSCTF{plain_string_tag}": "direct"}
    assert [row["text"] for row in records(report, "sign")] == ["no flag here"]
    (hit,) = [row for row in report["records"] if row["surface"] == "string"]
    assert hit["path"] == "$.note" and hit["where"]["chunk"] == [0, 0]


def test_gzip_and_uncompressed_chunks_are_read(tmp_path):
    a = chunk(0, 0, extra=[t_str("a", "CSCTF{gzip_chunk}")])
    b = chunk(1, 0, extra=[t_str("b", "CSCTF{raw_chunk}")])
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: (1, gzip.compress(a, mtime=0)), 1: (3, b)})})
    report = mw.walk(world)
    assert set(flags_of(report)) == {"CSCTF{gzip_chunk}", "CSCTF{raw_chunk}"}
    assert {row["path"] for row in report["records"] if row["flags"]} == {"$.a", "$.b"}
    assert report["stats"]["chunks_parsed"] == 2 and "chunks_undecoded" not in report["stats"]


def test_lz4_external_and_broken_chunks_are_named_skips(tmp_path):
    good = chunk(0, 0, extra=[t_str("a", "CSCTF{still_found}")])
    world = write_world(tmp_path / "w", files={"region/r.0.0.mca": region({
        0: good, 1: (4, b"LZ4Block" + b"\x00" * 20), 2: (0x82, b""), 3: (2, b"not a zlib stream"),
        4: (9, b"abc")})})
    report = mw.walk(world)
    why = {row["what"]: row["why"] for row in report["skipped"]}
    assert "LZ4" in why["region/r.0.0.mca slot 1"]
    assert "external .mcc" in why["region/r.0.0.mca slot 2"]
    assert "does not inflate" in why["region/r.0.0.mca slot 3"]
    assert "unknown chunk compression id 9" in why["region/r.0.0.mca slot 4"]
    assert report["stats"]["chunks_undecoded"] == 4 and report["stats"]["chunks_scanned"] == 1
    assert set(flags_of(report)) == {"CSCTF{still_found}"}


def test_a_chunk_whose_nbt_is_broken_is_scanned_as_bytes_and_said_so(tmp_path):
    broken = chunk(0, 0, extra=[t_str("a", "CSCTF{in_broken_nbt}")])[:-1] + b"\x63"    # an unknown tag id
    world = write_world(tmp_path / "w", files={"region/r.0.0.mca": region({0: broken})})
    report = mw.walk(world)
    assert flags_of(report) == {"CSCTF{in_broken_nbt}": "direct"}
    (row,) = [r for r in report["skipped"] if "slot 0" in r["what"]]
    assert "did not parse" in row["why"] and "raw bytes" in row["why"]
    assert report["flags"][0]["sources"][0]["surface"] == "region-chunk-bytes"


def test_byte_scan_drops_a_hit_that_runs_across_binary_data(tmp_path):
    # csctf's flag body is anything up to the next brace: "flag{" then binary then "}" is not a flag
    world = write_world(tmp_path / "w", files={"notes.bin": b"flag{\x00\x01\x02}" + b" CSCTF{real_one} "})
    report = mw.walk(world)
    assert flags_of(report) == {"CSCTF{real_one}": "direct"}
    assert report["stats"]["byte_hits_dropped_nonprintable"] == 1


def test_non_ascii_flag_is_one_flag_not_a_mojibake_twin(tmp_path):
    world = write_world(tmp_path / "w", files={"motd.txt": "CSCTF{grüße}".encode("utf-8")})
    assert list(flags_of(mw.walk(world))) == ["CSCTF{grüße}"]


# --------------------------------------------------------------------------- deleted data
def _world_with_orphan(tmp_path, **region_kwargs):
    live = chunk(0, 0, extra=[t_str("note", "nothing")])
    removed = chunk(0, 0, block_entities=[sign(4, 70, 4, [J({"text": "CSCTF{sign_that_"}), J("was_removed}"),
                                                         J(""), J("")])])
    return write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: live}, orphans=[removed], **region_kwargs)})


def test_orphaned_chunk_gives_back_a_removed_sign(tmp_path):
    report = mw.walk(_world_with_orphan(tmp_path))
    (row,) = records(report, "sign")
    assert row["parts"][:2] == ["CSCTF{sign_that_", "was_removed}"]
    assert row["where"]["deleted"] is True and row["where"]["pos"] == [4, 70, 4]
    assert flags_of(report) == {"CSCTF{sign_that_was_removed}": "joined"}
    assert report["stats"]["orphan_chunks"] == 1 and report["stats"]["regions_deep"] == 1
    assert "orphaned chunk" in mw.solve(_world_with_orphan(tmp_path / "again")).notes


def test_an_orphan_in_the_first_data_sector_is_seen(tmp_path):
    # sector 2 is the first one after the header: here it is the only unallocated one that holds data
    removed = chunk(0, 0, block_entities=[sign(4, 70, 4, [J("CSCTF{orphan_in_sector_two}")] + [J("")] * 3)])
    raw = region({0: chunk(0, 0, extra=[t_str("note", "nothing")])}, orphans=[removed], orphans_first=True)
    assert len(raw) == 4 * SECTOR and struct.unpack(">I", raw[:4])[0] == (3 << 8) | 1   # live chunk: sector 3
    world = write_world(tmp_path / "w", files={"region/r.0.0.mca": raw})
    report = mw.walk(world)
    assert report["stats"]["regions_deep"] == 1 and report["stats"]["orphan_chunks"] == 1
    (row,) = records(report, "sign")
    assert row["where"]["deleted"] is True and row["where"]["sector"] == 2
    assert set(flags_of(report)) == {"CSCTF{orphan_in_sector_two}"}


def test_deep_pass_off_says_what_it_left(tmp_path):
    report = mw.walk(_world_with_orphan(tmp_path), deep=False)
    assert report["flags"] == [] and records(report, "sign") == []
    assert any(row["what"] == "deep pass" and "unallocated sectors" in row["why"] for row in report["skipped"])


def test_a_region_with_no_leftover_data_gets_no_deep_pass(tmp_path):
    world = write_world(tmp_path / "w", files={"region/r.0.0.mca": region({0: chunk(0, 0)})})
    assert "regions_deep" not in mw.walk(world)["stats"]


def test_deep_pass_reports_a_chunk_stored_in_the_wrong_slot(tmp_path):
    moved = chunk(40, 3, extra=[t_str("note", "nothing")])          # slot 5 of r.0.0 is chunk (5, 0)
    leftover = chunk(9, 9, extra=[t_str("note", "old copy")])
    world = write_world(tmp_path / "w", files={"region/r.0.0.mca": region({5: moved}, orphans=[leftover])})
    report = mw.walk(world)
    issues = [row["issue"] for row in report["anomalies"]]
    assert any("xPos 40" in issue for issue in issues) and any("zPos 3" in issue for issue in issues)
    assert all(row["file"] == "region/r.0.0.mca" and row["slot"] == 5 for row in report["anomalies"])


def test_plain_text_left_in_a_region_is_found_by_the_whole_file_scan(tmp_path):
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0)}, slack={0: b"\x00\x00CSCTF{left_in_slack}\x00"})})
    report = mw.walk(world)
    assert flags_of(report) == {"CSCTF{left_in_slack}": "direct"}
    assert report["flags"][0]["sources"][0]["surface"] == "region-raw"


# --------------------------------------------------------------------------- the folder walk
def test_other_files_are_scanned_and_ctf_and_git_folders_never_entered(tmp_path):
    world = write_world(tmp_path / "w", files={
        "datapacks/p/data/x/functions/f.mcfunction": "say CSCTF{in_a_function}\n",
        "server.properties": "motd=welcome\n",
        ".ctf/token.txt": "CSCTF{never_read_ctf}",
        ".git/config": "CSCTF{never_read_git}"})
    write_world(tmp_path / "w" / ".ctf" / "hidden_world", name="CSCTF{hidden_world}")
    report = mw.walk(tmp_path)
    assert flags_of(report) == {"CSCTF{in_a_function}": "direct"}
    assert report["flags"][0]["sources"][0] == {
        "surface": "file", "file": "w/datapacks/p/data/x/functions/f.mcfunction", "where": {}}
    assert [w["path"] for w in report["worlds"]] == ["w"]
    assert mw.find_worlds(tmp_path) == [tmp_path / "w"]


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("CSCTF{outside_the_world}")
    world = write_world(tmp_path / "w")
    (world / "link.txt").symlink_to(outside)
    report = mw.walk(world)
    assert report["flags"] == []
    assert {"what": "link.txt", "why": "symlink (not followed)"} in report["skipped"]


def test_the_same_world_twice_is_walked_once(tmp_path):
    first = write_world(tmp_path / "files" / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, extra=[t_str("n", "CSCTF{once}")])})})
    shutil.copytree(first, tmp_path / "unpacked" / "w")
    report = mw.walk(tmp_path)
    assert [w["path"] for w in report["worlds"]] == ["files/w"]
    assert report["stats"]["duplicate_worlds"] == 1 and report["stats"]["regions_scanned"] == 1
    assert any(row["what"] == "unpacked/w" and "same world as files/w" in row["why"] for row in report["skipped"])


def test_loose_region_structure_and_nbt_files_without_a_world(tmp_path):
    (tmp_path / "r.2.3.mca").write_bytes(region({0: chunk(64, 96, extra=[t_str("n", "CSCTF{loose_region}")])}))
    schem = nbt_root(t_list_comp("BlockEntities", [[t_str("Id", "minecraft:sign"),
                                                    t_str("Text1", J("CSCTF{in_a_schematic}"))]]))
    (tmp_path / "build.schem").write_bytes(gzip.compress(schem, mtime=0))
    (tmp_path / "player.dat").write_bytes(gzip.compress(nbt_root(t_str("n", "CSCTF{loose_dat}")), mtime=0))
    (tmp_path / "settings.dat").write_bytes(b"CSCTF{not_nbt_so_not_taken}")
    (tmp_path / "backup").mkdir()
    (tmp_path / "backup" / "inv.dat_old").write_bytes(
        gzip.compress(nbt_root(t_str("n", "CSCTF{loose_backup}")), mtime=0))
    report = mw.walk(tmp_path)
    assert set(flags_of(report)) == {"CSCTF{loose_region}", "CSCTF{in_a_schematic}", "CSCTF{loose_dat}",
                                     "CSCTF{loose_backup}"}
    assert [w["path"] for w in report["worlds"]] == ["(loose files)"]
    (hit,) = [row for row in report["records"] if "CSCTF{loose_region}" in row["flags"]]
    assert hit["where"]["chunk"] == [64, 96]


def test_a_single_file_can_be_walked(tmp_path):
    target = tmp_path / "r.0.0.mca"
    target.write_bytes(region({0: chunk(0, 0, extra=[t_str("n", "CSCTF{one_file}")])}))
    assert set(flags_of(mw.walk(target))) == {"CSCTF{one_file}"}


def test_missing_path_and_bad_budget_are_errors(tmp_path):
    with pytest.raises(mw.MinecraftWorldError, match="no such path"):
        mw.walk(tmp_path / "absent")
    for bad in (0, -1, float("nan"), True, "5"):
        with pytest.raises(mw.MinecraftWorldError, match="budget"):
            mw.walk(tmp_path, budget=bad)


def test_bedrock_world_is_named_not_guessed_at(tmp_path):
    world = tmp_path / "bedrock"
    (world / "db").mkdir(parents=True)
    (world / "db" / "CURRENT").write_text("MANIFEST-000001\n")
    (world / "level.dat").write_bytes(struct.pack("<ii", 10, 4) + b"\x0a\x00\x00\x00")
    report = mw.walk(world)
    assert report["worlds"][0]["edition"] == "bedrock"
    assert any("Bedrock world" in row["why"] for row in report["skipped"])
    result = mw.solve(world)
    assert result.status == "blocked" and "Bedrock" in result.notes


# --------------------------------------------------------------------------- flag format and budget
def test_the_given_profile_decides_the_flag_format(tmp_path):
    lines = [J("PINK{pink_event}"), J("CSCTF{csctf_event}"), J(""), J("")]
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[sign(1, 1, 1, lines)])})})
    assert set(flags_of(mw.walk(world, profile=event.load("pink")))) == {"PINK{pink_event}"}
    assert set(flags_of(mw.walk(world))) == {"CSCTF{csctf_event}"}          # the suite's event is csctf
    assert mw.solve(world, event.load("pink")).flags == ("PINK{pink_event}",)


def test_budget_spent_keeps_the_cheap_surfaces_and_names_what_it_left(tmp_path):
    world = write_world(tmp_path / "w", name="CSCTF{level_name}", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, extra=[t_str("n", "CSCTF{in_a_region}")])})})
    report = mw.walk(world, budget=1.5, clock=StepClock())     # level.dat is read at 1 s; the region at 2 s
    assert set(flags_of(report)) == {"CSCTF{level_name}"}
    assert report["budget"]["spent"] is True and report["stats"]["files_not_reached"] == 1
    (row,) = [r for r in report["skipped"] if r["what"] == "budget"]
    assert "1 file(s) not reached" in row["why"] and "region/r.0.0.mca" in row["why"]
    assert "CPU budget of 1.5 s spent" not in mw.solve(world).notes     # the real clock has time to spare
    unlimited = mw.walk(world, budget=None, clock=StepClock())
    assert set(flags_of(unlimited)) == {"CSCTF{level_name}", "CSCTF{in_a_region}"}
    assert unlimited["budget"]["spent"] is False


@pytest.mark.parametrize("spawn,found", [((2600, 64, 2600), "CSCTF{far_region}"), ((0, 64, 0), "CSCTF{near_origin}")])
def test_regions_nearest_the_spawn_are_read_first(tmp_path, spawn, found):
    world = write_world(tmp_path / "w", spawn=spawn, files={
        "region/r.0.0.mca": region({0: chunk(0, 0, extra=[t_str("n", "CSCTF{near_origin}")])}),
        "region/r.5.5.mca": region({0: chunk(160, 160, extra=[t_str("n", "CSCTF{far_region}")])})})
    # readings: level.dat 1, first region 2, its chunk 3, second region 4 -> not reached at 3.5
    report = mw.walk(world, budget=3.5, clock=StepClock())
    assert set(flags_of(report)) == {found}
    assert report["stats"]["files_not_reached"] == 1


def _three_sign_region() -> bytes:
    return region({index: chunk(index, 0, block_entities=[
        sign(index, 64, 0, [J({"text": f"CSCTF{{sign_{index}}}"})] + [J("")] * 3)]) for index in range(3)})


def test_the_budget_is_read_before_each_chunk_is_inflated(tmp_path, monkeypatch):
    target = tmp_path / "r.0.0.mca"
    target.write_bytes(_three_sign_region())
    inflated = []
    real_chunk_blob = mw._chunk_blob
    monkeypatch.setattr(mw, "_chunk_blob", lambda raw, offset, count: (
        inflated.append(offset), real_chunk_blob(raw, offset, count))[1])
    # readings: the file 1, chunk 0 at 2 (read), chunk 1 at 3 and chunk 2 at 4 (budget 2.5 is spent)
    report = mw.walk(target, budget=2.5, clock=StepClock())
    assert inflated == [2]                                      # sectors 3 and 4 were never inflated
    assert report["stats"]["chunks_present"] == 3 and report["stats"]["chunks_scanned"] == 1
    assert report["stats"]["chunks_parsed"] == 1 and report["stats"]["chunks_not_reached"] == 2
    assert set(flags_of(report)) == {"CSCTF{sign_0}"}
    assert {"what": "r.0.0.mca", "why": "2 chunk(s) not read: CPU budget spent"} in report["skipped"]
    assert report["budget"]["spent"] is True
    del inflated[:]
    unlimited = mw.walk(target, budget=None, clock=StepClock())
    assert inflated == [2, 3, 4] and "chunks_not_reached" not in unlimited["stats"]
    assert set(flags_of(unlimited)) == {"CSCTF{sign_0}", "CSCTF{sign_1}", "CSCTF{sign_2}"}


def test_slots_that_point_at_the_same_sectors_are_inflated_once(tmp_path, monkeypatch):
    one = chunk(0, 0, block_entities=[sign(1, 64, 1, [J("CSCTF{pointed_at_many_times}")] + [J("")] * 3)])
    target = tmp_path / "r.0.0.mca"
    target.write_bytes(region({0: one}, same_as={index: 0 for index in range(1, 128)}))
    inflated = []
    real_chunk_blob = mw._chunk_blob
    monkeypatch.setattr(mw, "_chunk_blob", lambda raw, offset, count: (
        inflated.append(offset), real_chunk_blob(raw, offset, count))[1])
    report = mw.walk(target)
    assert inflated == [2]
    assert report["stats"]["chunks_present"] == 128 and report["stats"]["chunks_scanned"] == 1
    assert report["stats"]["chunks_repeated_location"] == 127
    assert len(records(report, "sign")) == 1 and set(flags_of(report)) == {"CSCTF{pointed_at_many_times}"}
    (row,) = [r for r in report["skipped"] if "already uses" in r["why"]]
    assert row["what"] == "r.0.0.mca" and row["why"].startswith("127 slot(s) point at sectors")
    assert "slot 1 repeats slot 0" in row["why"]
    assert "regions_deep" not in report["stats"]              # every sector is still accounted for


def test_one_regions_chunks_inflate_to_a_cap_and_the_rest_are_named(tmp_path, monkeypatch):
    target = tmp_path / "r.0.0.mca"
    target.write_bytes(_three_sign_region())
    assert set(flags_of(mw.walk(target))) == {"CSCTF{sign_0}", "CSCTF{sign_1}", "CSCTF{sign_2}"}
    first = len(chunk(0, 0, block_entities=[sign(0, 64, 0, [J({"text": "CSCTF{sign_0}"})] + [J("")] * 3)]))
    monkeypatch.setattr(mw, "MAX_REGION_INFLATED", first + 1)   # chunk 0 fits; chunk 1 passes the cap
    report = mw.walk(target)
    assert set(flags_of(report)) == {"CSCTF{sign_0}", "CSCTF{sign_1}"}
    assert report["stats"]["chunks_scanned"] == 2 and report["stats"]["chunks_past_inflation_cap"] == 1
    assert {"what": "r.0.0.mca", "why": "1 chunk(s) not read: this region's chunks inflate past the "
                                        f"{first + 1} byte per-region cap"} in report["skipped"]


def test_the_deep_pass_stops_at_the_budget_and_says_so(tmp_path):
    world = _world_with_orphan(tmp_path)
    # readings: level.dat 1, the region 2, its live chunk 3, the deep pass 4 (budget 3.5 is spent)
    report = mw.walk(world, budget=3.5, clock=StepClock())
    assert report["flags"] == [] and records(report, "sign") == []
    assert report["stats"]["regions_deep_not_reached"] == 1 and "regions_deep" not in report["stats"]
    assert {"what": "deep pass", "why": "1 region(s) with data in unallocated sectors not inspected: "
                                        "CPU budget spent"} in report["skipped"]
    in_time = mw.walk(world, budget=4.5, clock=StepClock())
    assert set(flags_of(in_time)) == {"CSCTF{sign_that_was_removed}"} and in_time["stats"]["regions_deep"] == 1


# --------------------------------------------------------------------------- caps are counted, never silent
def test_flags_past_the_cap_are_counted_and_said(tmp_path, monkeypatch):
    world = write_world(tmp_path / "w", files={f"note{n}.txt": f"CSCTF{{flag_{n}}}" for n in range(4)})
    assert len(mw.walk(world)["flags"]) == 4 and mw.walk(world)["flags_dropped"] == 0
    monkeypatch.setattr(mw, "MAX_FLAGS", 2)
    report = mw.walk(world)
    assert set(flags_of(report)) == {"CSCTF{flag_0}", "CSCTF{flag_1}"} and report["flags_dropped"] == 2
    assert "2 flag hit(s) past the cap of 2 distinct flags were not kept" in mw.solve(world).notes
    assert "dropped        2 flag hit(s) past the cap of 2" in mw.render_text(report)


def test_records_past_the_cap_are_counted_and_said(tmp_path, monkeypatch):
    signs = [sign(n, 64, 0, [J(f"words {n}")] + [J("")] * 3) for n in range(3)]
    world = write_world(tmp_path / "w", files={"region/r.0.0.mca": region({0: chunk(0, 0, block_entities=signs)})})
    assert len(records(mw.walk(world), "sign")) == 3 and mw.walk(world)["records_dropped"] == 0
    monkeypatch.setattr(mw, "MAX_RECORDS", 1)
    report = mw.walk(world)
    # the level name is the first record of this world; the three signs come after it
    assert len(report["records"]) == 1 and report["records_dropped"] == 3
    assert "3 text record(s) past the cap of 1 were not kept" in mw.solve(world).notes
    assert "dropped        3 text record(s) past the cap of 1" in mw.render_text(report)


def test_skips_and_anomalies_past_their_caps_are_counted_and_said(tmp_path, monkeypatch):
    moved = chunk(40, 3, extra=[t_str("note", "nothing")])          # slot 5: wrong xPos and wrong zPos
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({5: moved}, orphans=[chunk(9, 9, extra=[t_str("note", "old copy")])])})
    for n in range(3):
        (world / f"link{n}.txt").symlink_to(tmp_path / "nowhere")
    whole = mw.walk(world)
    assert len(whole["anomalies"]) >= 2 and whole["anomalies_dropped"] == 0
    assert len(whole["skipped"]) == 3 and whole["skipped_dropped"] == 0
    monkeypatch.setattr(mw, "MAX_ANOMALIES", 1)
    monkeypatch.setattr(mw, "MAX_SKIPPED", 1)
    report = mw.walk(world)
    assert len(report["anomalies"]) == 1 and report["anomalies_dropped"] == len(whole["anomalies"]) - 1
    assert len(report["skipped"]) == 1 and report["skipped_dropped"] == 2
    notes = mw.solve(world).notes
    assert f"{report['anomalies_dropped']} chunk anomaly(ies) past the cap of 1 were not kept" in notes
    assert "2 skip(s) past the cap of 1 were not listed" in notes


def test_a_chunk_that_inflates_past_the_per_chunk_cap_is_a_named_skip(tmp_path, monkeypatch):
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, extra=[t_str("note", "CSCTF{in_a_big_chunk}")])})})
    assert set(flags_of(mw.walk(world))) == {"CSCTF{in_a_big_chunk}"}
    monkeypatch.setattr(mw, "MAX_CHUNK_INFLATED", 32)
    report = mw.walk(world)
    assert report["flags"] == [] and report["stats"]["chunks_undecoded"] == 1
    assert {"what": "region/r.0.0.mca slot 0", "why": "inflates past the 32 byte cap"} in report["skipped"]


def test_a_text_component_with_too_many_values_is_said_and_still_searched(tmp_path):
    values = mw.MAX_COMPONENT_NODES
    stored = J(["x"] * values + ["CSCTF{past_the_values_read}"])
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, extra=[t_str("note", stored), t_str("small", J(["CSCTF{small}"]))])})})
    report = mw.walk(world)
    assert set(flags_of(report)) == {"CSCTF{past_the_values_read}", "CSCTF{small}"}
    assert report["stats"]["text_components_cut"] == 1
    (row,) = [r for r in report["skipped"] if "values" in r["why"]]
    assert row == {"what": "region/r.0.0.mca $.note",
                   "why": f"text component holds more than {values} values: past that it was searched as "
                          "stored text, not value by value"}
    cut: list[bool] = []
    assert len(mw.json_strings(["x"] * (values - 1), cut)) == values - 1 and cut == []     # all of it read
    assert len(mw.json_strings(["x"] * values, cut)) == values - 1 and cut == [True]
    cut = []
    assert mw.json_component_text({"text": "a", "extra": ["b"] * values}, cut).startswith("ab") and cut == [True]
    assert mw.json_component_text({"text": "a", "extra": ["b"]}, cut) == "ab" and cut == [True]   # not appended to


def test_a_search_for_worlds_that_is_cut_short_is_reported(tmp_path, monkeypatch):
    for n in range(3):
        (tmp_path / "a").mkdir(exist_ok=True)
        (tmp_path / "a" / f"junk{n}.txt").write_text("nothing")
    write_world(tmp_path / "z", name="CSCTF{never_reached}")
    assert [w["path"] for w in mw.walk(tmp_path)["worlds"]] == ["z"]
    monkeypatch.setattr(mw, "MAX_WALK_FILES", 2)
    report = mw.walk(tmp_path)
    assert report["worlds"] == [] and report["flags"] == []
    assert {"what": "discovery", "why": "more than 2 files under the path: the search for worlds "
                                        "stopped early"} in report["skipped"]


# --------------------------------------------------------------------------- solve()
def test_solve_statuses(tmp_path):
    one = write_world(tmp_path / "one", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[sign(1, 2, 3, [J("CSCTF{the_one}")] + [J("")] * 3)])})})
    result = mw.solve(one)
    assert isinstance(result, SolverResult) and result.engine == "toolkits.minecraft_world"
    assert result.status == "solved" and result.flags == ("CSCTF{the_one}",)
    assert result.evidence[0].kind == "match" and result.evidence[0].path == "region/r.0.0.mca"
    assert "at (1, 2, 3)" in result.evidence[0].detail

    two = write_world(tmp_path / "two", name="CSCTF{decoy}", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, extra=[t_str("n", "CSCTF{real}")])})})
    assert mw.solve(two).status == "candidate" and set(mw.solve(two).flags) == {"CSCTF{decoy}", "CSCTF{real}"}

    text_only = write_world(tmp_path / "text", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[sign(7, 8, 9, [J("speak friend")] + [J("")] * 3)])})})
    result = mw.solve(text_only)
    assert result.status == "unsure" and result.flags == ()
    assert any(e.kind == "text" and "speak friend" in e.detail and "(7, 8, 9)" in e.detail for e in result.evidence)

    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "readme.txt").write_text("nothing here")
    result = mw.solve(empty)
    assert result.status == "none" and "no Minecraft Java world" in result.notes


def test_solve_options(tmp_path):
    world = write_world(tmp_path / "w", name="CSCTF{reported}")
    out = tmp_path / "report.json"
    mw.solve(world, report=str(out), budget=5, deep=False)
    assert json.loads(out.read_text())["flags"][0]["flag"] == "CSCTF{reported}"
    with pytest.raises(mw.MinecraftWorldError, match="unknown option"):
        mw.solve(world, bugdet=5)


def test_engine_runs_through_ctf_run(tmp_path):
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[sign(1, 2, 3, [J("CSCTF{via_ctf_run}")] + [J("")] * 3)])})})
    proc = subprocess.run([sys.executable, "-m", "ctf", "run", "--no-ledger", "toolkits.minecraft_world",
                           str(world), "--event", "csctf"], cwd=REPO, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    result = SolverResult.from_json(proc.stdout.strip().splitlines()[-1])
    assert result.status == "solved" and result.flags == ("CSCTF{via_ctf_run}",)


# --------------------------------------------------------------------------- CLI
def test_cli_text_json_and_exit_codes(tmp_path, capsys):
    world = write_world(tmp_path / "w", name="Hub", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[sign(1, 2, 3, [J("CSCTF{cli}"), J("line two")] + [J("")] * 2)])})})
    assert mw.main([str(world)]) == 0
    out = capsys.readouterr().out
    assert "world . [java] name='Hub'" in out and "spawn=(0, 64, 0)" in out
    assert "FLAG [direct] CSCTF{cli}" in out
    assert "sign" in out and "at (1, 2, 3): CSCTF{cli} | line two" in out

    assert mw.main([str(world), "--json", "--compact"]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "minecraft-world"

    assert mw.main([str(world), "--event", "pink"]) == 1          # no PINK flag in it
    capsys.readouterr()
    assert mw.main([str(tmp_path / "absent")]) == 2
    assert "no such path" in capsys.readouterr().err
    assert mw.main([str(world), "--event", "no-such-event"]) == 2
    assert "no flag format" in capsys.readouterr().err


def test_where_text():
    assert mw.where_text({"dimension": "the_end", "pos": [1, -2, 3]}) == "the_end, at (1, -2, 3)"
    assert mw.where_text({"dimension": "overworld", "chunk": [4, 5], "deleted": True}).startswith(
        "overworld, chunk (4, 5), orphaned chunk data")
    assert mw.where_text({"player": "abc"}) == "player abc" and mw.where_text(None) == ""


# --------------------------------------------------------------------------- wiring
def test_router_ranks_the_world_walker_above_the_one_region_readers(tmp_path):
    ids = [hit.manifest.id for hit in router.route("misc", "we recovered an old minecraft world download")]
    assert ids.index("toolkits.minecraft_world") < ids.index("toolkits.ffgame_anvil_semantics")
    write_world(tmp_path / "files" / "w")
    by_file = {hit.manifest.id: hit.reason for hit in router.route("forensics", "", tmp_path / "files")}
    assert "level.dat" in by_file["toolkits.minecraft_world"]


def test_intake_plans_the_walker_for_a_world_handout_and_never_the_ping(tmp_path):
    ours = [m for m in engine_manifest.discover()
            if m.id in ("toolkits.minecraft_world", "toolkits.minecraft_netplay", "toolkits.unreal_pak")]
    assert len(ours) == 3
    folder = tmp_path / "unpacked"
    write_world(folder / "w", files={"region/r.0.0.mca": region({0: chunk(0, 0)})})
    plan = intake_engines.plan(ours, "Minecraft", "join the minecraft server at mc.example and find the temple",
                               folder, guard=intake_guard.Guard("hook", (), "test: hook only"))
    assert [job.engine for job in plan.jobs] == ["toolkits.minecraft_world"]
    assert plan.skipped == []
    # the status ping is routed by the brief but has no input adapter: listed for the agent, never run
    assert [row[0] for row in plan.unadapted] == ["toolkits.minecraft_netplay"]


def test_a_minecraft_category_now_has_a_playbook_whose_engine_paths_exist():
    path = dispatch.playbook_path("minecraft")
    assert path is not None and path.is_file()
    assert triage.suggest("Minecraft", "")["playbook"] == "docs/playbooks/minecraft.md"
    text = path.read_text(encoding="utf-8")
    for name in ("minecraft_world.py", "minecraft_netplay.py", "unreal_pak.py", "ffgame_anvil_semantics.py",
                 "research_ff_nbt.py"):
        assert f"solvers/toolkits/{name}" in text and (REPO / "solvers" / "toolkits" / name).is_file()
    for engine in ("toolkits.minecraft_world", "toolkits.minecraft_netplay", "toolkits.unreal_pak"):
        assert engine in text
    assert "player checklist" in text.lower()


# --------------------------------------------------------------------------- several worlds
def test_two_snapshots_that_differ_in_one_chunk_are_both_walked(tmp_path):
    before = region({0: chunk(0, 0, extra=[t_str("n", "CSCTF{snapshot_one}")])})
    after = region({0: chunk(0, 0, extra=[t_str("n", "CSCTF{snapshot_two}")])})
    assert len(before) == len(after)                               # same names, same sizes: only content differs
    write_world(tmp_path / "before", files={"region/r.0.0.mca": before})
    write_world(tmp_path / "after", files={"region/r.0.0.mca": after})
    report = mw.walk(tmp_path)
    assert set(flags_of(report)) == {"CSCTF{snapshot_one}", "CSCTF{snapshot_two}"}
    assert [w["path"] for w in report["worlds"]] == ["after", "before"]
    assert "duplicate_worlds" not in report["stats"]


def test_worlds_past_the_cap_are_named_and_not_read_as_loose_files(tmp_path, monkeypatch):
    monkeypatch.setattr(mw, "MAX_WORLDS", 1)
    for name in ("a", "b"):
        write_world(tmp_path / name, files={
            "region/r.0.0.mca": region({0: chunk(0, 0, extra=[t_str("n", f"CSCTF{{world_{name}}}")])})})
    report = mw.walk(tmp_path)
    assert set(flags_of(report)) == {"CSCTF{world_a}"}
    assert [w["path"] for w in report["worlds"]] == ["a"]
    assert {"what": "worlds", "why": "1 world folder(s) past the first 1 not walked"} in report["skipped"]


def test_backup_dat_old_files_are_read(tmp_path):
    old_player = gzip.compress(nbt_root(t_list_comp("Inventory", [[
        t_str("id", "minecraft:paper"),
        t_comp("tag", t_comp("display", t_str("Name", J("CSCTF{dropped_since}"))))]])), mtime=0)
    world = write_world(tmp_path / "w", files={
        "level.dat_old": level_dat(name="CSCTF{old_world_name}"),
        "playerdata/0000-01.dat_old": old_player})
    report = mw.walk(world)
    assert set(flags_of(report)) == {"CSCTF{old_world_name}", "CSCTF{dropped_since}"}
    assert report["worlds"][0]["level"]["name"] == "Test World"       # the summary is the current level.dat
    (row,) = records(report, "item-name")
    assert row["where"]["player"] == "0000-01" and row["file"] == "playerdata/0000-01.dat_old"


# --------------------------------------------------------------------------- more surfaces and limits
def test_formatting_codes_inside_a_sign_do_not_hide_a_flag(tmp_path):
    line = J({"text": "§aCSCTF{§lcol§rour}"})
    world = write_world(tmp_path / "w", files={
        "region/r.0.0.mca": region({0: chunk(0, 0, block_entities=[sign(1, 1, 1, [line, J(""), J(""), J("")])])})})
    report = mw.walk(world)
    assert flags_of(report) == {"CSCTF{colour}": "component"}
    assert records(report, "sign")[0]["parts"][0] == "CSCTF{colour}"


def test_oversized_file_and_broken_region_files_are_named(tmp_path, monkeypatch):
    monkeypatch.setattr(mw, "MAX_AUX_FILE", 16)
    world = write_world(tmp_path / "w", files={
        "big.log": "x" * 17 + "CSCTF{too_big_to_scan}", "small.txt": "CSCTF{small}",
        "region/r.0.0.mca": b"", "region/r.0.1.mca": b"\x00" * 100})
    report = mw.walk(world)
    assert set(flags_of(report)) == {"CSCTF{small}"}
    assert {"what": "big.log", "why": "larger than the 16 byte cap"} in report["skipped"]
    assert {"what": "region/r.0.1.mca", "why": "shorter than the 8192-byte region header"} in report["skipped"]
    assert report["stats"]["regions_empty"] == 1 and "regions_scanned" not in report["stats"]


def test_newer_level_dat_layout_gives_spawn_and_seed(tmp_path):
    world = tmp_path / "w"
    world.mkdir()
    data = t_comp("Data", t_str("LevelName", "New Layout"),
                  t_comp("spawn", t_int_array("pos", [2600, 70, -40])),
                  t_comp("WorldGenSettings", t_long("seed", -77)))
    (world / "level.dat").write_bytes(gzip.compress(nbt_root(data), mtime=0))
    level = mw.walk(world)["worlds"][0]["level"]
    assert level["spawn"] == [2600, 70, -40] and level["seed"] == -77 and level["name"] == "New Layout"
    assert level["single_player_inventory"] is False


def test_orphaned_data_in_an_entities_file_is_recovered_too(tmp_path):
    gone = nbt_root(t_list_comp("Entities", [[t_str("id", "minecraft:armor_stand"),
                                             t_list_double("Pos", [1.5, 64.0, 1.5]),
                                             t_str("CustomName", J("CSCTF{renamed_since}"))]]))
    world = write_world(tmp_path / "w", files={
        "entities/r.0.0.mca": region({0: nbt_root(t_list_comp("Entities", []))}, orphans=[gone])})
    report = mw.walk(world)
    (row,) = records(report, "custom-name")
    assert row["where"]["deleted"] is True and row["where"]["pos"] == [1, 64, 1]
    assert report["anomalies"] == []                      # slot checks are for terrain chunks only


def test_a_second_tag_with_the_same_name_is_still_read(tmp_path):
    # NBT allows it; a reader that keeps one tag per name would hide the other
    twice = chunk(0, 0, extra=[t_str("note", "CSCTF{first_of_two}"), t_str("note", "CSCTF{second_of_two}")])
    world = write_world(tmp_path / "w", files={"region/r.0.0.mca": region({0: twice})})
    assert set(flags_of(mw.walk(world))) == {"CSCTF{first_of_two}", "CSCTF{second_of_two}"}


def test_no_event_is_an_error_not_a_guessed_flag_format(tmp_path, capsys, monkeypatch):
    world = write_world(tmp_path / "w", name="CSCTF{needs_an_event}")
    monkeypatch.delenv("CTF_EVENT", raising=False)
    with pytest.raises(event.EventError):
        mw.walk(world)
    assert mw.main([str(world)]) == 2
    assert "no flag format" in capsys.readouterr().err
    assert mw.main([str(world), "--event", "csctf"]) == 0
