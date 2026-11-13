"""B-216: day-agnostic member selection by name, then leniently, then by content (content_members.py)."""
import binary_lookahead as L
import content_members as cm

ELF = L.elf64([(".text", b"\xc3" * 32, 6, 0x401000)])
PE = L.pe64([(".text", b"\xc3" * 64, 0x60000020)])


def names(sel):
    return [n for n, _ in sel.members]


def test_by_name_first_and_other_days_ignored():
    files = {"d07--variant-000.elf": ELF, "d07--variant-000.json": b"{}", "d08--variant-000.elf": PE}
    sel = cm.select(files, {}, 7)
    assert sel.how == "name" and names(sel) == ["d07--variant-000.elf", "d07--variant-000.json"]


def test_lenient_day_word_on_a_folder():
    files = {"day07/sample.elf": ELF, "day08/sample.elf": PE}
    sel = cm.select(files, {}, 7)
    assert sel.how == "lenient" and names(sel) == ["day07/sample.elf"]


def test_content_picks_the_one_unclaimed_image_and_its_stem_mates():
    files = {"payload.exe": PE, "payload.runtimeconfig.json": b"{}", "notes.txt": b"hello", "d08--x.elf": ELF}
    sel = cm.select(files, {}, 7)
    assert sel.how == "content"
    assert sorted(names(sel)) == ["payload.exe", "payload.runtimeconfig.json"]
    assert any("picked by content" in n for n in sel.notes)


def test_two_unclaimed_images_are_ambiguous():
    sel = cm.select({"a.elf": ELF, "b.exe": PE}, {}, 7)
    assert sel.how is None and sel.members == []
    assert any("2 images are unclaimed" in n for n in sel.notes)


def test_an_accept_predicate_decides_among_several():
    sel = cm.select({"a.elf": ELF, "b.exe": PE}, {}, 7, accept=lambda b: b[:2] == b"MZ")
    assert sel.how == "content" and names(sel) == ["b.exe"]


def test_no_image_no_pick():
    sel = cm.select({"readme.txt": b"text only"}, {}, 7)
    assert sel.how is None and sel.members == []


def test_the_delivery_archive_is_never_a_member():
    delivery = b"PK\x03\x04" + b"\0" * 30
    sel = cm.select({"evidence.zip": delivery, "sample.elf": ELF}, {"delivery": delivery,
                                                                     "delivery_name": "evidence.zip"}, 7)
    assert names(sel) == ["sample.elf"]


def test_is_image_magics():
    assert all(cm.is_image(x) for x in (ELF, PE, L.macho64(None), b"\0asm\1\0\0\0", b"dex\n035\0"))
    assert not any(cm.is_image(x) for x in (b"PK\3\4", b"{}", b"", None))
