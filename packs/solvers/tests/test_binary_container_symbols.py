"""B-216: symbols from the container's own table (solvers/binary/container_symbols.py)."""
import pytest

import binary_lookahead as L
import container_symbols as cs

TEXT = [(".text", b"\xc3" * 32, 6, 0x401000), (".data", b"D" * 16, 3, 0x402000)]


def test_elf_symtab_names_in_raw_order_and_defined_functions():
    data = L.elf64(TEXT, symtab=[("zeta", 2, 1), ("alpha", 2, 1), ("g_data", 1, 2), ("ext_fn", 2, 0)])
    got = cs.read(data)
    assert got.container == "elf" and got.table == "symtab" and got.absent is False
    assert got.names == ["", "zeta", "alpha", "g_data", "ext_fn"]          # table order, not sorted
    assert got.functions == ["zeta", "alpha"]                              # STT_FUNC with a section only


def test_stripped_elf_proves_absence():
    got = cs.read(L.elf64(TEXT))
    assert got.table is None and got.absent is True
    assert cs.absent(L.elf64(TEXT)) == (True, got.why)


def test_stripped_elf_that_exports_a_function_is_not_absent():
    got = cs.read(L.elf64(TEXT, dynsym=[("exported_fn", 2, 1), ("undef_import", 2, 0)]))
    assert got.absent is False and got.table is None and got.exports == ["exported_fn"]


def test_elf_with_only_undefined_dynamic_functions_is_absent():
    assert cs.read(L.elf64(TEXT, dynsym=[("puts", 2, 0)])).absent is True


def test_elf_without_a_section_table_is_not_proof():
    data = bytearray(L.elf64(TEXT))
    data[0x28:0x30] = b"\0" * 8          # e_shoff = 0
    got = cs.read(bytes(data))
    assert got.absent is None and got.table is None


def test_pe_coff_symbols_in_raw_order_with_long_names_and_aux_skipped():
    data = L.pe64([(".text", b"\xc3" * 64, 0x60000020), (".rdata", b"R" * 16, 0x40000040)],
                  coff_symbols=[(".text", 1, 0, 3, 1), ("zz_main", 1, 0x20, 2),
                                ("a_function_name_longer_than_eight", 1, 0x20, 2), ("g_table", 2, 0, 2),
                                ("imported", 0, 0x20, 2)])
    got = cs.read(data)
    assert got.container == "pe" and got.table == "coff" and got.absent is False
    assert got.names == [".text", "zz_main", "a_function_name_longer_than_eight", "g_table", "imported"]
    assert got.functions == ["zz_main", "a_function_name_longer_than_eight"]


def test_pe_without_coff_table_or_exports_proves_absence():
    got = cs.read(L.pe64([(".text", b"\xc3" * 64, 0x60000020)]))
    assert got.absent is True and got.table is None


def test_pe_exports_are_read_and_deny_absence():
    got = cs.read(L.pe64([(".text", b"\xc3" * 64, 0x60000020)], exports=["CheckLicense", "Init"]))
    assert got.exports == ["CheckLicense", "Init"] and got.absent is False


def test_macho_lc_symtab_functions_and_exports():
    got = cs.read(L.macho64([("_main", 0x0F, 1), ("_local_fn", 0x0E, 1), ("_puts", 0x01, 0), ("stab", 0x24, 1)]))
    assert got.container == "macho" and got.table == "macho" and got.absent is False
    assert got.names == ["_main", "_local_fn", "_puts", "stab"]
    assert got.functions == ["_main", "_local_fn"] and got.exports == ["_main"]


def test_macho_without_lc_symtab_proves_absence():
    assert cs.read(L.macho64(None)).absent is True


def test_macho_lc_symtab_with_no_entries_proves_absence():
    got = cs.read(L.macho64([]))                    # an LC_SYMTAB command with nsyms 0
    assert got.absent is True and got.table is None


@pytest.mark.parametrize("data", [b"", b"plain text", b"\x7fELF\x02", b"MZ" + b"\0" * 10])
def test_not_an_image_reads_none_and_is_never_absent(data):
    assert cs.read(data) is None
    assert cs.absent(data)[0] is False


def test_container_of_reads_the_magic():
    assert [cs.container_of(x) for x in (L.elf64(TEXT), L.pe64(), L.macho64(None), b"PK\3\4")] == \
        ["elf", "pe", "macho", None]


def test_cli(tmp_path, capsys):
    p = tmp_path / "s.bin"
    p.write_bytes(L.elf64(TEXT, symtab=[("main", 2, 1)]))
    assert cs._main([str(p)]) == 0
    assert "table=symtab" in capsys.readouterr().out
