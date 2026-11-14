"""xlsx_hidden: surface hidden/very-hidden sheets, defined names and their cell text from an .xlsx."""
from __future__ import annotations

import io
import zipfile

import pytest

import xlsx_hidden as xh

MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
RELNS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKGREL = "http://schemas.openxmlformats.org/package/2006/relationships"


def _build_xlsx(sheets, *, shared=None, defined=None):
    """sheets: list of (name, state, rId, part, [cell-xml-strings]). Builds a real OOXML zip."""
    shared = shared or []
    defined = defined or []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("_rels/.rels",
                   f'<Relationships xmlns="{PKGREL}">'
                   f'<Relationship Id="rIdWb" Type="{RELNS}/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        sheet_xml = "".join(
            f'<sheet name="{name}" sheetId="{i+1}" state="{state}" r:id="{rid}"/>'
            for i, (name, state, rid, part, cells) in enumerate(sheets))
        dn_xml = "".join(f'<definedName name="{n}">{v}</definedName>' for n, v in defined)
        z.writestr("xl/workbook.xml",
                   f'<?xml version="1.0"?><workbook xmlns="{MAIN}" xmlns:r="{RELNS}">'
                   f'<sheets>{sheet_xml}</sheets>'
                   f'{"<definedNames>" + dn_xml + "</definedNames>" if dn_xml else ""}</workbook>')
        rels = "".join(
            f'<Relationship Id="{rid}" Type="{RELNS}/worksheet" Target="{part}"/>'
            for name, state, rid, part, cells in sheets)
        z.writestr("xl/_rels/workbook.xml.rels", f'<Relationships xmlns="{PKGREL}">{rels}</Relationships>')
        if shared:
            si = "".join(f"<si><t>{s}</t></si>" for s in shared)
            z.writestr("xl/sharedStrings.xml",
                       f'<?xml version="1.0"?><sst xmlns="{MAIN}" count="{len(shared)}" uniqueCount="{len(shared)}">{si}</sst>')
        for name, state, rid, part, cells in sheets:
            body = "".join(cells)
            z.writestr("xl/" + part if not part.startswith("xl/") else part,
                       f'<?xml version="1.0"?><worksheet xmlns="{MAIN}"><sheetData><row>{body}</row></sheetData></worksheet>')
    return buf.getvalue()


def _inline(text):
    return f'<c t="inlineStr"><is><t>{text}</t></is></c>'


def _shared_ref(idx):
    return f'<c t="s"><v>{idx}</v></c>'


def test_very_hidden_sheet_inline_flag():
    data = _build_xlsx([
        ("Visible", "visible", "rId1", "worksheets/sheet1.xml", [_inline("nothing here")]),
        ("Secret", "veryHidden", "rId2", "worksheets/sheet2.xml", [_inline("CSCTF{v3ry_h1dd3n_sh33t}")]),
    ])
    r = xh.inspect(data)
    assert len(r["sheets"]) == 2
    secret = next(s for s in r["sheets"] if s["name"] == "Secret")
    assert secret["state"] == "veryHidden"
    assert "CSCTF{v3ry_h1dd3n_sh33t}" in secret["cells"]
    assert "CSCTF{v3ry_h1dd3n_sh33t}" in r["flags"]


def test_hidden_sheet_shared_string_flag():
    data = _build_xlsx(
        [("H", "hidden", "rId1", "worksheets/sheet1.xml", [_shared_ref(1)])],
        shared=["decoy", "CSCTF{sh4r3d_str1ng}"])
    r = xh.inspect(data)
    assert r["sheets"][0]["state"] == "hidden"
    assert "CSCTF{sh4r3d_str1ng}" in r["flags"]


def test_defined_name_value_flag():
    data = _build_xlsx(
        [("S", "visible", "rId1", "worksheets/sheet1.xml", [_inline("x")])],
        defined=[("flag", "&quot;CSCTF{def1n3d_n4m3}&quot;".replace("&quot;", ""))])
    r = xh.inspect(data)
    assert any(d["name"] == "flag" for d in r["defined_names"])
    assert "CSCTF{def1n3d_n4m3}" in r["flags"]


def test_visible_sheet_cells_not_extracted():
    # we only pull cell text for hidden/very-hidden sheets (latency + noise); visible gets name+state only
    data = _build_xlsx([("V", "visible", "rId1", "worksheets/sheet1.xml", [_inline("CSCTF{visible}")])])
    r = xh.inspect(data)
    assert "cells" not in r["sheets"][0]
    # a flag typed into a visible sheet is NOT scanned here (that's a normal-cell reader's job)
    assert "CSCTF{visible}" not in r["flags"]


def test_flag_in_sheet_name():
    data = _build_xlsx([("CSCTF{n4m3}", "hidden", "rId1", "worksheets/sheet1.xml", [])])
    r = xh.inspect(data)
    assert "CSCTF{n4m3}" in r["flags"]


def test_fail_closed():
    with pytest.raises(xh.XlsxError):
        xh.inspect("not bytes")
    with pytest.raises(xh.XlsxError):
        xh.inspect(b"short")
    with pytest.raises(xh.XlsxError):
        xh.inspect(b"NOTPKzip" + b"\x00" * 30)       # bad magic
    with pytest.raises(xh.XlsxError):
        xh.inspect(b"PK\x03\x04" + b"\x00" * 60)      # PK magic but not a valid zip
    # a valid zip that isn't a spreadsheet (no workbook.xml)
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("hello.txt", "hi")
    with pytest.raises(xh.XlsxError):
        xh.inspect(b.getvalue())


def test_cli(capsys, tmp_path):
    data = _build_xlsx([("Hid", "veryHidden", "rId1", "worksheets/sheet1.xml", [_inline("CSCTF{cli_xlsx}")])])
    p = tmp_path / "book.xlsx"
    p.write_bytes(data)
    assert xh.main([str(p)]) == 0
    out = capsys.readouterr().out
    assert "CSCTF{cli_xlsx}" in out and "VERYHIDDEN" in out
    assert xh.main([str(tmp_path / "missing.xlsx")]) == 1
    assert xh.main(["--help"]) == 0
