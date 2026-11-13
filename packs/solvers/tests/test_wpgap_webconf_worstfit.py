"""Published-vector tests for the offline Windows WorstFit evidence model.

Expected strings below are literal, hand-audited rows from Microsoft's
WindowsBestFit mapping files, as reproduced by Orange Tsai's WorstFit
research.  They are intentionally not produced with the implementation under
test or Python's codecs (which do not emulate WideCharToMultiByte best fit).
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import wpgap_webconf_analyzer as webconf  # noqa: E402


def test_cp1252_published_math_vector_is_occurrence_preserving():
    # Orange Tsai's published CP1252 demonstration.  Microsoft best-fit rows:
    # U+221A->v, U+03C0->p, U+2077->7, U+2264->=, U+221E->8.
    report = webconf.analyze_best_fit("√π⁷≤∞", "cp1252")

    assert report.projected_text == "vp7=8"
    assert report.complete is True
    assert report.unknown_codepoints == ()
    assert [row.offset for row in report.mappings] == [0, 1, 2, 3, 4]
    assert [row.source for row in report.mappings] == ["√", "π", "⁷", "≤", "∞"]
    assert [row.replacement for row in report.mappings] == ["v", "p", "7", "=", "8"]

    encoded = report.as_dict()
    assert encoded["offline"] is True
    assert encoded["network_requests"] == 0
    assert encoded["vulnerability_confirmed"] is False
    assert encoded["projected_text"] == "vp7=8"
    assert report.findings
    json.dumps(encoded, sort_keys=True)


@pytest.mark.parametrize(
    ("code_page", "source", "expected"),
    [
        # PHP CVE-2024-4577's dangerous soft-hyphen-to-hyphen family.
        ("cp932", "¥\u00ad", "\\-"),
        ("cp936", "\u00ad", "-"),
        ("cp950", "\u00ad", "-"),
        # Korean won becomes the Windows path separator under CP949 best fit.
        ("cp949", "₩", "\\"),
        # Orange Tsai's Perl CGI path-routing example under CP1250.
        ("cp1250", "/cgi.pl/àdmin", "/cgi.pl/admin"),
        # Fullwidth syntax collapses to ASCII in the CP1252 best-fit table.
        ("cp1252", "＂／＼", '"/\\'),
    ],
)
def test_published_windows_best_fit_vectors(code_page: str, source: str, expected: str):
    report = webconf.analyze_best_fit(source, code_page)

    assert report.projected_text == expected
    assert report.complete is True
    assert report.unknown_codepoints == ()
    assert report.mappings
    assert report.as_dict()["vulnerability_confirmed"] is False


def test_cp932_fullwidth_slash_is_not_falsely_treated_as_ascii_slash():
    # CP932 represents U+FF0F as a multibyte fullwidth character.  It is not
    # the CP1252 single-byte best-fit row U+FF0F->0x2F.  A small curated model
    # must therefore decline to project it, never borrow another code page's
    # mapping or substitute NFKC.
    report = webconf.analyze_best_fit("／", "cp932")

    assert report.projected_text is None
    assert report.complete is False
    assert report.mappings == ()
    assert report.unknown_codepoints
    assert "U+FF0F" in json.dumps(report.as_dict(), sort_keys=True)
    assert report.findings
    assert report.as_dict()["vulnerability_confirmed"] is False


def test_best_fit_table_can_be_filtered_without_mutating_the_catalog():
    all_rows = webconf.best_fit_table()
    cp932_rows = webconf.best_fit_table("cp932")

    assert isinstance(all_rows, tuple)
    assert isinstance(cp932_rows, tuple)
    assert cp932_rows
    assert len(cp932_rows) < len(all_rows)
    assert cp932_rows == webconf.best_fit_table("cp932")
    assert {row.code_page for row in cp932_rows} == {"cp932"}
    assert {(row.source, row.replacement) for row in cp932_rows} >= {
        ("¥", "\\"),
        ("\u00ad", "-"),
    }


@pytest.mark.parametrize(
    ("text", "code_page"),
    [
        ("x", "cp437"),
        ("x", ""),
        ("x", object()),
        (b"x", "cp1252"),
        ("a\x00b", "cp1252"),
        ("\ud800", "cp1252"),
    ],
)
def test_best_fit_public_boundary_uses_only_declared_exception(text, code_page):
    with pytest.raises(webconf.WPGAPWebConfError):
        webconf.analyze_best_fit(text, code_page)


def test_best_fit_table_rejects_unknown_code_page_with_declared_exception():
    with pytest.raises(webconf.WPGAPWebConfError):
        webconf.best_fit_table("cp437")

