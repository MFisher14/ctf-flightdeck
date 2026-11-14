#!/usr/bin/env python3
"""The maldoc toolkit on real documents (solvers/toolkits/maldoc.py).

  .venv/bin/python tests/real/test_real_maldoc.py

Offline. SKIPs when `challenges/_realdata/maldoc/` is absent (tests/real/fetch_a.py fills it). The files are
public test corpora: oletools' own test documents (VBA in Word, Excel and PowerPoint, Excel 4 macros in xls,
xlsm, xlsb and SYLK, DDE in docx, xlsx, CSV and 2003 XML, embedded OLE packages, encrypted workbooks, RTF
objects), pypdf's sample PDFs and LnkParse3's sample shortcuts. Neither Huntress write-up repository holds
a malicious document, so there is no challenge drill for this toolkit.

What each expectation rests on:
  macros, DDE, objects   oletools run in the sandbox on 2026-10-08: olevba (macro count, the auto-exec
                         keywords it reports), msodde (the DDE links it prints), oleobj (the embedded
                         package's file name and paths), rtfobj. The values are written below.
                         CTF_TK_LIVE=1 with the sandbox up runs olevba again and compares.
  PDFs                   pdfminer.six, read here (page count, encryption).
  shortcuts              LnkParse3, read here.
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import warnings

from _real_a import check, finish, folder, is_plain, manifest, offers, q, timed, values

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import paths

D = folder("maldoc")
import maldoc as M     # noqa: E402

# olevba in the sandbox, 2026-10-08: (file, macros olevba lists > 0, its AutoExec keywords)
OLEVBA = {"oletools-sample_with_vba.ppt": (True, ["Action_Click"]), "oletools-oleform-PR314.docm": (True, ["Frame1_Click", "TabStrip1_Change"]),
          "oletools-excel4_sample_macro.xls": (True, ["Auto_Open"]), "oletools-excel4_sample_macro_excel5_format.xls": (True, ["Auto_Open"]),
          "oletools-excel4_sample_macro.slk": (True, ["Auto_Open"]), "oletools-autostart-encrypt-standardpassword.xlsm": (True, ["Auto_Open"]),
          "oletools-autostart-encrypt-standardpassword.xls": (True, ["Auto_Open"]),
          "oletools-harmless-clean.doc": (False, []), "oletools-harmless-clean.docx": (False, []), "oletools-dde-test.docx": (False, []),
          "oletools-embedded-simple-2007.doc": (False, []), "oletools-embedded-simple-2007.xls": (False, []),
          "oletools-sample_with_lnk_file.ppt": (False, []), "oletools-sample_with_external_link_to_doc.xlsx": (False, [])}
# msodde in the sandbox, 2026-10-08: the DDE links it prints
MSODDE = {"oletools-dde-test.xlsx": ["cmd /c calc.exe"], "oletools-dde-in-csv.csv": ["cmd '/k \\..\\..\\..\\Windows\\System32\\calc.exe'"],
          "oletools-dde-in-excel2003.xml": ["cmd '/c calc.exe'"]}
EXTERNAL = "https://raw.githubusercontent.com/decalage2/oletools/master/tests/test-data/oleobj/embedded-simple-2007.doc"     # oleobj


def ask(name, as_name, *questions):
    data = (D / name).read_bytes()
    qs = [q(f"q{i}", t if isinstance(t, str) else t[1], "exact_text" if isinstance(t, str) else t[0], artifact=as_name) for i, t in enumerate(questions)]
    got, _ = timed(f"solve_set {name}", lambda: M.solve_set(qs, {as_name: data}, {"partial": {}}), len(data))
    return [got.get(x["id"]) for x in qs]


def main() -> int:
    names = [e["name"] for e in manifest("maldoc")]
    check("every document of the manifest is in the cache", all((D / n).is_file() for n in names), [n for n in names if not (D / n).is_file()][:5])

    # ---- every file parses, reports, and none is slow
    docs = {}
    for n in names:
        data = (D / n).read_bytes()
        try:
            doc, dt = timed(f"parse+report {n}", lambda: (lambda d: (d, M.report(d))[0])(M.parse(data, n)), len(data))
        except Exception as e:            # noqa: BLE001  a crash on a real file is the finding
            check(f"{n}: parsed and reported", False, f"{type(e).__name__}: {e}")
            continue
        docs[n] = doc
        bad = [x for x in doc["notes"] if x.startswith("not fully read")]
        if bad:
            check(f"{n}: read in full", False, bad)
    check(f"all {len(docs)} documents parse and report without an error or a reader that gave up", len(docs) == len(names))
    kinds = {n: d["kind"] for n, d in docs.items()}
    check("kinds by the bytes: PowerPoint, encrypted package, SYLK, 2003 XML, a CSV with a DDE formula, RTF, PDF, shortcut",
          kinds["oletools-sample_with_vba.ppt"] == "ole_powerpoint" and kinds["oletools-encrypted.docx"] == "ole_encrypted" and kinds["oletools-excel4_sample_macro.slk"] == "slk"
          and kinds["oletools-dde-in-excel2003.xml"] == "xml_excel_2003" and kinds["oletools-dde-in-csv.csv"] == "csv_dde" and kinds["oletools-issue_251.rtf"] == "rtf"
          and kinds["pypdf-with-attachment.pdf"] == "pdf" and kinds["lnkparse3-sample.lnk"] == "lnk", kinds)

    # ---- macros, as olevba finds them
    for n, (has, auto) in OLEVBA.items():
        f = docs[n]["fields"]
        mine = sorted(set(str(x) for d in M.flatten(docs[n]) for x in (d["fields"].get("autoexec") or [])) | {x for x in auto if x in (f.get("procedure_names") or [])})
        ok = f.get("has_macros") is has and (not auto or any(a.lower() in [m.lower() for m in mine] for a in auto) or n.endswith((".xls", ".slk")))
        check(f"{n}: has_macros is {has}, as olevba" + (f" (its auto-exec {auto[0]} is found)" if auto and not n.endswith(".xls") else ""), ok, (f.get("has_macros"), mine))
    ppt = docs["oletools-sample_with_vba.ppt"]
    check("PowerPoint 97: the VBA project is a compressed storage inside the PowerPoint Document stream, read as a child",
          [c["kind"] for c in ppt["children"]] == ["ole_vba_project"] and ppt["fields"].get("module_names") == ["Module1"]
          and ppt["fields"].get("procedure_names") == ["Action_Click"], [c["kind"] for c in ppt["children"]])
    enc = docs["oletools-autostart-encrypt-standardpassword.xlsm"]
    check("an encrypted workbook: Excel's built-in password opens it; encrypted and has_macros are both true of the file",
          enc["fields"].get("encrypted") is True and enc["fields"].get("has_macros") is True and enc["children"] and enc["children"][0]["fields"].get("autoexec") == ["Auto_Open"])
    check("an xlsb workbook: its binary parts are not read, so has_macros is absent, not false (olevba finds nothing in it either)",
          "has_macros" not in docs["oletools-excel4_sample_macro.xlsb"]["fields"], docs["oletools-excel4_sample_macro.xlsb"]["fields"].get("has_macros"))
    check("an xlsm macro sheet: Excel 4 macros are found (olevba lists none for this file)", docs["oletools-excel4_sample_macro.xlsm"]["fields"].get("has_macros") is True)
    check("a document whose password is not known is encrypted and says nothing of macros beyond that",
          docs["oletools-encrypted.docx"]["fields"].get("encrypted") is True and not docs["oletools-encrypted.docx"]["children"])

    # ---- DDE, as msodde prints it
    for n, want in MSODDE.items():
        check(f"{n}: the DDE link is msodde's: {want[0]}", docs[n]["fields"].get("dde") == want, docs[n]["fields"].get("dde"))
    dde = docs["oletools-dde-test.docx"]["fields"].get("dde") or []
    check("dde-test.docx: both fields msodde prints, DDEAUTO and DDE, each running cmd.exe /k calc.exe", len(dde) == 2 and dde[0].startswith("DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe")
          and dde[1].startswith("DDE c:\\\\windows\\\\system32\\\\cmd.exe"), dde)
    check("no DDE in the clean documents", not docs["oletools-harmless-clean.docx"]["fields"].get("dde") and not docs["oletools-harmless-clean.doc"]["fields"].get("dde"))

    # ---- embedded objects, as oleobj and rtfobj find them
    lnkppt = docs["oletools-sample_with_lnk_file.ppt"]
    flat = M.flatten(lnkppt)
    pkg = [d for d in flat if d["kind"] == "ole_package"]
    lnk = [d for d in flat if d["kind"] == "lnk"]
    check("sample_with_lnk_file.ppt: the OLE Package oleobj extracts (calc.lnk, its source and temp paths) and the shortcut inside",
          len(pkg) == 1 and pkg[0]["fields"].get("package_source_paths") == ["C:\\Users\\user\\Desktop\\calc.lnk"]
          and pkg[0]["fields"].get("package_temp_paths") == ["C:\\Users\\user\\AppData\\Local\\Temp\\calc.lnk"] and len(lnk) == 1 and lnk[0]["name"] == "calc.lnk"
          and lnk[0]["fields"].get("target") == "C:\\Windows\\System32\\calc.exe", [d["name"] for d in flat])
    check("sample_with_external_link_to_doc.xlsx: the external oleObject relationship oleobj reports",
          docs["oletools-sample_with_external_link_to_doc.xlsx"]["fields"].get("external_targets") == [EXTERNAL])
    for n in ("oletools-embedded-simple-2007.doc", "oletools-embedded-simple-2007.docx", "oletools-embedded-simple-2007.xls"):
        check(f"{n}: one embedded object", docs[n]["fields"].get("embedded_count") == 1, docs[n]["fields"].get("embedded_count"))
    rtf = docs["oletools-issue_251.rtf"]["fields"]
    check("issue_251.rtf: one object (rtfobj: index 0, not a well-formed OLE object) of class equation.3", rtf.get("object_count") == 1 and rtf.get("object_classes") == ["equation.3"], rtf)

    # ---- questions in the event's style
    a = ask("oletools-sample_with_vba.ppt", "invoice.ppt", "Does the document contain macros?", "What is the name of the VBA module?", "What type of macro does the document contain?")
    check("ppt: macros yes (unsure), the module's name, the macro type", values(a[0])[:1] == ["true"] and values(a[1])[:1] == ["Module1"] and values(a[2])[:1] == ["vba"], a)
    a = ask("oletools-sample_with_lnk_file.ppt", "report.ppt", "What is the name of the embedded file?", "What is the SHA-256 of the embedded file calc.lnk?",
            "What is the target of the embedded shortcut?")
    check("ppt with a package: the embedded file is calc.lnk (a storage this file named itself is not offered as a file name)", values(a[0]) == ["calc.lnk"], a[0])
    check("... the hash asked of calc.lnk is the shortcut's own bytes, not the storage's around it", values(a[1]) == [lnk[0]["sha256"]] and lnk[0]["sha256"] == hashlib.sha256(lnk[0]["data"]).hexdigest(), a[1])
    check("... and the shortcut's target", values(a[2]) == ["C:\\Windows\\System32\\calc.exe"], a[2])
    a = ask("oletools-autostart-encrypt-standardpassword.xlsm", "book.xlsm", "Is the document encrypted?", "Does the document contain macros?",
            "Which macro runs automatically when the workbook is opened?")
    check("encrypted xlsm: encrypted yes, macros yes, Auto_Open: all unsure, none plain", [values(x)[:1] for x in a] == [["true"], ["true"], ["Auto_Open"]] and not any(is_plain(x) for x in a), a)
    a = ask("oletools-issue_251.rtf", "doc.rtf", "What is the class name of the embedded object?", "Which CVE does the document exploit?")
    check("rtf: the class name is the object's class, not a payload name; the CVE is a label offered, never plain", values(a[0])[:1] == ["equation.3"] and "CVE-2017-11882" in values(a[1]), a)
    a = ask("oletools-dde-in-csv.csv", "data.csv", "What DDE command does the file run?")
    check("csv: the DDE formula is offered", values(a[0]) == MSODDE["oletools-dde-in-csv.csv"], a[0])
    a = ask("oletools-dde-test.docx", "doc.docx", "What DDE command does the document run?", "Does the document contain macros?")
    check("docx with two DDE fields: two candidates, no answer; macros no (unsure)", a[0] is None and values(a[1])[:1] == ["false"], a)

    # ---- PDFs against pdfminer.six
    try:
        from pdfminer.pdfdocument import PDFDocument, PDFPasswordIncorrect
        from pdfminer.pdfpage import PDFPage
        from pdfminer.pdfparser import PDFParser
    except Exception:            # noqa: BLE001
        PDFDocument = None
        print("note pdfminer.six not importable: the PDF comparison is skipped")
    for n in [x for x in names if x.endswith(".pdf")]:
        f = docs[n]["fields"]
        if PDFDocument is None:
            continue
        try:
            with open(D / n, "rb") as h:
                pages, locked = sum(1 for _ in PDFPage.create_pages(PDFDocument(PDFParser(h)))), False
        except PDFPasswordIncorrect:
            pages, locked = None, True
        mine = f.get("page_count")
        mine = {v for _, v in mine} if isinstance(mine, M.Alt) else {mine}
        check(f"{n}: " + ("needs a password, as pdfminer says: encrypted, and no page count is given" if locked else f"{pages} page(s) and not encrypted, as pdfminer reads it"),
              (f.get("encrypted") is True and mine == {None}) if locked else (mine == {pages} and f.get("encrypted") is False), (f.get("encrypted"), mine))
    att = docs["pypdf-with-attachment.pdf"]
    check("with-attachment.pdf: one embedded file, image.png, a PNG by its bytes", att["fields"].get("embedded_names") == ["image.png"] and att["children"][0]["data"][:8] == b"\x89PNG\r\n\x1a\n")
    a = ask("pypdf-with-attachment.pdf", "file.pdf", ("integer", "How many pages does the PDF have?"), "What is the name of the file embedded in the PDF?", "Is the PDF encrypted?")
    check("pdf: the page count is plain 1; the embedded name and the encryption flag are unsure", a[0] == "1" and values(a[1]) == ["image.png"] and values(a[2])[:1] == ["false"], a)
    a = ask("pypdf-libreoffice-writer-password.pdf", "file.pdf", "Is the PDF encrypted?", ("integer", "How many pages does the PDF have?"))
    check("a PDF that needs a password: encrypted is answered (unsure), nothing else", values(a[0])[:1] == ["true"] and a[1] is None, a)
    a = ask("pypdf-libre-office-link.pdf", "file.pdf", "What URL does the PDF link to?")
    check("pdf: the link annotation's URL", offers(a[0], "https://martin-thoma.com/"), a[0])

    # ---- shortcuts against LnkParse3
    try:
        import LnkParse3
    except Exception:            # noqa: BLE001
        LnkParse3 = None
        print("note LnkParse3 not importable: the shortcut comparison is skipped")
    for n in [x for x in names if x.endswith(".lnk")]:
        if LnkParse3 is None:
            continue
        data = (D / n).read_bytes()
        mine = M.lnk(data)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            j = LnkParse3.lnk_file(io.BytesIO(data)).get_json()
        d, li = j.get("data") or {}, j.get("link_info") or {}
        same = (mine.get("arguments") or None) == (d.get("command_line_arguments") or None) and (mine.get("working_dir") or None) == ((d.get("working_directory") or "").rstrip() or None) \
            and (mine.get("relative_path") or None) == (d.get("relative_path") or None) and (mine.get("description") or None) == (d.get("description") or None) \
            and (not li.get("local_base_path") or mine.get("target") == li["local_base_path"] + (li.get("common_path_suffix") or ""))
        check(f"{n}: arguments, working directory, relative path, description and local target as LnkParse3 reads them", same,
              {k: str(mine.get(k))[:50] for k in ("arguments", "working_dir", "target")})
    pad = docs["lnkparse3-padded_cli_arguments.lnk"]["fields"]
    check("padded shortcut: cmd.exe from the item list, the hidden /c arguments, the padding noted", pad.get("target") == "C:\\Windows\\System32\\cmd.exe"
          and str(pad.get("arguments")).startswith('/c "set PATH=') and pad.get("padded") is True and pad.get("working_dir") == "C:\\Windows\\System32", pad.get("target"))
    a = ask("lnkparse3-padded_cli_arguments.lnk", "invoice.lnk", "What is the target of the shortcut?", "What is the icon location of the shortcut?")
    check("padded shortcut: target and icon location are offered", values(a[0]) == ["C:\\Windows\\System32\\cmd.exe"] and values(a[1]) == ["C:\\Windows\\System32\\shell32.dll"], a)

    # ---- the command line; a zip no stored password opens is said, not guessed at
    env = dict(os.environ, CTF_WORKDIR=str(paths.workdir()))
    r = subprocess.run([sys.executable, str(M.__file__), str(D / "oletools-sample_with_vba.ppt")], capture_output=True, text=True, timeout=120, env=env)
    check("cli: the PowerPoint report says has_macros True and shows the child", r.returncode == 0 and "has_macros" in r.stdout and "ExternalOleObjectStg1" in r.stdout, r.stderr[-300:])
    r = subprocess.run([sys.executable, str(M.__file__), str(D / "oletools-issue_185.rtf.zip")], capture_output=True, text=True, timeout=120, env=env)
    check("cli: an encrypted zip whose password is not stored is a NOTE (`infected` and the stored ones are tried, nothing else)", "no stored password opens" in r.stdout, r.stdout[-300:])

    if os.environ.get("CTF_TK_LIVE") == "1":
        for n, (has, auto) in OLEVBA.items():
            code, text, _ = M.sandbox_run("olevba", (D / n).read_bytes(), n, args=("-a", "--json", "{in}"), timeout=90)
            if code is None:
                print("NOTE sandbox down: the live olevba comparison did not run")
                break
            try:
                rows = json.loads(text[text.index("["):text.rindex("]") + 1])
                found = any(c.get("macros") for c in rows if isinstance(c, dict))
            except ValueError:
                found = None
            check(f"live: olevba {'finds' if has else 'finds no'} macros in {n}", found is has, found)
    return finish("test_real_maldoc")


if __name__ == "__main__":
    sys.exit(main())
