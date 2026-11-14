# Malicious documents: `solvers/toolkits/maldoc.py` (toolkit key `maldoc`, backlog row 87)

Static only. Nothing in a document is run, opened in its application or fetched. Plain Python in this process,
well under a second for a small file; oletools, binwalk and 7z only inside `tools/sandbox.py`.

## First minute

```bash
PY=.venv/bin/python
$PY solvers/toolkits/maldoc.py --attempt workspace/<id>            # every question: field, document, answer, why
$PY solvers/toolkits/maldoc.py <file>... [--source] [--json]        # triage of files: fields, payloads, YARA hits
$PY solvers/toolkits/maldoc.py <file> --extract <scratch dir>       # payloads, script blocks, VBA modules as files
$PY solvers/toolkits/maldoc.py <file> --sandbox                     # adds olevba (or rtfobj) from the container
```

Reason to the one flag from the output, then submit it once via `ctf.submit.guarded_submit(...)` (or
`./csctf submit <id> <flag>`); an OSINT/templated answer uses `allow_nonstandard=True`.

`--attempt` reads a saved attempt (copy it to a scratch folder first if a tool already wrote there). The `why`
column says which rule gave or refused each answer. Unpacked members for reading: `tools/unpack.py`.

## What it reads

| Family (by magic, never by name) | Read | Not read here |
| --- | --- | --- |
| `ole` Word/Excel/PowerPoint 97-2003, MSI, MSG, `vbaProject.bin` | streams, SummaryInformation, VBA modules and source, XLM macro sheets and formulas (BIFF8 tokens), `\x01Ole10Native`, FILEPASS / EncryptedPackage marks, ActiveMime | p-code (VBA stomping), form control values, Word body text beyond its strings; XLM functions outside a small table give no formula |
| `ooxml` docx/docm/xlsx/xlsm/pptx | core and app properties, `vbaProject.bin`, external relationships, `attachedTemplate`, DDE fields, macro sheets, sheet states, embeddings | xlsb binary parts |
| `rtf` | every `\objdata` object (OLE1 header, class, Package file, embedded OLE2), `\objupdate`, `\*\template`, `\info` | objects hidden by `\bin` tricks other than a plain `\binN` |
| `pdf` | objects, object streams, Flate/ASCIIHex/ASCII85/RunLength, Info, JavaScript, OpenAction, AA, Launch, URI, embedded files, `#xx` names; an encrypted file with the empty user password through pypdf | LZW and image filters, XFA forms, a file that needs a password |
| `onenote` | every FileDataStoreObject (embedded file) | which name belongs to which file (`embedded_name_candidates` lists the names found) |
| `lnk` | target, arguments, working directory, icon, times, size, show command, volume serial and label, tracker machine id and MAC, bytes appended after the link | the ID list items |
| `iso`, `disk_image`, `vhd` | ISO 9660 + Joliet, MBR/GPT, FAT12/16/32 with long names, deleted and hidden entries, fixed and dynamic VHD | UDF-only, NTFS, exFAT, VHDX (a note tells you to list them with the sandbox's 7z) |
| `hta`, `wsf`, `sct` | script blocks and their language, external `src`, HTA attributes | the script itself: it goes to the Script Analysis engines |

Payloads (an embedded object, a file of an image, a script block) are read the same way, three levels deep. A
script block is named `<file>#script<N>.<ext>`; `--extract` writes it and the Script Analysis engines in
`solvers/script-analysis/` read it (`js_interp.py`, `powershell.py`, `vbscript.py` by language). VBA and XLM
strings built with `Chr`, `ChrW`, `&`, `StrReverse`, `Replace`, `Mid`, `Left`, `Right`,
`Join(Array())`, `CHAR`, base64, hex and PowerShell `-enc` are evaluated; a decoder the author wrote as a
function is not (read it with `--source`).

By hand, in Python (`sys.path.insert(0, "solvers/toolkits"); import maldoc`): `parse(data, name)`, `cfb(data)`,
`vba_modules(data)`, `vba_decompress(b)`, `deobfuscate(source)`, `mraptor(source)`, `ole_properties(data)`,
`ooxml(data)`, `rtf_objects(data)`, `pdf(data)`, `pdf_stream(p, num)`, `pdf_pypdf(data)`, `pdf_text(data)`,
`onenote_files(data)`, `lnk(data)`, `iso(data)`, `fat(img)`, `disk_image(img)`, `vhd(data)`, `scripts(text)`,
`handoff(doc)`, `yara_scan(data, derived(doc))`, `decrypt_office(data)`, `sandbox_run("olevba", data, name)`.

## Question shapes it answers

The field is read from the end of the answer id, then from the question's words. The document is the one the
question names, else the only one in the delivery that has the field (or all that have it agree).

| Asked | Field | Answer |
| --- | --- | --- |
| how many modules / streams / pages / objects / sheets / files / scripts | `*_count` | plain under an `integer` answer when it is above zero, every definition gives the same number (procedures: all, subs, functions; sheets: all, worksheets, visible; PDF objects: parsed, `obj` keywords, xref size) and neither the question nor its answer id has a qualifier (`visible-sheet-count`, `exe-file-count`); else unsure, one option per definition. A PDF that was not read whole answers no count |
| SHA-256 / MD5 / SHA-1 of the embedded payload | `embedded_sha256` ... | a candidate with one option (`payload`) when the document has exactly one payload; `None` for two |
| which procedure runs on open | `autoexec` | unsure: as written (`AutoOpen`), then lowercase |
| the URL / domain / IP / remote template / DDE command | `urls`, `domains`, `ipv4`, `remote_template`, `dde` | unsure `raw` for exactly one value; `None` for several unless the question asks for all |
| the command, the decoded string | `shell_command`, `decoded_strings` | unsure `raw` |
| author, last saved by, title, company, template, application, producer, creator | same names | unsure `raw` |
| created / modified / accessed / last printed | `created` ... | unsure in order: the text as stored, `iso_z`, `iso_space`, `iso_offset`, `iso_naive`, `date`, `epoch`; plain when the answer_format's pattern lets one through and the time is UTC in the file (a FILETIME, a `Z`). A PDF date with an offset or with none also offers its wall clock (`wall_iso_z`, ...) and stays unsure |
| does it contain macros / JavaScript, is it encrypted | `has_macros`, `has_javascript`, `encrypted` | a positive is plain when the question lists its options (`yes`/`no`); a negative, a verdict (`suspicious`) and an ATT&CK id that matches a listed option are offered unsure under `<key>.enum`; else unsure `true`, `yes`, `True`, `1`. A VBA project with no source read leaves `has_macros` unknown |
| what is this file | `kind` | the one listed option that fits, else unsure labels |
| ATT&CK technique (not in a Script Analysis set) | `attack` | unsure ids of the mechanism in the bytes |
| LNK target, arguments, working directory, icon, machine id, MAC, volume serial, show command | same names | unsure; MAC and serial in their usual forms |
| volume label, file names, hidden or deleted files, module / stream / sheet names | lists | unsure joins: `comma`, `comma_space`, `json`, `space`, `semicolon`, `pipe`, then sorted |

Always `None`: a question another engine owns (`Determine <property> for <file>`, a set with `-role`/`-steps`/
`-adapter`/`-campaign` ids, `dNN_` ids, `message`, `ANS-`); the hash or size of the delivered file itself (that
is `solvers/common/triage.py`'s); two documents that disagree; an encrypted or damaged document (a damaged one
answers only what its magic bytes say).

## Label keys and likely vocabularies

Keys are `maldoc.<field>/<kind>` (`maldoc.autoexec/ole_word`, `maldoc.attack/ole_word.vba`,
`maldoc.created/ooxml_word.time`, `maldoc.urls/pdf.list`). An accepted name answers every later id of its key
plain. Spellings offered, best first (event style: lowercase snake_case, descriptive):

- kind: `ole_word`, `doc`, `word_97_2003` / `ooxml_word`, `docx`, `docm` / `ole_excel`, `xls` / `rtf`, `rich_text` / `pdf` /
  `onenote`, `one` / `lnk`, `shortcut`, `windows_shortcut`, `shell_link` / `iso`, `iso9660`, `disk_image` / `vhd` / `hta`, `html_application`
- macro type: `vba`, `vba_macro` / `xlm`, `excel4`, `excel_4_0`, `xlm_macro`
- obfuscation: `chr_concat`, `str_reverse`, `replace`, `substring`, `array_join`, `string_concat`, `base64`, `hex`, `powershell_encoded_command`
- exploit: `cve_2017_11882`, `CVE-2017-11882`, `equation_editor`
- PDF open action: `javascript`, `launch`, `uri`, `goto`
- show command: `SW_SHOWMINNOACTIVE`, `minimized`, `7`; drive type: `fixed`, `DRIVE_FIXED`, `3`
- ATT&CK by mechanism: VBA `T1059.005`, `T1204.002`, `T1566.001`, `T1137`; XLM `T1204.002`, `T1059`; remote template `T1221`;
  DDE `T1559.002`; Equation Editor `T1203`; PDF JavaScript `T1059.007`; LNK `T1204.002`, `T1547.009` (with `T1059.001`, `T1059.003`
  or `T1218.005` first when the arguments name that interpreter); ISO/VHD `T1553.005`; HTA `T1218.005`; OneNote `T1204.002`

If the correct spelling is not among the offered ones, reason to the one value from the bytes and submit it once
via `ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`); the list in `_KIND_LABELS` or `_options`
can be extended.

## Limits to remember

- `labels.py` does not list the `maldoc` prefix yet: the module registers it in its own process.
- YARA hits (`maldoc_rules.yar`) are hints for the reader, never answers.

## Real artifacts (2026-10-08): what real documents changed

Tested on 44 real files (`tests/real/test_real_maldoc.py`; sources in `docs/toolkits/real-data.md`): oletools'
own test documents, pypdf's sample PDFs, LnkParse3's shortcuts. Compared with olevba, msodde, oleobj and rtfobj
in the sandbox, with pdfminer.six and with LnkParse3.

- **PowerPoint 97-2003.** The VBA project and embedded objects are compressed storages inside the
  `PowerPoint Document` stream (`ppt_storages`); they are children now. Before, a .ppt with a macro read
  `has_macros: False`.
- **A wrapper's content speaks for the document.** A package decrypted with Excel's built-in password, a storage
  inside a PowerPoint stream, the ActiveMime block of a 2003 XML document: macros found there make the
  document's `has_macros` true (with a note saying where). In `explain`, the parent's fields answer for both,
  except behind an encrypted package, where the decrypted child answers everything but `encrypted`, `kind` and
  the stream fields. An unreadable (password-protected) PDF still answers `encrypted` and `kind`.
- **DDE beyond Word fields**: a workbook's `xl/externalLinks` (`ddeService`, `ddeTopic`), a CSV cell
  (`=cmd|'/c calc.exe'!A0`, kind `csv_dde`), SpreadsheetML and WordprocessingML 2003 (kind `xml2003`, shown as
  `xml_excel_2003` / `xml_word_2003`), in msodde's own spelling (`dde_formulas`).
- **SYLK** (`ID;P...`, kind `slk`): cell expressions and names; an `Auto_Open` name makes it an Excel 4 macro.
- Shortcuts as the shell reads them (the same three fixes as in `windows.md`), with `padded` set and a note.
- The hash asked of an embedded file the question names is that payload's own bytes, not the storage around
  it; a name this file gave a payload (`ExternalOleObjectStg1`, `decrypted_package`, `object1.bin`) is never an
  embedded file's name; "the class name of the embedded object" is the object's class.
- The command opens a plain zip around a document, and an encrypted one with `infected` or a stored password
  (`solvers/common/archive_passwords.py`); a member nothing opens is a NOTE. Nothing is guessed.

Still not read: xlsb binary parts (`has_macros` is absent, not false), VBA p-code without source, a document
whose password is not known. Timing: every file parses and reports in under 0.1 s.

### Review of the real-artifact work (2026-10-08, `tests/real/test_review_a.py`)

- **A negated yes/no question is not answered.** "Does the document NOT contain macros? (yes or no)" was answered
  `yes`, plain, for a document with macros: the listed option that names the fact is the wrong one there.
- **Any question that negates or excludes is never plain** (`_negates`: "how many pages does the PDF not have"
  answered the page count). "Do not include the 0x prefix" is a format instruction, not a negation.
- **PowerPoint storages have one budget.** `ppt_storages` inflates at most 16 different storages and 64 MB in all
  (`PPT_INFLATE_MAX`); a built 4 MB .ppt with 64 storages of 64 MB each took 5 GB and 17 s before.
- **Word 97-2003 encryption.** `FibBase.fEncrypted` makes `encrypted` true (oletools' own `encrypted.doc` read as
  not encrypted), and nothing is then said about the text or the macros.
- **`csv_dde` by the bytes is narrower.** A text file is a DDE spreadsheet only when a formula's service is a
  program (cmd, MSEXCEL, rundll32, a path ending in .exe) or its topic is in single quotes. A Markdown list line
  (`- item | other !note`), a shell pipe and a batch line with `!var!` were read as one, with `item other`
  offered as the DDE command.
