# schema_bundle: field-level decoders over schemas you supply

`solvers/toolkits/schema_bundle.py` (engine `toolkits.schema_bundle`, B-159) decodes the message
bodies the sector engines leave opaque, against the real schema:

| body | header engine that stops short | decoder here |
|---|---|---|
| ISO 15118-2 / DIN 70121 / ISO 15118-20 EXI | `sec_evcharge_v2g` (EXI header, body opaque) | schema-informed EXI from the XSD (`_schema_exi.py`) |
| ETSI ITS Release 2 CAM / DENM (UPER) | `sec_v2x_etsi` (Release-2 header inventory) | pycrate, compiling the bundle's ASN.1 modules at run time: built, but blocked on the real modules (below) |
| MMS PDUs (BER) | `ot_mms_services` (services 0..77, no schema) | pycrate over the bundle's MMS module |
| VMF K-series bodies | `sec_tdl_link22` (application-header prefix) | dictionary-driven bit reader (`_schema_bits.py`) |
| PROFINET IO | `ics_app_depth`, `network_ics_depth` | none: there is no schema file to load |

No schema is in this repository. They are read from the **schema bundle**, a folder outside the
repo: the `schema-bundle` asset of `tools/assets.toml` (`$CTF_ASSET_SCHEMAS`, else
`<toolbox>/schemas`; `python -m ctf toolchain assets` shows whether it resolves). A missing bundle,
family folder, schema file or pycrate is a named failure (`BundleMissing`, `SchemaMissing`,
`ToolMissing`), and so is a schema that is there but does not load (`SchemaUnusable`); nothing falls
back to a guessed decode.

## Can each schema be obtained, and redistributed?

Settled on 2026-11-12. "Checked" means the publisher's page was read that day; "from the
standard's front matter" means it was not re-checked online.

| family | schema | where it comes from | obtainable | redistributable | decoder |
|---|---|---|---|---|---|
| `iso15118-2` | ISO 15118-2:2014 XSDs (`V2G_CI_AppProtocol.xsd`, `V2G_CI_MsgDef.xsd`, `V2G_CI_MsgHeader.xsd`, `V2G_CI_MsgBody.xsd`, `V2G_CI_MsgDataTypes.xsd`, `xmldsig-core-schema.xsd`) | ISO's electronic inserts, `standards.iso.org/iso/15118/-2/ed-2/en/` (checked: the six files are listed) | free | no | built |
| `din70121` | DIN SPEC 70121:2014 XSDs (same file names) | delivered with the purchased specification (from the standard's front matter) | paid | no | built |
| `iso15118-20` | ISO 15118-20:2022 XSDs (`V2G_CI_AppProtocol.xsd`, `V2G_CI_CommonMessages.xsd`, `V2G_CI_CommonTypes.xsd`, `V2G_CI_AC.xsd`, `V2G_CI_DC.xsd`, `V2G_CI_WPT.xsd`, `V2G_CI_ACDP.xsd`, `xmldsig-core-schema.xsd`) | ISO's electronic inserts, `standards.iso.org/iso/15118/-20/ed-1/en/` (checked: the eight files are listed) | free | no | built-unverified |
| `etsi-its-r2` | CAM (TS 103 900), DENM (TS 103 831) and the CDD module they import, ASN.1 | ETSI forge, `forge.etsi.org/rep/ITS/asn1/` repositories `cam_ts103900` and `denm_ts103831`, branch `release2`, and their `cdd` submodule (checked: the LICENSE is BSD 3-Clause, copyright ETSI) | free | yes | blocked |
| `mms` | the ISO 9506-2 MMS ASN.1 module | the purchased ISO standard; transcriptions exist inside GPL projects (from the standard's front matter) | paid | no | built-unverified |
| `vmf-k` | MIL-STD-6017 K-series message tables | the standard's controlling office; limited distribution, no public copy | restricted | no | built |
| `pnio` | PROFINET IO (IEC 61158-6-10) block dictionary | the purchased IEC standard or PI membership | paid | no | none |

What the answers mean for this repo:

- **ISO 15118-2 and -20.** The inserts are free to download, but downloading is accepting the ISO
  Customer Licence Agreement, and the site permits use "in their original format" for the standard's
  purposes. That is a licence a person accepts, and it grants no redistribution: the files are not
  vendored and a build agent does not fetch them. A human downloads them into the bundle.
- **DIN 70121, MMS, PROFINET.** Paid standards. Not vendored. The MMS module also circulates as
  transcriptions inside GPL-licensed projects; a transcription carries that project's licence, so
  it is not copied into this repo either.
- **ETSI ITS Release 2.** BSD 3-Clause with ETSI as the copyright holder: it may be redistributed
  with the notice and licence text kept. It is still loaded from the bundle rather than vendored,
  because vendoring means choosing and pinning one revision of three repositories. **The decoder is
  blocked on the compiler, not the licence:** the real modules were tried once (2026-11-12, branch
  `release2`, CDD submodule commit `15bcccb0`, read into a scratch folder, not kept) and pycrate
  0.8.1 does not compile the CDD module. It stops at `BasicLaneInformation: invalid value reference
  for SEQUENCE, (WITH COMPONENTS {..., connectingLane PRESENT})`; with every `WITH COMPONENTS`
  constraint taken out by hand it stops later, in its own constraint verification, with
  `TypeError: '<' not supported between instances of 'ASN1RangeInt' and 'int'`. So real CAM and
  DENM Release 2 PDUs do not decode yet. The decode path (family lookup, compile, UPER decode,
  re-encode check, field list) is built and tested on synthetic modules that pycrate compiles. The
  next step is another compiler for this family; `asn1tools` (MIT, pure Python, its two
  dependencies are already pinned here) is the candidate and was not tried.
- **VMF K-series.** The standard cannot be obtained publicly, so no message table can be written
  here. The interpreter is built; the tables are dictionaries that someone who holds the standard
  transcribes (format below).
- **PROFINET IO.** There is no machine-readable wire schema (GSDML describes devices, not PDUs), so
  there is nothing to load. The block decoders in `ics_app_depth` and `network_ics_depth` stay the
  path.

## Bundle layout

```
<bundle>/iso15118-2/    the six XSD files, as downloaded
<bundle>/din70121/      V2G_CI_AppProtocol.xsd, V2G_CI_MsgDef.xsd and the files they import
<bundle>/iso15118-20/   the eight XSD files, as downloaded
<bundle>/etsi-its-r2/   every .asn file of the CAM, DENM and CDD repositories, flat
<bundle>/mms/           the .asn file(s) defining MMSpdu
<bundle>/vmf-k/         one <message>.json dictionary per transcribed message
```

`tools/ctfpy solvers/toolkits/schema_bundle.py status` prints, per family, whether it is present,
which files were found, and the record above.

## Use

```sh
tools/ctfpy solvers/toolkits/schema_bundle.py status
tools/ctfpy solvers/toolkits/schema_bundle.py exi frame.bin --family iso15118-2          # V2GTP frames or a bare EXI body
tools/ctfpy solvers/toolkits/schema_bundle.py exi body.exi --family din70121 --document message
tools/ctfpy solvers/toolkits/schema_bundle.py exi body.exi --xsd challenge.xsd           # any XSD + EXI pair
tools/ctfpy solvers/toolkits/schema_bundle.py asn1 cam.uper --family etsi-its-r2 --pdu cam
tools/ctfpy solvers/toolkits/schema_bundle.py asn1 pdu.ber --asn a.asn b.asn --pdu Module.Type --codec ber
tools/ctfpy solvers/toolkits/schema_bundle.py bits body.bin --family vmf-k --message K05.1
python -m ctf run toolkits.schema_bundle <challenge_dir> [--opt family=iso15118-2]
```

Input files may hold bytes or one blob of hex text. The output is JSON: the decoded tree and a flat
`fields` list of `{path, value}`. `ctf run` (the contract entry `solve`) walks the challenge files,
decodes every V2GTP frame, bare EXI stream and ITS Release-2 CAM/DENM PDU it finds, and looks for
the event's flag format in the decoded fields (strings, and binary fields read as text):
`solved` with the field as evidence, `unsure` when fields decoded without a flag, `blocked` naming
the missing family and where it comes from (or the schema that does not load), `none` when no file
is such a payload. A file recognised only by its first header byte (a bare 0x80 EXI header, an ITS
02 01 / 02 02 header) is a guess, and a `blocked` note says so for that file by name. When some
payloads decode and others need a schema the bundle lacks, the `solved` or `unsure` note still names
the files that could not be tried and why.

## What the EXI decoder covers

The profile ISO 15118-2 and DIN 70121 use: bit-packed, schema-informed, strict = false, no options
document in the header, schema-valid content. It builds the grammars from the XSD (document grammar
over the sorted global elements, attribute uses, sequence / choice / all, occurrence ranges,
substitution groups, extension and restriction, simple content, wildcards for their event-code
width) and decodes strings (with the string tables), enumerations, booleans, bounded and unbounded
integers, decimals, floats, binary and lists.

Named failures instead of guesses: an EXI options header, a strict = false deviation (second-level
event code: `xsi:type`, `xsi:nil`, undeclared content), a wildcard element or attribute actually
present in the stream, an EXI Date-Time value, a string type with pattern facets (restricted
character set), `xs:redefine`. Bits left after the document that are not zero padding are an error,
which is also what tells two schemas apart: a stream decodes under one document of a family.

Verified against: the two public ISO 15118 application-handshake vectors (decoded against a schema
of the same structure written in the test) and hand-derived streams for every construct. Not
verified against the real ISO or DIN files here, because none were available to the build: the
tests that do that run only when the bundle holds the family and are reported as not run otherwise.
ISO 15118-20 has no known-answer vector at all and is marked `built-unverified`.

## What the ASN.1 path covers

pycrate compiles the family's `.asn` files once per process and decodes UPER (CAM, DENM) or BER
(MMS). A UPER, APER, DER or OER PDU must re-encode to the same bytes, so a wrong type, a wrong
schema or a non-canonical encoding is refused rather than half-decoded. BER has no canonical form
and gets no such check: pycrate's BER decoder also skips a component the type does not declare, so a
BER PDU read as the wrong SEQUENCE type can decode partially. Modules pycrate cannot compile are a `SchemaUnusable` failure naming its error
(today that includes the real ETSI Release 2 CDD, see above); the MMS path has not been tried on
the real ISO 9506-2 module. `--asn` compiles files you name: the generated Python is imported, so name only
modules you trust. The CLI warns on every `--asn` run and refuses a module that lies under the work
base, the current work folder (`$CTF_WORKDIR` moves it), the real-data corpus, the saved challenges or
the rehearsal corpus: that file is challenge-supplied. Review it and copy it out first if you trust
it. When `$CTF_REAL_CHALLENGES` or `$CTF_REHEARSAL_CORPUS` is set to something that is not a folder,
`--asn` stops before compiling, naming the variable ("--asn guard cannot check ..."): fix or unset it. `solve` never compiles a challenge's own files. The compiled modules carry the
ETSI module names; they do not replace the Release-1 modules `sec_v2x_etsi` uses from pycrate.

## Writing a VMF K-series dictionary

```json
{"message": "K05.1", "edition": "the edition you transcribed from",
 "fields": [
   {"name": "Originator", "bits": 24},
   {"name": "Speed", "bits": 11, "presence": true, "codes": {"2047": "no statement"}},
   {"name": "Remark", "type": "text7", "max_chars": 20, "presence": true},
   {"name": "Waypoint", "presence": true, "repeat": 4, "fields": [
      {"name": "Latitude", "bits": 25}, {"name": "Longitude", "bits": 26}]}]}
```

`presence: true` puts an FPI (field) or GPI (group) bit first; `repeat: N` puts an FRI or GRI bit
before each occurrence (1 = another follows), at most N; `text7` is 7-bit characters ended by 0x7F
or `max_chars`. Bits are read the way `sec_tdl_link22` reads the VMF header: least significant bit
of each octet first, a field's first bit its least significant (`"bit_order": "msb0"` flips that
for other formats). Every key is checked; an unknown one is an error. The dictionaries are yours:
they hold transcribed content of a restricted standard and stay in the bundle.
