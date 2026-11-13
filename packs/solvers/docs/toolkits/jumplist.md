# `jumplist` — Windows Jump Lists

Built for wave121/forensics-next (forensics/dfir coverage gap, the cheap fast-follow after ESE). Reads the
two Jump List containers and hands every embedded shell link to the `windows.lnk()` parser, so it
adds only the containers, never a second LNK decoder.

```
.venv/bin/python solvers/toolkits/jumplist.py <file>...          a per-entry triage of each Jump List
.venv/bin/python solvers/toolkits/jumplist.py --json <file>...   the same as JSON
```

Offline, static, stdlib only: no network request, no token, nothing written, nothing executed. The CLI
is RECON only.

## What it reads

- **`*.automaticDestinations-ms`** — an OLE Compound File (CFB). A bounded, tree-agnostic CFB walk
  (`_cfb_streams`) reads the `DestList` metadata stream and every numbered stream. Each numbered stream is a
  shell link, parsed by `windows.lnk()` (target path, creation/access/write times, volume serial, drive type,
  volume label, tracker machine id and MAC). `DestList` gives the **MRU order**, and per entry the hostname,
  recorded access time and pin state. `DestList` facts are attached only on a **self-validating** parse: the
  header version is 1/3/4, the walk consumes the body and parses exactly the header's entry count, and every
  entry number maps to an existing numbered stream (the set matches). Any inconsistency sets `destlist_ok`
  false and the MRU falls back to `None` — the numbered streams still answer.
- **`*.customDestinations-ms`** — not a CFB. A header and category blocks hold a run of shell links. The
  reader **carves** each LNK by its 20-byte header (size `0x4C` + the fixed LNK CLSID) and parses it with
  `windows.lnk()`. Custom-destinations carry no reliable MRU, so entries are in file order and MRU questions
  are `None`.
- **AppID** — the hex stem of the file name (`1a2b…​.automaticDestinations-ms`), a known-but-unjudged label.

`parse(data, name)` returns `{kind, app_id, stream_count, destlist_ok, mru, entries:[{id|offset, lnk,
destlist}]}`. `classify(data, name)` validates the container from the real bytes only (a CFB with a numbered
LNK stream, or a `.customDestinations-ms` / multi-LNK blob) and returns `None` otherwise, so a bare `.lnk` is
left to the shortcuts reader and a zip/anything else never matches.

## Never-wrong

No Jump List value is a fixed label, so **no answer here is treated as certain**. `solve_set` returns, per question:

- a `labels.pick` whose option names are **formats** (`raw`, `lower`, `basename`, `hex`, `iso_z`, `colon_lower`…)
  for a text/number/time fact, or
- a `labels.candidates` whose names are **hypotheses** (`streams`, `destlist_entries`, `pinned`, `drive_type`,
  `appid`…) for a value the bytes narrow but whose exact reading is not fixed, or
- `None`.

Every option's VALUE is re-derived from **this variant's bytes**; no option is a bare `name == value` label,
and every key is per-question scoped (`windows.jumplist_<field>/<shape>@<answer id>`). So an accepted name
never answers a different question or a different variant plain — it only re-derives the fact. A flag, a
question the toolkit cannot place to exactly one fact, two differing readings, and anything on an incomplete
DestList are `None`. `signals()` is `0.0` unless a real Jump List container validates in the bytes, so the
toolkit triggers on nothing else. Key prefix: `windows`.
