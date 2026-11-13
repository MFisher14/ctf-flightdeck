# Toolkit `sqlite_timetravel`: a SQLite database as of each commit in its WAL

Module: `solvers/toolkits/sqlite_timetravel.py` (standard library only; B-075). The page and WAL-frame
parser underneath is `sqlite_artifacts.Pages`, which now lists the commits (`commits()`) and builds the
page image at any commit (`image_at(k)`, `size_at(k)`, `image_bytes(k)`). Tests:
`tests/test_toolkits_sqlite_timetravel.py` (fixtures: `tests/sqlite_wal_fixtures.py`).

## Run this first

```bash
tools/ctfpy solvers/toolkits/sqlite_timetravel.py app.db                       # the timeline (app.db-wal beside it)
tools/ctfpy solvers/toolkits/sqlite_timetravel.py app.db --when jobs.status=COMPLETED --where job_id=LR-7
tools/ctfpy solvers/toolkits/sqlite_timetravel.py app.db --profile export-profile.md --block 1 --at when --variants
tools/ctfpy solvers/toolkits/sqlite_timetravel.py app.db --image 3 /tmp/at3.db  # the database file as of commit 3
python -m ctf run toolkits.sqlite_timetravel <challenge_dir> --opt when=jobs.status=COMPLETED
```

Intake runs it with no model on every challenge whose files hold a WAL (either byte order of the WAL
magic): the timeline, decoded cells, and every fenced SELECT in the handout's text files run as of each
commit.

## What it gives

- **Commit list**: the committed transactions among the valid frames (header salts, unbroken checksum
  chain), each with its frames, the pages it wrote and the database size after it. Valid frames after the
  last commit frame are counted as uncommitted, never shown as a commit.
- **Snapshots**: commit 0 is the main file alone, commit k the main file under the valid frames up to
  commit k. `--at` takes `K`, `base`, `final`, `when` (the commits `--when` found), `all`, or `sN`.
- **Stale commits** (`s1`, `s2`, ...): frames of an earlier WAL cycle that a restarted WAL has not
  overwritten yet. Each is the main file as it is now under that cycle's frames: APPROXIMATE, and the
  report says so.
- **Checkpoints**: a page of the main file that holds the bytes of one of its own WAL frames was copied
  in by a checkpoint, so commits from before that frame show a later version of it. With the `-shm`
  beside the WAL, only frames below its backfill count are taken as copied. Those snapshots are marked
  APPROXIMATE.
- **Per-commit table diff**: rows added, removed and changed (typed: 1, 1.0 and '1' differ); a WITHOUT
  ROWID table is keyed by its primary key.
- **State transitions**: `--when TABLE.COLUMN=VALUE [--where COLUMN=VALUE]...` gives the commit where a
  row enters that state (`base` when the main file already has it) and where it leaves it.
  `--find VALUE` lists every cell that becomes VALUE.
- **BLOB cells**: every cell of every snapshot, and the rows sqlite_artifacts recovers from frames, the
  freelist and unallocated space, is inflated when compressed (zlib, gzip, bz2, xz), read as text (UTF-8
  or UTF-16) and fed to `embedded_decode` (base64, base32, hex). A TEXT cell is scanned only for runs that
  decode to a flag. A flag in the event format makes the result a `candidate`.

## The SELECT

`--sql`, or the fenced blocks of a handout profile (`--profile FILE`, `--block N`; engine opt
`sql_file`, because `profile` is the event profile argument): tagged `sql`, `sqlite` or `sqlite3`, or
untagged and starting with SELECT or WITH. The handout text is data: only a SELECT is ever taken from it,
and a tagged block that is not one is reported as not run.

It runs on an in-memory copy (`sqlite3.deserialize`) of the snapshot, never on the file:

- one statement, starting with SELECT, WITH or VALUES;
- an authorizer that allows reads only: it denies ATTACH, every write and DDL, transactions, PRAGMA
  writes (read pragmas such as `table_info` are allowed) and the functions `load_extension`,
  `fts3_tokenizer`, `readfile`, `writefile`, `edit`;
- extension loading off, `query_only`, `SQLITE_DBCONFIG_DEFENSIVE`, untrusted schema, no attached
  databases;
- a progress handler that stops it after its budget of CPU seconds (5 by default);
- more than 200000 result rows is an error, never a cut result.

`--csv NAME=FILE` loads a CSV as a temp table to join with. The result is rendered as TSV or CSV
(`--format`, `--header`, `--crlf`, `--no-trailing-newline`, `--null`) and hashed with SHA-256;
`--variants` lists the digest of all sixteen common renderings. Which rendering a handout means is the
reader's call: the tool never guesses it. `--out FILE` writes one result.

## Limits

A database or WAL over 256 MiB, or a handout text over 1 MiB, is not read (named in the report). Tables
are read up to 20000 rows per snapshot (marked when cut). The whole timeline has a 15 CPU-second budget
(`--budget`); when it runs out the report says INCOMPLETE and where it stopped.

## API (B-085 imports it)

`TimeTravel(data, wal, shm=None)` with `.commits`, `.snapshots`, `.stale`, `.uncommitted`,
`.checkpointed`, `.timeline()`, `.transitions()`, `.find_value()`, `.cells()`, `.query()`;
`Snapshot.image()`, `Snapshot.tables()`; `run_select()`, `ReadOnly`, `sql_blocks()`, `render()`,
`variants()`, `decode_cell()`, `cell_findings()`, `find_pairs()`, `shm_backfill()`.
