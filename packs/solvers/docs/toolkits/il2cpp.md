# Toolkit `il2cpp`: Unity IL2CPP `global-metadata.dat` reader

Built 2026-10-23 (reversing / mobile insurance). A hedge for a reversed Unity game or app where the managed C#
logic is AOT-compiled to native code and the only recoverable source-level facts live in the metadata blob.
Offline, static, standard library only. Nothing is executed and no byte of a delivery is ever run.

## Run first

```bash
.venv/bin/python solvers/toolkits/il2cpp.py <global-metadata.dat>... [--json]   # RECON ONLY; names unsure, flag None
```

As a solver: `signals()` / `solve_set()` are the runner contract; `solve_set` returns ranked candidate
values (`labels.show(...)`). Reason to the flag from them and submit it once via
`ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`).

## What it recovers (and nothing more)

It parses the header (magic `0xFAB11BAF`), the string-literal table and its data blob, the identifier string
heap, and the type/method/field definition tables:

- the embedded string **literals**, each read byte-exact at its `(dataIndex, length)`;
- the **identifier names** of the type / method / field definition tables, read null-terminated from the string
  heap at each definition's `nameIndex`.

A paired `libil2cpp.so` / `GameAssembly.dll` binary shipped beside the metadata is **noted** (its format) but no
code or address is read from it: every source-level fact comes from the metadata.

## Never-guess

A string **literal** is a deterministic byte-exact read at a fixed `(offset, length)`: plain when it decodes
cleanly as UTF-8, else `labels.candidates` of its renderings (utf-8 / latin-1 / hex). The metadata **version**
and the string-literal table **count** are deterministic byte-exact reads → plain-eligible. A method/field/type
definition **count** is NOT byte-exact (name-count undercounts, the raw table-entry count depends on the
version-inferred stride), so it is always unsure: `labels.candidates(key, [("table_entries", …), ("names_read", …)])`.
A type/method/field **name** is an author-chosen label (spelling + namespace unjudged), always unsure. An
unsupported version, inconsistent offsets, or a truncated heap/blob → `None`. Answers go under the `binary.il2cpp_*`
key family (the `binary` prefix, every name an unsure candidate, never plain); the flag is `None`.
