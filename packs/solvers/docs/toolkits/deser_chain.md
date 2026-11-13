# Toolkit `deser_chain`: Java / PHP / .NET deserialization gadget-chain detection

Built for the **encoding+network+serial** coverage gap (wave121), the sibling of
[`wire_decode`](wire_decode.md) and [`asn1_reader`](asn1_reader.md). A captured insecure-deserialization
payload (a Java `.ser` blob or a `rO0`/`AC ED` cookie, a PHP `serialize()` string or a phar file, a .NET
`BinaryFormatter`/NRBF stream) was uncoverable: `java_deser.py` *builds* Java payloads for the live web
engine but nothing **reads** a serialized stream's structure as never-wrong facts, and PHP and .NET had zero
coverage. This decodes the **structure** of a serialized object graph **without deserializing it** — it
never runs `pickle.loads`, `yaml.load`, PHP `unserialize`, a Java `readObject`, a .NET
`BinaryFormatter.Deserialize` or any constructor. Offline, standard library only.

## Run first

```bash
.venv/bin/python solvers/toolkits/deser_chain.py <file>...          # structure + gadget-family hint per file
.venv/bin/python solvers/toolkits/deser_chain.py <file> --json      # as JSON
```

As a solver: `solvers/toolkits/deser_chain.py` has `solve_set` and `signals(questions, files)` (0..1,
0.0 when nothing serialized is recognised) for running the whole file set at once.

By hand, from Python:

```python
sys.path.insert(0, "solvers/toolkits"); import deser_chain as T
T.classify(data)        # {"format": "java"|"php"|"dotnet", ...} or None (+ gadget_families, outer_encoding)
T.parse_java(data)      # {classes, serial_uids, object_count, root_class, strings, complete}
T.parse_php(data)       # {objects, classes, object_count, root, max_depth, complete}
T.parse_phar(data)      # a phar's manifest global-metadata serialize blob, parsed as PHP
T.parse_dotnet(data)    # {types, libraries, record_count, root_type, complete}  (MS-NRBF)
T.gadget_families(rep)  # [(hypothesis_name, label)] the class/type names suggest (UNSURE only)
T.leads_from(rep)       # command/url/flag-shaped strings a payload carries, as findings (never submitted)
```

## What it reads

| Format | Detected by | Structural facts |
| --- | --- | --- |
| java | magic `AC ED 00 05` (a whole-file base64 layer is peeled) | a bounded grammar walk (TC_OBJECT / TC_CLASSDESC / TC_ARRAY / TC_STRING / handles / block data / super-class chains): the class-descriptor names, each class's serialVersionUID, the top-level object's class, the object/string counts |
| php | a strict whole-buffer `serialize()` parse (`O:`/`C:`/`a:`/`s:`/`i:`/`d:`/`b:`/`N;`/`E:`), byte-exact lengths | object class names, the root object's property names and count, nesting depth, object count; a phar file (`__HALT_COMPILER();`) has its manifest global-metadata blob parsed the same way (the `phar://` deserialization vector) |
| dotnet | magic `00 01 00 00 00 … 01 00 00 00 00 00 00 00` (NRBF `SerializationHeaderRecord`, major 1 minor 0) | a best-effort record walk: the class type names (`ClassWithMembersAndTypes`), the `BinaryLibrary` assembly strings, the root type, the record count |

Verified against the eight real ysoserial payloads embedded in `java_templates.json` (every one parses to
completion: CommonsCollections1–7, CommonsBeanutils1, URLDNS) and hand-built PHP / phar / NRBF fixtures
(`tests/test_deser_chain.py`).

**Python pickle is deliberately left to [`ai_model_files`](ai_model_files.md)**, which already does a
symbolic pickle opcode walk (never unpickled). `deser_chain.signals()` returns 0 for a pickle, so it never
competes there; the CLI still names a pickle it sees and points at `ai_model_files`.

A buffer that does not parse cleanly is **`None`** for every count. For Java and .NET the walk is
fail-closed: on any byte it does not understand it stops, keeps the names collected so far (as **unsure
candidates only**), and reports `complete: false` so no count is trusted. Bounded: 16 MiB file, ≤200000
nodes, ≤200 deep.

## Never-guess

- **Structural COUNTS** (how many classes / objects / records / properties) read from a **fully-parsed**
  stream (`complete: true`) are deterministic, so they are **high-confidence**: returned as
  `labels.pick(key, renderings)` (`decimal`/`hex`), a ranked list you read and reason to one value. An
  incomplete parse gives **no count**.
- **Class / type names** and the **gadget-chain family** are the author's vocabulary, so they are
  **candidates** (`labels.candidates`) — leads to read, never a decided value, and each candidate key is
  attempt-scoped. The family hint (`commons_collections`,
  `object_data_provider`, `monolog_rce`, …) means "classes consistent with this gadget are referenced", a
  lead, not a judged fact.
- The serialization **format/language** is byte-proven but its label is the author's, so it is a candidate
  pick of spellings (`java` / `java_serialization` / …), never a bare `name==value` pick.
- A **command, URL, or flag-shaped string** a payload carries is a **lead** (`leads_from`), reported for the
  player, never an answer and never submitted. A string that addresses the reader is still just a lead. The
  flag is always `None`.

Keys are `deser_chain.<field>/<shape>` (`deser_chain.gadget_family/java`, `deser_chain.class_count/java`,
`deser_chain.root_class/php`, `deser_chain.library/dotnet`).

## Never-execute

This toolkit is a **detection** reader. It deserializes nothing and runs nothing a blob contains; building and
firing a gadget at a live target stays the player-gated hand tools (`java_deser.py`, `web_exploit.py`). Every
name/family it emits is a candidate and every count needs a clean parse, so it only ever yields a reasoned
structural fact — never a guess.
