# Toolkit `linefilter`: odd-line-out / Extraction helper

Module: `solvers/toolkits/linefilter.py` (standard library only). Tests: `tests/test_linefilter.py`.
Playbook: `docs/playbooks/linux.md`.

For the CSCTF 2024 **Extraction 1/2** archetype — the flag is the one line that does not fit.

```bash
.venv/bin/python solvers/toolkits/linefilter.py data.txt                         # auto odd-one-out
.venv/bin/python solvers/toolkits/linefilter.py -v '^[a-fA-F0-9]{32}$' data.txt  # grep -Ev (non-MD5 line)
.venv/bin/python solvers/toolkits/linefilter.py -g '^[A-Z]{4}[a-z]{6}…$' data.txt # grep -E (keep matching)
```

Key functions: `not_matching(lines, pattern)` (`grep -Ev`), `matching(lines, pattern)` (`grep -E`),
`odd_one_out(lines)` → `(odd_lines, common_shape)` (each line reduced to a character-class **shape**;
the minority is the odd one — "find the non-MD5 line" with no regex given), `shape(line)`,
`flag_lines(lines)`, `flags(lines)`.
