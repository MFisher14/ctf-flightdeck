# Toolkit `hashcrack`: john-the-ripper pipeline wrapper

Module: `solvers/toolkits/hashcrack.py` (standard library only; shells out to the installed `john` /
`*2john` / `unshadow` tools when asked to run). Tests: `tests/test_hashcrack.py`. Playbook:
`docs/playbooks/linux.md`.

For the CSCTF 2024 **Linux/John** (protected zip), **My secure password** (`/etc` shadow+passwd),
and **Hashes** archetypes. Recognises the input, emits the exact `john` commands, and — when
`john` + the extractor + a `rockyou.txt` are installed — runs the local dictionary attack.

```bash
.venv/bin/python solvers/toolkits/hashcrack.py secret.zip          # print the plan (commands)
.venv/bin/python solvers/toolkits/hashcrack.py --run secret.zip    # run locally if tools present
.venv/bin/python solvers/toolkits/hashcrack.py --run passwd shadow # unshadow + john
```

Key functions: `classify(path)`, `plan(paths)` → `Plan` (`.commands`, `.render()`),
`crack(paths, run=True)` → `Result` (`.cracked`, `.pot`), `parse_show`/`parse_pot`, `longest(cracked)`
(the *My-secure-password* answer is the longest recovered password). Tool discovery searches `$PATH`
then the john-jumbo share dirs; wordlist discovery honours `$ROCKYOU`/`$WORDLIST`.

**Not** a flag brute-force: this is offline recovery of a hash we hold, never a submission sweep at
CTFd, and it runs only the trusted cracking tools, never the challenge artifact.
