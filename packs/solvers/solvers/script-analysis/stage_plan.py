#!/usr/bin/env python3
"""The literals of a typed handoff plan, offered UNSURE (built 2026-10-13 for Day 14).

`invoke-python-stage.ps1` has been in every Script Analysis delivery since Day 5 and no question has named
it. It is no specimen of any component: it stores no encoded plan, only plain assignments

    $HandoffId = 'PSPY-E1DA846A13011150'
    $NextStage = 'pyarmor-pyinstaller-recovered.py'
    $ExecutionPlan = [pscustomobject]@{ Adapter = 'Start-Process'; Interpreter = $Interpreter; Executed = $false }

and every reader of the lane answers None for it. If a day asks about it, `answers()` offers, for an id that
nothing else answered, the ONE literal whose name is the field the id asks (`...-handoff-id` and `$HandoffId`,
`...-adapter` and the `Adapter =` entry; a reference to a variable is followed once), as
`labels.pick('script.<field>/<ext>.stage_plan', [('as_written', value)])`: unsure, one option, a probe on the
untimed base. Nothing of it was ever judged, so nothing here is plain.

It answers nothing when the file holds an encoded plan or a tagged descriptor (those have their readers), when
the id's field matches no name or two names with different values, and for the fields a name cannot answer
(role, attack, steps, a campaign the file does not name). A `$true`/`$false` is offered lower case first."""
import re
import sys

try:
    import labels
except Exception:  # noqa: BLE001
    labels = None

EXTS = (".ps1", ".psm1", ".psd1")
MAX_BYTES = 64 * 1024
ASSIGN = re.compile(r"(?m)^[ \t]*\$([A-Za-z_]\w*)[ \t]*=[ \t]*(?:'([^'\r\n]*)'|\"([^\"$`\r\n]*)\"|\$(true|false)\b)[ \t]*;?[ \t]*(?:#[^\r\n]*)?$")
ENTRY = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*(?:'([^'\r\n]*)'|\"([^\"$`\r\n]*)\"|\$(true|false)\b|\$([A-Za-z_]\w*))[ \t]*;?[ \t]*(?:#[^\r\n]*)?$")
NEVER = {"role", "attack", "steps", "stagecount", "scenario", "technique", "classification", "verdict"}


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def literals(text: str) -> dict:
    """{normalised name: set of values} of the plain assignments and hashtable entries of the file."""
    variables = {}
    for m in ASSIGN.finditer(text):
        value = m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else "$" + m.group(4).lower()
        variables.setdefault(m.group(1).lower(), set()).add(value)
    found = {}
    for name, values in variables.items():
        found.setdefault(_norm(name), set()).update(values)
    for m in ENTRY.finditer(text):
        if m.group(5) is not None:
            values = variables.get(m.group(5).lower())
            if not values:
                continue
        else:
            values = {m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else "$" + m.group(4).lower()}
        found.setdefault(_norm(m.group(1)), set()).update(values)
    return found


def answers(member: str, qs: list, got: dict, files: dict) -> dict:
    """{qid: value} for the ids of this specimen nothing else answered: labels.pick, so unsure until the judge has
    accepted a name for the key. Never raises."""
    out = {}
    try:
        if labels is None or not str(member or "").lower().endswith(EXTS):
            return out
        if not qs or any(got.get(q.get("qid")) is not None for q in qs):
            return out                       # a specimen some reader answers is that reader's
        data = files.get(member)
        if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_BYTES or b"\x00" in data[:4096]:
            return out
        text = bytes(data).decode("utf-8", "replace")
        if "HUNTRESS_ANALYSIS" in text or "descriptor_" in text or "Material_" in text or "Codec_" in text:
            return out
        found = literals(text)
        if not found:
            return out
        ext = member.rsplit(".", 1)[-1].lower()
        for q in qs:
            words = [w for w in re.split(r"[-_]", str(q.get("qid") or "").lower()) if w]
            hit = None
            for n in (3, 2, 1):              # the longest tail of the id that is a name of the file
                if len(words) > n and "".join(words[-n:]) in found:
                    hit = "".join(words[-n:])
                    break
            if hit is None or hit in NEVER or len(found[hit]) != 1:
                continue
            value = next(iter(found[hit]))
            if not value:
                continue
            options = [("lower", value[1:]), ("as_written", value)] if value in ("$true", "$false") else [("as_written", value)]
            field = "_".join(words[-n:])
            picked = labels.pick(f"script.{field}/{ext}.stage_plan", options)
            if isinstance(picked, str) and picked:     # plain only once the ledger holds an accepted name for the key
                out[q["qid"]] = picked
                print(f"[stage_plan] {q['qid']}: the file's own literal for {hit}, "
                      f"{'offered unsure' if picked.startswith('??') else 'under the name the judge accepted'}", file=sys.stderr)
    except Exception as e:  # noqa: BLE001 - a file that does not read answers nothing
        print(f"[stage_plan] {member}: {type(e).__name__}: {e}; nothing offered", file=sys.stderr)
    return out
