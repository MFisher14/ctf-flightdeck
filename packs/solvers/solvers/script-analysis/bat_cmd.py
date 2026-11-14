#!/usr/bin/env python3
"""cmd.exe on paper: enough of the batch interpreter to follow a specimen statically.

Nothing is executed. Commands that would touch the system (ver, findstr, the
adapters themselves) are no-ops; only variables, expansion, and control flow are
modelled, in cmd.exe's own order:

  1. percent expansion of the whole line: %%, %1 / %~1, %var%, %var:a=b%, %var:~n,m%
  2. the line is parsed into commands: unquoted & && || | separate them, a `(`
     where a command starts opens a block that ends at its `)`, redirections are
     removed and carets resolved. A block left open at the end of a line goes on
     over the next lines, as cmd.exe reads it (each line percent-expanded first).
  3. FOR substitutes its variable into the body
  4. delayed expansion (!var!) just before a command runs
  5. CALL repeats step 1 on its command, which is what turns %%var%% into a value

Cmd.assigns records every SET with how its value was produced and where it ran
(the call depth, the IFs and FORs around it, the variables it read), and
Cmd.events records the control flow the same way, so a caller can name the
expansion and control forms from what actually gated a statement.

The walk starts from the variables every Windows session has (SYSTEM_ENV), so a
guard that is always true on a real system (`if defined ComSpec`) is followed.
Their values are stand-ins for this machine's, so Cmd.system_refs maps each one
a walk expanded to the value it was given, and a caller can refuse a result
that contains one. Three budgets bound a walk: MAX_STEPS (lines run plus loop
iterations), MAX_DEPTH (nested calls) and MAX_VALUE (the length of one
variable, so a loop that doubles a string cannot eat the machine's memory);
Cmd.exhausted says one ran out.
"""
import re
from itertools import islice

MAX_STEPS = 5000         # the saved specimens take 15 to 34
MAX_DEPTH = 40
MAX_BLOCK = 120          # physical lines one parenthesised block may span
MAX_VALUE = 8191         # cmd.exe's own limit on a command line, and so on what one SET can store
EVENT_VALUES = 16        # loop values kept in a for_l / for_in event

# What `set` prints in a fresh cmd.exe on a default install. The values are typical, not this machine's.
SYSTEM_ENV = {
    "ALLUSERSPROFILE": r"C:\ProgramData",
    "APPDATA": r"C:\Users\user\AppData\Roaming",
    "CommonProgramFiles": r"C:\Program Files\Common Files",
    "CommonProgramFiles(x86)": r"C:\Program Files (x86)\Common Files",
    "CommonProgramW6432": r"C:\Program Files\Common Files",
    "COMPUTERNAME": "DESKTOP",
    "ComSpec": r"C:\Windows\system32\cmd.exe",
    "DriverData": r"C:\Windows\System32\Drivers\DriverData",
    "HOMEDRIVE": "C:",
    "HOMEPATH": r"\Users\user",
    "LOCALAPPDATA": r"C:\Users\user\AppData\Local",
    "LOGONSERVER": r"\\DESKTOP",
    "NUMBER_OF_PROCESSORS": "4",
    "OS": "Windows_NT",
    "Path": r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0" + "\\",
    "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
    "PROCESSOR_ARCHITECTURE": "AMD64",
    "PROCESSOR_IDENTIFIER": "Intel64 Family 6 Model 158 Stepping 10, GenuineIntel",
    "PROCESSOR_LEVEL": "6",
    "PROCESSOR_REVISION": "9e0a",
    "ProgramData": r"C:\ProgramData",
    "ProgramFiles": r"C:\Program Files",
    "ProgramFiles(x86)": r"C:\Program Files (x86)",
    "ProgramW6432": r"C:\Program Files",
    "PROMPT": "$P$G",
    "PSModulePath": r"C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules",
    "PUBLIC": r"C:\Users\Public",
    "SystemDrive": "C:",
    "SystemRoot": r"C:\Windows",
    "TEMP": r"C:\Users\user\AppData\Local\Temp",
    "TMP": r"C:\Users\user\AppData\Local\Temp",
    "USERDOMAIN": "DESKTOP",
    "USERNAME": "user",
    "USERPROFILE": r"C:\Users\user",
    "windir": r"C:\Windows",
}

# Commands that change nothing a walk models. A GOTO that only jumps over such commands, joined by
# a command separator, is the generator's separator showcase and not a dispatch.
INERT = {"ver", "rem", "echo", "findstr", "find", "more", "sort", "type", "title", "color", "verify", "break", "cls", "chcp"}

_IF = re.compile(r"if\s+(/i\s+)?(not\s+)?", re.I)
_IF_DEFINED = re.compile(r"defined\s+([^\s&|]+)\s?", re.I)
_IF_ERRORLEVEL = re.compile(r"errorlevel\s+(\d+)\s?", re.I)
_IF_EXIST = re.compile(r"exist\s+(\"[^\"]*\"|[^\s&|]+)\s?", re.I)
_IF_COMPARE = re.compile(r"(\"[^\"]*\"|\S+?)\s*(==|\s(?:equ|neq|lss|leq|gtr|geq)\s)\s*(\"[^\"]*\"|[^\s&|]+)\s?", re.I)
_ELSE = re.compile(r"\s*else(?=[\s(]|$)\s*", re.I)
_FOR = re.compile(r"for\s+(?:(/[A-Za-z])\s+)?(?:\"[^\"]*\"\s+)?%([A-Za-z?#$@~])\s+in\s*\((.*?)\)\s*do(?=[\s(])\s*", re.I | re.S)
_WORD = re.compile(r"[A-Za-z]+")
_EXIT_CODE = re.compile(r"\s*(?:/b\s+)?(-?\d+)\s*$", re.I)
_CMD_EXIT = re.compile(r"cmd(?:\.exe)?\s+/c\s+exit\s+(?:/b\s+)?(-?\d+)\s*$", re.I)


def decode(data: bytes) -> str:
    """The text of a script file. cmd.exe reads bytes; a specimen saved as UTF-8 or UTF-16 with a
    byte-order mark (or as UTF-16 without one, which shows as a NUL in every other byte) is the same
    script, so it is decoded by what it is and not as UTF-8 whatever it is."""
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", "replace")
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    head = data[:400]
    if len(head) >= 8 and b"\x00" in head:
        odd, even = head[1::2].count(0), head[0::2].count(0)
        if odd > len(head) // 4 and even == 0:
            return data.decode("utf-16-le", "replace")
        if even > len(head) // 4 and odd == 0:
            return data.decode("utf-16-be", "replace")
    return data.decode("utf-8", "replace")


# ---- parsing one logical line ---------------------------------------------------------------------
#
# Nodes:  ("simple", text, stdout_redirected)      carets resolved, redirections removed
#         ("rem",)
#         ("group", items, stdout_redirected)      a parenthesised block
#         ("if", cond, then_items, else_items, raw_then)
#         ("for", switch, var, spec, raw_body)     the body stays text: the variable is substituted first
#         ("noop",)                                an IF or FOR this model cannot read
# items = [(operator before the command, node)], operator in None & && || |  (a newline inside a block is &)

def _redirection(s: str, i: int, cur: list, in_group: bool):
    """s[i] is an unquoted < or >. Drops the redirection (and a handle digit already in cur).
    Returns (index after it, whether stdout was redirected)."""
    n, c = len(s), s[i]
    handle = None
    if cur and cur[-1].isdigit() and (len(cur) == 1 or cur[-2].isspace()):
        handle = cur.pop()              # the 2 of 2>nul
    out = c == ">" and handle in (None, "1")
    i += 2 if s[i:i + 2] == ">>" else 1
    if i < n and s[i] == "&":
        i += 1                          # >&1
    while i < n and s[i] in " \t":
        i += 1
    if i < n and s[i] == '"':
        j = s.find('"', i + 1)
        i = n if j == -1 else j + 1
    else:
        while i < n and not s[i].isspace() and s[i] not in "&|<>" and not (in_group and s[i] == ")"):
            i += 1
    return i, out


def _simple(s: str, i: int, in_group: bool):
    """One plain command from s[i:]. Stops before an unquoted operator, a newline, or the `)` of the
    enclosing block. Returns (node, index)."""
    cur, quoted, redirected, n = [], False, False, len(s)
    while i < n:
        c = s[i]
        if c == "^" and not quoted:
            if i + 1 < n:
                cur.append(s[i + 1])
            i += 2
            continue
        if c == "\n":
            break
        if c == '"':
            quoted = not quoted
        elif not quoted and (c in "&|" or (in_group and c == ")")):
            break
        elif not quoted and c in "<>":
            i, out = _redirection(s, i, cur, in_group)
            redirected = redirected or out
            continue
        cur.append(c)
        i += 1
    return ("simple", "".join(cur), redirected), i


def _after_group(s: str, i: int, in_group: bool):
    """Redirections written after a block's `)`. Returns (index, whether stdout was redirected)."""
    n, redirected = len(s), False
    while True:
        j = i
        while j < n and s[j] in " \t":
            j += 1
        cur = []
        if j < n and s[j].isdigit() and j + 1 < n and s[j + 1] in "<>":
            cur, j = [s[j]], j + 1
        if j < n and s[j] in "<>":
            i, out = _redirection(s, j, cur, in_group)
            redirected = redirected or out
            continue
        return i, redirected


def _sequence(s: str, i: int, in_group: bool, st: dict):
    """Commands from s[i:] up to the end, or up to the `)` that closes the enclosing block.
    Returns (items, index of that `)` or len(s)). st["open"] counts blocks the text never closed."""
    items, op, n = [], None, len(s)
    while True:
        node, i = _command(s, i, in_group, st)
        if node is not None:
            items.append((op, node))
        while i < n and s[i] in " \t":
            i += 1
        if i >= n:
            if in_group:
                st["open"] += 1
            return items, n
        if in_group and s[i] == ")":
            return items, i
        if s[i] == "\n":
            op, i = "&", i + 1
        elif s[i:i + 2] in ("&&", "||"):
            op, i = s[i:i + 2], i + 2
        elif s[i] in "&|":
            op, i = s[i], i + 1
        else:
            i += 1                      # not reached: every command stops at one of the above


def _group(s: str, i: int, in_group: bool, st: dict):
    """s[i] is the `(` of a block. Returns (items, stdout_redirected, index after the block)."""
    st["groups"].append(i)
    items, j = _sequence(s, i + 1, True, st)
    st["groups"].pop()
    j, redirected = _after_group(s, min(j + 1, len(s)), in_group)
    return items, redirected, j


def _command(s: str, i: int, in_group: bool, st: dict):
    """One command from s[i:]: a block, an IF, a FOR, a REM or a plain command. Returns (node, index)."""
    n = len(s)
    while i < n and s[i] in " \t@":
        i += 1
    if i >= n or s[i] == "\n" or (in_group and s[i] == ")"):
        return None, i
    if s[i] == "(":
        items, redirected, j = _group(s, i, in_group, st)
        return ("group", items, redirected), j
    m = _WORD.match(s, i)
    word = m.group(0).lower() if m else ""
    if word == "rem":
        # REM takes the rest of its line. In a block opened on that same line (`(rem note)`), the
        # last `)` of the line is the block's own and the comment ends there.
        end = s.find("\n", i)
        end = n if end == -1 else end
        if in_group and "\n" not in s[st["groups"][-1]:i]:
            k = s.rfind(")", i, end)
            end = k if k != -1 else end
        return ("rem",), end
    if word == "if":
        return _if(s, i, in_group, st)
    if word == "for":
        m = _FOR.match(s, i)
        if not m:                       # FOR in a form this model does not read: the line does nothing
            _, j = _sequence(s, i + 3, in_group, st)
            return ("noop",), j
        k = m.end()
        if s[k:k + 1] == "(":
            _, _, j = _group(s, k, in_group, st)
        else:
            _, j = _sequence(s, k, in_group, st)   # without a block the body is the rest of the line
        return ("for", (m.group(1) or "").lower(), m.group(2), m.group(3), s[k:j]), j
    return _simple(s, i, in_group)


def _if(s: str, i: int, in_group: bool, st: dict):
    head = _IF.match(s, i)
    k = head.end() if head else i
    nocase, neg = bool(head and head.group(1)), bool(head and head.group(2))
    cond = None
    for kind, rx in (("defined", _IF_DEFINED), ("errorlevel", _IF_ERRORLEVEL), ("exist", _IF_EXIST), ("compare", _IF_COMPARE)):
        m = rx.match(s, k) if head else None
        if m:
            cond = (kind, nocase, neg) + m.groups()
            k = m.end()
            break
    if cond is None:
        _, j = _sequence(s, i + 2, in_group, st)
        return ("noop",), j
    while k < len(s) and s[k] in " \t":
        k += 1
    orelse = None
    if s[k:k + 1] == "(":
        then, _, j = _group(s, k, in_group, st)
        raw = s[k:j]
        e = _ELSE.match(s, j)
        if e:
            if s[e.end():e.end() + 1] == "(":
                orelse, _, j = _group(s, e.end(), in_group, st)
            else:
                orelse, j = _sequence(s, e.end(), in_group, st)
    else:
        then, j = _sequence(s, k, in_group, st)    # without a block the body is the rest of the line
        raw = s[k:j]
    return ("if", cond, then, orelse, raw), j


def parse(text: str):
    """One logical line as (items, unclosed): unclosed is true when a block is still open at its end."""
    st = {"open": 0, "groups": []}
    items, _ = _sequence(text, 0, False, st)
    return items, st["open"] > 0


def _words(items, out: list) -> list:
    """Every plain command's first word in a parsed line, blocks included."""
    for _, node in items:
        if node[0] == "simple":
            m = _WORD.match(node[1].lstrip())
            out.append(m.group(0).lower() if m else "")
        elif node[0] == "group":
            _words(node[1], out)
        elif node[0] != "rem":
            out.append(node[0])
    return out


def is_separator_line(line: str) -> bool:
    """A line of inert commands joined by a command separator (`ver >nul & rem ...`, `x | findstr y`)."""
    line = line.strip()
    if not line or line.startswith(":"):
        return False
    items, _ = parse(line)
    words = _words(items, [])
    return len(items) > 1 and all(w in INERT for w in words)


_NEUTRAL_SET = re.compile(r'set\s+(?:/a\s+)?"?\s*neutral_\w*\s*[-+*/%&|^]?=', re.I)


def neutral_kind(line: str):
    """What a line is to the plan: "set" if every command on it is a SET of a neutral_* variable,
    "label" for a label or a comment (a label that says neutral counts as "set": it is the
    generator's own word for a statement that changes no answer), None for anything else."""
    s = line.strip().lstrip("@").strip()
    if s.startswith("::") or re.match(r"rem(\s|$)", s, re.I):
        return "label"
    if s.startswith(":"):
        return "set" if "neutral" in s.lower() else "label"
    items, unclosed = parse(s)
    if unclosed or not items:
        return None
    for _, node in items:
        if node[0] == "rem":
            continue
        if node[0] != "simple" or not _NEUTRAL_SET.match(node[1].strip()):
            return None
    return "set"


class Cmd:
    def __init__(self, text: str, args=(), env=None, keep_trailing: bool = False):
        """text: the script. args: %0, %1, ... env: the variables to start from (default SYSTEM_ENV).
        Trailing blanks of a line are dropped unless keep_trailing: cmd.exe would keep them in an
        unquoted `set name=value `, but there they are an editing accident, not part of the value."""
        if text[:1] == "\ufeff":
            text = text[1:]
        lines = re.split(r"\r\n|\n|\r", text)
        self.lines = lines if keep_trailing else [line.rstrip(" \t") for line in lines]
        self.labels = {}                 # label -> the first line it stands on
        self.label_lines = {}            # label -> every line it stands on (see find_label)
        for i, line in enumerate(self.lines):
            s = line.strip()
            if s.startswith(":") and not s.startswith("::"):
                parts = s[1:].split()
                if parts:
                    self.labels.setdefault(parts[0].upper(), i)
                    self.label_lines.setdefault(parts[0].upper(), []).append(i)
        self.args = list(args)
        self.env = {k.upper(): v for k, v in (SYSTEM_ENV if env is None else env).items()}
        self.system = set(self.env)      # names that came with the session, not from the script
        self.system_refs = {}            # the ones the walk expanded: {name: stand-in value}
        self.delayed = False
        self.errorlevel = 0
        self.out = []
        # assigns: {"seq", "name", "value", "flags", "line", "depth", "frames", "guards", "loops", "reads"}
        #   flags   how the value was produced: percent, delayed, call, for
        #   depth   how many `call :label` frames deep the SET ran
        #   frames  those frames, outermost first, each `call :label` under its own number: what ran
        #           in frames (1, 2) was reached through what ran in (1,) and (), and through nothing
        #           that ran in (3,), a subroutine that had already returned
        #   guards  the conditions it ran under: (form, detail, depth where it stands, on a mode-switch
        #           line); form is if_defined, if_not_defined, if_errorlevel, ..., `_else` appended for
        #           the ELSE branch, or if_status for a command after && or ||
        #   loops   the FORs it ran under: (kind, whether the body uses the loop variable, depth, count)
        #   reads   the variables expanded on its line up to the SET
        # events: {"seq", "kind", "line", "depth", "frames", "guards", "loops", "mode", ...}; kinds:
        #   goto, call, for_l, for_in, echo, and one per condition tested: if_defined, if_errorlevel,
        #   if_exist, if_compare (result: the THEN branch ran; escape: that branch starts with exit or
        #   goto) and if_status (an exit or goto after && or || that was passed over). `mode` marks a
        #   line that reads the script's arguments (the mode switch). A goto says what it jumped
        #   over: `separator` (only inert commands) or `neutral` (only neutral_* statements).
        self.assigns = []
        self.events = []
        self.seq = 0
        self.steps = 0
        self.pc = 0
        self.exhausted = False
        self.depth = 0
        self.frames = ()
        self.calls = 0
        self.guards = []
        self.loops = []
        self.used = set()                # variables expanded so far on the current logical line
        self.mode = False                # the current logical line reads %1, %~1 or %*

    def _event(self, kind, **kw):
        self.seq += 1
        self.events.append({"seq": self.seq, "kind": kind, "line": self.pc, "depth": self.depth, "frames": self.frames,
                            "guards": tuple(self.guards), "loops": tuple(self.loops), "mode": self.mode, **kw})

    def find_label(self, name: str, after: int):
        """The line GOTO or CALL lands on, or None. cmd.exe looks for the label from the line below
        the command to the end of the file and only then from the top, so of two labels with one
        name the next one below is taken, not the first in the file."""
        lines = self.label_lines.get(name.upper())
        if not lines:
            return None
        return next((i for i in lines if i > after), lines[0])

    # ---- variables ---------------------------------------------------------
    def lookup(self, ref: str):
        name, sep, op = ref.partition(":")
        key = name.upper()
        val = self.env.get(key)
        if val is None and key == "ERRORLEVEL":
            val = str(self.errorlevel)
        if val is not None:
            self.used.add(key)
            if key in self.system:
                self.system_refs[key] = val
        if val is None or not sep:
            return val
        if op.startswith("~"):
            m = re.fullmatch(r"~(-?\d+)(?:,(-?\d+))?", op)
            if not m:
                return val
            start = int(m.group(1))
            if start < 0:
                start = max(len(val) + start, 0)
            if m.group(2) is None:
                return val[start:]
            n = int(m.group(2))
            return val[start:start + n] if n >= 0 else val[start:len(val) + n]
        if "=" in op:
            old, _, new = op.partition("=")
            if old.startswith("*"):
                k = val.lower().find(old[1:].lower())
                return val if k < 0 else new + val[k + len(old) - 1:]
            return re.sub(re.escape(old), lambda _m: new, val, flags=re.I) if old else val
        return val

    def expand_percent(self, s: str):
        """Phase 1. Returns (text, whether any variable was substituted)."""
        out, i, used, grown = [], 0, False, 0
        while i < len(s):
            if s[i] != "%":
                out.append(s[i])
                i += 1
                continue
            if s.startswith("%%", i):
                out.append("%")
                i += 2
                continue
            m = re.match(r"%(~[A-Za-z]*)?(\d)", s[i:])
            if m:
                n = int(m.group(2))
                val = self.args[n] if n < len(self.args) else ""
                out.append(val.strip('"') if m.group(1) is not None else val)
                i += m.end()
                if self.depth == 0 and n > 0:
                    # Inside a subroutine %1 is that call's argument, not the script's, and %0 (%~f0,
                    # %~dp0) is the script's own path anywhere: neither makes a line the mode switch.
                    self.mode = True
                continue
            if s.startswith("%*", i):
                out.append(" ".join(self.args[1:]))
                i += 2
                if self.depth == 0:
                    self.mode = True
                continue
            j = s.find("%", i + 1)
            if j == -1:
                i += 1          # a lone percent is dropped in a batch file
                continue
            val = self.lookup(s[i + 1:j])
            if val is not None:
                out.append(val)
                used = True
                grown += len(val)
                if grown > MAX_VALUE:
                    self.exhausted = True       # cmd.exe: "The input line is too long"
                    break
            i = j + 1           # an undefined %name% expands to nothing
        return "".join(out), used

    def expand_delayed(self, s: str):
        """Phase 5. Returns (text, whether any variable was substituted)."""
        if not self.delayed or "!" not in s:
            return s, False
        out, i, used, grown = [], 0, False, 0
        while i < len(s):
            if s[i] != "!":
                out.append(s[i])
                i += 1
                continue
            j = s.find("!", i + 1)
            if j == -1:
                i += 1
                continue
            val = self.lookup(s[i + 1:j])
            if val is not None:
                out.append(val)
                used = True
                grown += len(val)
                if grown > MAX_VALUE:
                    self.exhausted = True
                    break
            i = j + 1
        return "".join(out), used

    # ---- execution ---------------------------------------------------------
    def run(self, start: int = 0, depth: int = 0):
        pc = start
        while 0 <= pc < len(self.lines):
            self.steps += 1
            if self.steps > MAX_STEPS or depth > MAX_DEPTH:
                self.exhausted = True
                return
            self.pc = pc
            sig, taken = self.exec_line(pc, depth)
            pc += taken
            if self.exhausted:
                return
            if sig is None:
                continue
            if sig[0] == "exit":
                return
            target = sig[1].upper()
            at = None if target == "EOF" else self.find_label(target, pc - 1)
            if at is None:
                return
            pc = at + 1

    def exec_line(self, pc: int, depth: int):
        """Run the logical line that starts at lines[pc]. Returns (signal, physical lines it took)."""
        line = self.lines[pc].lstrip().lstrip("@").lstrip()
        if not line.strip() or line.startswith(":"):
            return None, 1
        self.used, self.mode = set(), False
        self.steps += len(line) >> 8        # the budget counts work: a long line costs more than a short one
        text, used = self.expand_percent(line)
        items, unclosed = parse(text)
        taken, stale = 1, False
        while unclosed and pc + taken < len(self.lines) and taken < MAX_BLOCK:
            more, u = self.expand_percent(self.lines[pc + taken])   # a block is read to its `)` before it runs
            self.steps += len(more) >> 8
            text, used, taken = text + "\n" + more, used or u, taken + 1
            stale = ")" not in more          # only a line with a `)` can close the block: parse again then
            if not stale:
                items, unclosed = parse(text)
        if stale:
            items, _ = parse(text)           # never closed: what was read runs, as before
        return self.exec_items(items, depth, frozenset({"percent"}) if used else frozenset()), taken

    def exec_text(self, text: str, depth: int, flags, quiet: bool = False):
        self.steps += len(text) >> 8        # a FOR body or a CALL is read again every time it runs
        return self.exec_items(parse(text)[0], depth, flags, quiet)

    def exec_items(self, items: list, depth: int, flags, quiet: bool = False):
        ok = True
        for i, (op, node) in enumerate(items):
            if self.exhausted:
                return ("exit", "")
            kind = node[0]
            if kind in ("rem", "noop"):
                continue
            if op == "|" or (op == "&&" and not ok) or (op == "||" and ok):
                first = _WORD.match(node[1].lstrip(" \t@")) if kind == "simple" else None
                if op != "|" and first and first.group(0).lower() in ("exit", "goto"):
                    # `cmd || exit /b 1`: a guard written with an operator, passed without leaving
                    self._event("if_status", result=False, neg=op == "||", body=node[1].strip(),
                                escape=first.group(0).lower(), orelse=False)
                continue
            piped = quiet or (i + 1 < len(items) and items[i + 1][0] == "|")
            conditional = op in ("&&", "||")
            if conditional:
                self.guards.append(("if_status", op, self.depth, self.mode))
            try:
                if kind == "group":
                    sig = self.exec_items(node[1], depth, flags, piped or node[2])
                elif kind == "if":
                    sig = self.do_if(node, depth, flags, piped)
                elif kind == "for":
                    sig = self.do_for(node, depth, flags, piped)
                else:
                    t = node[1].lstrip().lstrip("@").lstrip()
                    if not t.strip() or t.startswith(":"):
                        continue        # a label written inside a block
                    m = _WORD.match(t)
                    sig = self.exec_simple(t, m.group(0).lower() if m else "", depth, flags, quiet=piped or node[2])
            finally:
                if conditional:
                    self.guards.pop()
            ok = self.errorlevel == 0
            if sig is not None:
                return sig
        return None

    def exists(self, path: str) -> bool:
        """IF EXIST on paper: only what every Windows system has (the session's own directories)."""
        p = path.strip().strip('"').rstrip("\\").lower()
        if p in ("nul", "con"):
            return True
        known = {v.rstrip("\\").lower() for k, v in self.env.items() if k in self.system and v[1:3] == ":\\"}
        known |= {v[:2].lower() for v in known}
        return bool(p) and p in known

    def do_if(self, node, depth: int, flags, quiet: bool):
        _, cond, then, orelse, raw = node
        kind, nocase, neg = cond[:3]
        if kind == "defined":
            result = cond[3].upper() in self.env
            name, detail = "if_defined", {"name": cond[3]}
        elif kind == "errorlevel":
            result = self.errorlevel >= int(cond[3])
            name, detail = "if_errorlevel", {"level": int(cond[3])}
        elif kind == "exist":
            path, _ = self.expand_delayed(cond[3])
            result = self.exists(path)
            name, detail = "if_exist", {"path": path}
        else:
            left, _ = self.expand_delayed(cond[3])
            right, _ = self.expand_delayed(cond[5])
            if nocase:
                left, right = left.lower(), right.lower()
            oper = cond[4].strip().lower()
            if oper in ("==", "equ"):
                result = left == right
            elif oper == "neq":
                result = left != right
            else:
                try:
                    a, b = int(left.strip('"')), int(right.strip('"'))
                except ValueError:
                    a, b = left, right
                result = {"lss": a < b, "leq": a <= b, "gtr": a > b, "geq": a >= b}[oper]
            name, detail = "if_compare", {}
        taken = result != neg
        m = _WORD.match(raw.lstrip(" \t(@"))
        first = m.group(0).lower() if m else ""
        # body: the THEN branch as written. escape: it leaves the straight line (exit or goto).
        self._event(name, result=taken, neg=neg, body=raw.strip(), escape=first if first in ("exit", "goto") else None,
                    orelse=orelse is not None, **detail)
        branch = then if taken else orelse
        if branch is None:
            return None
        ident = detail.get("name", detail.get("level"))
        form = name.replace("if_", "if_not_", 1) if neg else name       # if_defined, if_not_defined, ...
        self.guards.append((form if taken else form + "_else", ident, self.depth, self.mode))
        try:
            return self.exec_items(branch, depth, flags, quiet)
        finally:
            self.guards.pop()

    def do_for(self, node, depth: int, flags, quiet: bool):
        _, switch, var, spec, raw = node
        if switch == "/l":
            nums = [int(n) for n in re.findall(r"-?\d+", spec)]
            if len(nums) != 3 or nums[1] == 0:
                return None
            start, step, end = nums
            values = range(start, end + (1 if step > 0 else -1), step)
            kind = "for_l"
        elif switch == "":
            values = [v for v in re.split(r"[\s,;=]+", spec) if v]
            kind = "for_in"
        else:
            return None         # FOR /F, /D, /R read the system: nothing to follow on paper
        uses = "%" + var in raw
        self._event(kind, values=[str(v) for v in islice(values, EVENT_VALUES)], count=len(values), uses=uses)
        inner = flags | {"for"} if uses else flags
        self.loops.append((kind, uses, self.depth, len(values)))
        try:
            for value in values:
                self.steps += 1         # a loop is bounded by the same budget as the lines
                if self.steps > MAX_STEPS:
                    self.exhausted = True
                if self.exhausted:
                    return ("exit", "")
                sig = self.exec_text(raw.replace("%" + var, str(value)), depth, inner, quiet)
                if sig is not None:
                    return sig
        finally:
            self.loops.pop()
        return None

    def exec_simple(self, t: str, word: str, depth: int, flags, quiet: bool = False):
        rest = t[len(word):]
        if word == "echo":
            if rest.strip().lower() in ("off", "on", ""):
                return None
            text, _ = self.expand_delayed(rest[1:])     # echo( echo. echo<space>
            if self.exhausted or len(text) > MAX_VALUE:
                self.exhausted = True       # a line cmd.exe would refuse: nothing of it is taken as output
                return ("exit", "")
            if not quiet:
                self.out.append(text)
                self._event("echo", text=text, vars=frozenset(self.used))
            return None
        if word == "set":
            return self.do_set(rest, flags)
        if word == "goto":
            parts = rest.strip().lstrip(":").split()
            if not parts:
                return None
            idx = self.find_label(parts[0], self.pc)
            skipped = [x for x in self.lines[self.pc + 1:idx] if x.strip()] if idx is not None and idx > self.pc else []
            named = "separator" in parts[0].lower() or "separator" in " ".join(skipped).lower()
            kinds = [neutral_kind(x) for x in skipped]
            self._event("goto", label=parts[0], skipped=len(skipped),
                        separator=named or (bool(skipped) and all(is_separator_line(x) for x in skipped)),
                        neutral=None not in kinds and "set" in kinds)
            return ("goto", parts[0])
        if word == "call":
            target = rest.strip()
            if target.startswith(":"):
                words = target[1:].split()
                label = words[0] if words else ""
                self._event("call", label=label)
                at = self.find_label(label, self.pc)
                if at is not None:
                    saved_args, saved_pc, saved_used, saved_mode = self.args, self.pc, self.used, self.mode
                    saved_frames = self.frames
                    self.args = [self.args[0] if self.args else ""] + words[1:]
                    self.depth += 1
                    self.calls += 1
                    self.frames = saved_frames + (self.calls,)
                    try:
                        self.run(at + 1, depth + 1)
                    finally:
                        self.depth -= 1
                        self.frames = saved_frames
                        self.args, self.pc, self.used, self.mode = saved_args, saved_pc, saved_used, saved_mode
                    if self.exhausted:
                        return ("exit", "")
                return None
            again, _ = self.expand_percent(rest.lstrip())    # CALL's second percent pass
            return self.exec_text(again, depth + 1, flags | {"call"}, quiet)
        if word == "exit":
            m = _EXIT_CODE.match(rest)
            if m:
                self.errorlevel = int(m.group(1))   # what the caller's IF ERRORLEVEL sees
            return ("exit", "")
        if word == "setlocal":
            low = rest.lower()
            if "enabledelayedexpansion" in low:
                self.delayed = True
            elif "disabledelayedexpansion" in low:
                self.delayed = False
            return None
        m = _CMD_EXIT.match(t) if word == "cmd" else None
        self.errorlevel = int(m.group(1)) if m else 0   # every other command is a no-op that succeeds
        return None

    def do_set(self, rest: str, flags):
        body = rest.lstrip()
        if body[:2].lower() in ("/p", "/a"):
            return None         # prompts and arithmetic carry no plan material
        if body.startswith('"'):
            end = body.rfind('"')
            body = body[1:end] if end > 0 else body[1:]
        body, used = self.expand_delayed(body)
        name, sep, value = body.partition("=")
        if not sep or not name.strip():
            return None
        key = name.strip().upper()
        if self.exhausted or len(value) > MAX_VALUE:
            # cmd.exe stops here with "The input line is too long". A walk that went on would let
            # a loop over `set "z=!z!!z!"` double the value until the memory is gone.
            self.exhausted = True
            return ("exit", "")
        if value == "":
            self.env.pop(key, None)
        else:
            self.env[key] = value
        self.seq += 1
        self.assigns.append({"seq": self.seq, "name": key, "value": value,
                             "flags": set(flags) | ({"delayed"} if used else set()),
                             "line": self.pc, "depth": self.depth, "frames": self.frames, "guards": tuple(self.guards),
                             "loops": tuple(self.loops), "reads": frozenset(self.used) - {key}})
        return None
