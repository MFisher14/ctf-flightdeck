"""The practice set: synthetic challenges in the folder-board format, each one solvable.

Every challenge has a reference solver here. It recovers the flag from the handout files with the
standard library alone and never runs handout code: it reads the data out of the files and undoes
the transformation. The flag it finds must match the board's flag format and hash to the answers
file's entry, so a challenge nobody can solve, or an answer that does not match, fails here. No
flag is written in this file or anywhere else in the repository: the solvers derive them, and
failure messages show hashes, never flags.

challenge.json is checked against the folder-board format with plain json rather than with
flightdeck's board loader, so the data is held to the format on its own.
"""

from __future__ import annotations

import ast
import base64
import csv
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import urllib.parse
import zipfile
import zlib
from collections import Counter
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import pytest

REPO = Path(__file__).resolve().parents[1]
PRACTICE = REPO / "src" / "ctf_flightdeck" / "practice"  # inside the package, so it ships in the wheel


def load_json(path: Path):
    """Parse JSON, refusing duplicate keys (plain json.loads would keep the last one silently)."""

    def no_repeats(pairs):
        keys = [key for key, _ in pairs]
        repeated = sorted({key for key in keys if keys.count(key) > 1})
        if repeated:
            raise ValueError(f"duplicate keys {repeated}")
        return dict(pairs)

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_repeats)


def files_under(folder: Path) -> list[Path]:
    """Regular files below `folder`; symlinks are not followed (a test reports them)."""
    found = []
    for root, _dirs, names in os.walk(folder):
        found += [Path(root) / name for name in names if not (Path(root) / name).is_symlink()]
    return sorted(found)


CHALLENGES = sorted(p for p in PRACTICE.iterdir() if p.is_dir() and (p / "challenge.json").is_file())
BOARD = load_json(PRACTICE / "board.json")
FLAG = re.compile(BOARD["flag_format"])
ANSWERS = load_json(PRACTICE / "answers.sha256.json")


def challenge(folder: Path) -> dict:
    return load_json(folder / "challenge.json")


def challenge_id(folder: Path) -> str:
    return challenge(folder).get("id", folder.name)


def find_flag(text: str) -> str:
    found = FLAG.search(text)
    assert found, "the decoded text holds nothing in the flag format"
    return found.group()


# --- the folder-board format (docs: the M1 contracts, section C) ----------------------------

FIELDS = {"name": str, "category": str, "points": int, "solves": int, "description": str, "files": list, "urls": list, "id": str}
REQUIRED = ("name", "category", "points")
ID = re.compile(r"[a-z0-9][a-z0-9_.-]*")
ORIGIN = re.compile(r"https?://[A-Za-z0-9.-]+(?::\d{1,5})?")  # scheme://host[:port], no path


def format_errors(folder: Path) -> list[str]:
    """What is wrong with folder/challenge.json, by the folder-board format."""
    try:
        data = challenge(folder)
    except ValueError as exc:
        return [f"not valid JSON: {exc}"]
    if not isinstance(data, dict):
        return ["not a JSON object"]
    errors = [f"unknown key {key!r}" for key in data if key not in FIELDS]
    errors += [f"missing {key!r}" for key in REQUIRED if key not in data]
    # type() rather than isinstance(): JSON true and false are bools, and bool is an int subclass
    errors += [f"{key!r} is not {kind.__name__}" for key, kind in FIELDS.items() if key in data and type(data[key]) is not kind]
    if errors:
        return errors
    if not data["name"].strip():
        errors.append("empty name")
    if data["points"] < 0:
        errors.append("negative points")
    if data.get("solves", 0) < 0:
        errors.append("negative solves")
    if not ID.fullmatch(data.get("id", folder.name)):
        errors.append(f"id {data.get('id', folder.name)!r} does not match {ID.pattern}")
    for item in data.get("files", []):
        if type(item) is not str or not item or PurePosixPath(item).is_absolute() or ".." in PurePosixPath(item).parts:
            errors.append(f"file {item!r} is not a relative path inside the directory")
        elif (folder / item).is_symlink() or not (folder / item).is_file():
            errors.append(f"file {item!r} is missing or not a regular file")
    for url in data.get("urls", []):
        if type(url) is not str or not ORIGIN.fullmatch(url):
            errors.append(f"url {url!r} is not an http(s) origin")
    return errors


# --- reference solvers: read the handout, undo the transformation, never run handout code ---


def shift_letters(text: str, by: int) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + by) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + by) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def solve_crab_walk(folder: Path) -> str:
    """A shift cipher: of the 26 shifts, only the right one turns the text before "{" into the prefix."""
    card = (folder / "postcard.txt").read_text(encoding="utf-8")
    for shift in range(26):
        found = FLAG.search(shift_letters(card, -shift))
        if found:
            return found.group()
    raise AssertionError("no shift of the postcard reads as a flag")


def peel(text: str) -> str:
    """One layer off, recognised by its alphabet; hex is tried first as it fits the others' too."""
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", text):
        data = bytes.fromhex(text)
    elif re.fullmatch(r"[A-Z2-7]+=*", text) and len(text) % 8 == 0:
        data = base64.b32decode(text)
    elif re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) and len(text) % 4 == 0:
        data = base64.b64decode(text, validate=True)
    else:
        data = base64.b85decode(text)
    return data.decode("ascii")


def solve_mille_feuille(folder: Path) -> str:
    text = (folder / "layers.txt").read_text(encoding="ascii").strip()
    for _ in range(32):
        if FLAG.fullmatch(text):
            return text
        text = peel(text)
    raise AssertionError("still no flag after 32 layers")


def solve_harbour_memo(folder: Path) -> str:
    """Repeating-key XOR: the header the description names is known plaintext, so it gives the key."""
    hint = re.search(r'header, "([^"]+)"', challenge(folder)["description"])
    assert hint, "the description no longer names the memo header"
    header = hint.group(1).encode()
    cipher = (folder / "memo.enc").read_bytes()
    stream = bytes(c ^ p for c, p in zip(cipher, header))
    period = next(n for n in range(1, len(stream) + 1) if all(stream[i] == stream[i % n] for i in range(len(stream))))
    assert period < len(stream), "the key is no shorter than the header: the header cannot reveal it"
    key = stream[:period]
    return find_flag(bytes(c ^ key[i % period] for i, c in enumerate(cipher)).decode("ascii"))


def solve_postmarked(folder: Path) -> str:
    """Vigenere keyed with the postmark's town: letters advance the key, everything else passes through."""
    postmark = re.search(r"POSTMARK\s+([A-Z]+)", (folder / "envelope.txt").read_text(encoding="utf-8"))
    assert postmark, "the envelope has no postmark town"
    key = [ord(ch) - 65 for ch in postmark.group(1)]
    out, used = [], 0
    for ch in (folder / "letter.txt").read_text(encoding="utf-8"):
        if ch.isascii() and ch.isalpha():
            ch = shift_letters(ch, -key[used % len(key)])
            used += 1
        out.append(ch)
    return find_flag("".join(out))


def integer_cube_root(n: int) -> int:
    """floor(n ** (1/3)) by Newton's method, from a start at or above the root."""
    x = 1 << -(-n.bit_length() // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


def solve_three_wishes(folder: Path) -> str:
    """e = 3 with no padding: m**3 is smaller than n, so c is m**3 itself and its cube root is m."""
    values = dict(re.findall(r"^(\w+) = (\d+)$", (folder / "output.txt").read_text(encoding="ascii"), re.M))
    assert int(values["e"]) == 3
    c = int(values["c"])
    m = integer_cube_root(c)
    assert m**3 == c, "c is not a perfect cube: m**3 wrapped around n"
    return find_flag(m.to_bytes((m.bit_length() + 7) // 8, "big").decode("ascii"))


def png_texts(data: bytes) -> list[str]:
    """The text of every tEXt and zTXt chunk (zTXt: keyword, NUL, method byte, zlib data)."""
    assert data.startswith(b"\x89PNG\r\n\x1a\n"), "not a PNG"
    texts, pos = [], 8
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        kind, body = data[pos + 4 : pos + 8], data[pos + 8 : pos + 8 + length]
        pos += 12 + length  # length, type, data, CRC
        if kind == b"tEXt":
            texts.append(body.split(b"\x00", 1)[1].decode("latin-1"))
        elif kind == b"zTXt":
            texts.append(zlib.decompress(body.split(b"\x00", 1)[1][1:]).decode("latin-1"))
    return texts


def solve_fine_print(folder: Path) -> str:
    return find_flag("\n".join(png_texts((folder / "harbour_dawn.png").read_bytes())))


def flag_in_zip(data: bytes, depth: int = 0) -> str | None:
    """Open zips inside zips in memory, as deep as they go (within reason), until a member holds a flag."""
    assert depth < 16, "zips nested more than 16 deep"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            member = archive.read(info)
            if member.startswith(b"PK\x03\x04"):
                found = flag_in_zip(member, depth + 1)
            else:
                match = FLAG.search(member.decode("utf-8", "replace"))
                found = match.group() if match else None
            if found:
                return found
    return None


def solve_nesting_dolls(folder: Path) -> str:
    found = flag_in_zip((folder / "dolls.zip").read_bytes())
    assert found, "no doll holds a flag"
    return found


def solve_quiet_night(folder: Path) -> str:
    """URL-decode each request line, then try every base64-looking token in it."""
    for line in (folder / "access_log").read_text(encoding="utf-8").splitlines():
        request = re.search(r'"[A-Z]+ (\S+) HTTP/[\d.]+"', line)
        if not request:
            continue
        target = urllib.parse.unquote(request.group(1))
        for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", target):
            try:
                text = base64.b64decode(token, validate=True).decode("ascii")
            except ValueError:  # binascii.Error and UnicodeDecodeError are both ValueErrors
                continue
            found = FLAG.search(text)
            if found:
                return found.group()
    raise AssertionError("no request in the log decodes to a flag")


def solve_wrong_jar(folder: Path) -> str:
    """The name says PDF; the magic bytes say gzip. Believe the bytes."""
    data = (folder / "minutes.pdf").read_bytes()
    assert not data.startswith(b"%PDF"), "the minutes really are a PDF"
    assert data.startswith(b"\x1f\x8b"), "expected gzip's magic bytes"
    return find_flag(gzip.decompress(data).decode("utf-8"))


def module_constant(path: Path, name: str):
    """A module-level constant read from the source with ast; the module is never run."""
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and [getattr(t, "id", None) for t in node.targets] == [name]:
            return ast.literal_eval(node.value)
    raise AssertionError(f"{path.name} has no constant {name}")


def solve_turnstile(folder: Path) -> str:
    """punch() XORs the key, adds 7*i, rotates left 3; undo it last step first."""
    source = folder / "turnstile.py"
    key, holes = module_constant(source, "KEY"), module_constant(source, "TICKET")
    ticket = bytearray()
    for i, hole in enumerate(holes):
        x = ((hole >> 3) | (hole << 5)) & 0xFF
        x = (x - 7 * i) % 256
        ticket.append(x ^ key[i % len(key)])
    return find_flag(ticket.decode("ascii"))


UNDO: dict[str, Callable[[int, int], int]] = {
    "ADD": lambda x, k: (x - k) % 256,
    "SUB": lambda x, k: (x + k) % 256,
    "XOR": lambda x, k: x ^ k,
    "ROL": lambda x, n: ((x >> n) | (x << (8 - n))) & 0xFF,
    "NOT": lambda x, _: 255 - x,
}


def solve_pancake_stack(folder: Path) -> str:
    """Walk the program's accepting path statically, then undo each check's arithmetic.

    The checks sit in shuffled order, joined by jumps, among spare checks that nothing jumps
    to; so the walk follows each JMP and lets each JZ fall through (the check passing). Each
    check reads one byte (IN), transforms it (PUSH k + ADD/SUB/XOR, ROL n, NOT) and compares
    it with a target (PUSH t, EQ, JZ to the failure). A target of 0 with nothing done to it
    is the final check that the order ends there.
    """
    opcodes = module_constant(folder / "vm.py", "OPCODES")
    width = module_constant(folder / "vm.py", "WIDTH")
    names = {code: name for name, code in opcodes.items()}
    program = (folder / "program.bin").read_bytes()
    path: list[tuple[str, int | None]] = []
    pc, seen = 0, set()
    while True:
        assert pc not in seen, f"the accepting path loops at {pc}"
        seen.add(pc)
        name = names[program[pc]]
        operand = program[pc + 1 : pc + 1 + width.get(name, 0)]
        pc += 1 + len(operand)
        if name == "JMP":
            pc = int.from_bytes(operand, "big")
        elif name == "HALT":
            break
        else:
            path.append((name, operand[0] if len(operand) == 1 else None))
    order = bytearray()
    i = 0
    while i < len(path):
        if path[i][0] != "IN":
            i += 1
            continue
        steps, target, i = [], None, i + 1
        while path[i][0] != "EQ":
            name, arg = path[i]
            if name == "PUSH" and path[i + 1][0] in ("ADD", "SUB", "XOR"):
                steps.append((path[i + 1][0], arg))
                i += 2
            elif name == "PUSH":
                target = arg
                i += 1
            else:
                steps.append((name, arg))
                i += 1
        assert target is not None, "a check compares with nothing"
        for name, arg in reversed(steps):
            target = UNDO[name](target, arg)
        if target == 0 and not steps:
            break
        order.append(target)
    return find_flag(order.decode("ascii"))


MORSE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g", "....": "h",
    "..": "i", ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o", ".--.": "p",
    "--.-": "q", ".-.": "r", "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
}


def milliseconds(stamp: str) -> int:
    hours, minutes, seconds = stamp.split(":")
    return round((int(hours) * 3600 + int(minutes) * 60 + float(seconds)) * 1000)


def solve_signal_lamp(folder: Path) -> str:
    """Morse from the lamp's on and off times: on 1 unit is a dot, 3 a dash; off 1 unit is inside a
    letter, 3 between letters, 7 between words. The shortest interval is one unit."""
    rows = list(csv.DictReader(io.StringIO((folder / "lamp_log.csv").read_text(encoding="ascii"))))
    times = [milliseconds(row["time"]) for row in rows]
    unit = min(b - a for a, b in zip(times, times[1:]))
    words, letters, symbols = [], [], ""
    for row, start, end in zip(rows, times, times[1:]):
        units = (end - start) / unit
        if row["lamp"] == "ON":
            symbols += "." if units < 2 else "-"
        elif units >= 2:
            letters.append(MORSE[symbols])
            symbols = ""
            if units >= 5:
                words.append("".join(letters))
                letters = []
    letters.append(MORSE[symbols])
    words.append("".join(letters))
    # the description: the message in lower case, words joined by underscores, inside practice{...}
    return find_flag("practice{" + "_".join(words) + "}")


def solve_half_and_half(folder: Path) -> str:
    """Groups of eight 0s and 1s are bytes in binary; two-digit groups are bytes in hex."""
    data = bytearray()
    for group in (folder / "halves.txt").read_text(encoding="ascii").split():
        if re.fullmatch(r"[01]{8}", group):
            data.append(int(group, 2))
        elif re.fullmatch(r"[0-9a-fA-F]{2}", group):
            data.append(int(group, 16))
        else:
            raise AssertionError(f"group {group!r} is neither binary nor hex")
    return find_flag(data.decode("ascii"))


def js_constant(source: str, name: str):
    """`const NAME = <number or JSON array>;` read from the script's text; the script never runs."""
    found = re.search(rf"^const {name} = (.*?);", source, re.M | re.S)
    assert found, f"no const {name} in the script"
    value = found.group(1)
    return int(value, 0) if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", value) else json.loads(value)


def solve_welcome_mat(folder: Path) -> str:
    """banner() walks MAT in ORDER and XORs each code with SALT plus its position: redo that."""
    source = (folder / "portal.js").read_text(encoding="utf-8")
    salt, order, mat = js_constant(source, "SALT"), js_constant(source, "ORDER"), js_constant(source, "MAT")
    codes = [code for i in order for code in mat[i]]
    return find_flag("".join(chr(code ^ ((salt + n) & 0xFF)) for n, code in enumerate(codes)))


SOLVERS: dict[str, Callable[[Path], str]] = {
    "crab-walk": solve_crab_walk,
    "fine-print": solve_fine_print,
    "half-and-half": solve_half_and_half,
    "harbour-memo": solve_harbour_memo,
    "mille-feuille": solve_mille_feuille,
    "nesting-dolls": solve_nesting_dolls,
    "pancake-stack": solve_pancake_stack,
    "postmarked": solve_postmarked,
    "quiet-night": solve_quiet_night,
    "signal-lamp": solve_signal_lamp,
    "three-wishes": solve_three_wishes,
    "turnstile": solve_turnstile,
    "welcome-mat": solve_welcome_mat,
    "wrong-jar": solve_wrong_jar,
}


# --- the tests ------------------------------------------------------------------------------


def test_the_board_names_the_event_and_the_flag_format():
    assert BOARD == {"event": "Practice Range", "flag_format": r"practice\{[a-z0-9_]+\}"}


@pytest.mark.parametrize("folder", CHALLENGES, ids=lambda p: p.name)
def test_challenge_json_follows_the_folder_board_format(folder):
    assert format_errors(folder) == []


def test_the_set_spreads_twelve_to_sixteen_offline_challenges_over_five_categories():
    data = [challenge(folder) for folder in CHALLENGES]
    assert 12 <= len(data) <= 16
    assert {d["category"] for d in data} == {"crypto", "forensics", "rev", "misc", "web"}  # no pwn, no osint
    assert [d["name"] for d in data if not 50 <= d["points"] <= 300] == []
    assert [d["name"] for d in data if d.get("urls")] == []  # no network, no live instance


def test_challenge_ids_and_names_are_unique():
    for values in ([challenge_id(f) for f in CHALLENGES], [challenge(f)["name"] for f in CHALLENGES]):
        assert [value for value, n in Counter(values).items() if n > 1] == []


@pytest.mark.parametrize("folder", CHALLENGES, ids=lambda p: p.name)
def test_the_files_list_names_every_handout_file_and_nothing_else(folder):
    listed = challenge(folder).get("files")
    assert listed is not None, "the practice set lists its handout files explicitly"
    present = {p.relative_to(folder).as_posix() for p in files_under(folder) if not p.name.startswith(".")}
    assert sorted(listed) == sorted(present - {"challenge.json"})


def test_descriptions_are_short_and_hold_nothing_in_the_flag_format():
    for folder in CHALLENGES:
        description = challenge(folder)["description"]
        assert 0 < len(description) <= 250, f"{folder.name}: a description of {len(description)} characters"
        # a flag-shaped string here would be a candidate flag for any lane that reads it
        assert not FLAG.search(description), f"{folder.name}: the description holds a flag-shaped string"


EXPLICIT_HINTS = {"fine-print": "text chunks", "harbour-memo": "XOR", "signal-lamp": "Morse code"}


def test_three_descriptions_name_their_technique_outright():
    """Later milestones test the "ignores the hint" alert on these three."""
    descriptions = {challenge_id(f): challenge(f)["description"].lower() for f in CHALLENGES}
    assert [cid for cid, technique in EXPLICIT_HINTS.items() if technique.lower() not in descriptions[cid]] == []


def test_the_answers_file_holds_one_sha256_per_challenge_and_nothing_else():
    assert sorted(ANSWERS) == sorted(challenge_id(f) for f in CHALLENGES)
    assert [cid for cid, digest in ANSWERS.items() if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest)] == []
    assert len(set(ANSWERS.values())) == len(ANSWERS), "two challenges share a flag"
    assert not FLAG.search((PRACTICE / "answers.sha256.json").read_text(encoding="utf-8"))


def test_every_challenge_has_a_reference_solver_and_every_solver_a_challenge():
    assert sorted(SOLVERS) == sorted(challenge_id(f) for f in CHALLENGES)


@pytest.mark.parametrize("folder", CHALLENGES, ids=lambda p: p.name)
def test_the_reference_solver_recovers_the_flag_from_the_handout(folder):
    cid = challenge_id(folder)
    assert cid in SOLVERS, f"no reference solver for {cid}"
    flag = SOLVERS[cid](folder)
    in_format = FLAG.fullmatch(flag) is not None
    assert in_format, f"{cid}: what the solver recovered is not in the board's flag format"
    digest = hashlib.sha256(flag.encode()).hexdigest()
    assert digest == ANSWERS[cid], f"{cid}: the recovered flag does not hash to the answer on file"


def git_or_skip() -> str:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed, and the repository's file list comes from git ls-files")
    return git


def git_env() -> dict[str, str]:
    """The environment without GIT_* variables, so git finds the repository from its working
    directory: a hook's GIT_DIR or GIT_INDEX_FILE would point it at another one."""
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def repository_files(root: Path = REPO) -> list[Path]:
    """What a commit of `root` could publish: every file git tracks, plus every untracked one it
    does not ignore. git lists them, so no directory can be left off a list kept here, and what
    .gitignore covers (the venv, caches, build output, private notes, agent worktrees, run state)
    is left out."""
    if not (root / ".git").exists():
        pytest.skip(f"{root} is not a git checkout, so there is no repository to scan")
    listing = subprocess.run(
        [git_or_skip(), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, env=git_env(), capture_output=True, timeout=60,
    )
    assert listing.returncode == 0, f"git ls-files failed in {root}: {listing.stderr.decode('utf-8', 'replace').strip()}"
    paths = {root / os.fsdecode(name) for name in listing.stdout.split(b"\0") if name}
    # a tracked file deleted from the work tree, or a submodule, has no file here to read
    return sorted(path for path in paths if path.is_symlink() or path.is_file())


def flag_leaks(root: Path, flags: dict[str, bytes]) -> list[str]:
    """'<name> in <path>' for each flag written verbatim in a file a commit of `root` could publish."""
    leaks = []
    for path in repository_files(root):
        # a symlink is published as the text of its target, so that is what is read, never the target
        data = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        leaks += [f"{name} in {path.relative_to(root).as_posix()}" for name, flag in flags.items() if flag in data]
    return leaks


def test_the_flag_scan_reads_every_file_git_would_publish_and_nothing_it_ignores(tmp_path):
    """A directory nobody thought to list (examples/, .github/) is scanned all the same."""
    git = git_or_skip()
    canary = os.urandom(16).hex().encode()  # stands in for a flag
    files = {
        ".gitignore": b"ignored/\n.venv/\n*.log\n",
        "README.md": b"top level, tracked ",
        "docs/guide.md": b"tracked ",
        "examples/demo-run.jsonl": b"untracked and not ignored ",
        ".github/workflows/ci.yml": b"in a dot directory ",
        "ignored/notes.md": b"ignored ",
        ".venv/lib/site.py": b"ignored ",
        "run.log": b"ignored ",
    }
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(text + canary + b"\n")
    for args in (["init", "-q"], ["add", ".gitignore", "README.md", "docs/guide.md"]):
        subprocess.run([git, *args], cwd=tmp_path, env=git_env(), check=True, capture_output=True, timeout=60)
    publishable = [".gitignore", "README.md", "docs/guide.md", "examples/demo-run.jsonl", ".github/workflows/ci.yml"]
    assert sorted(flag_leaks(tmp_path, {"canary": canary})) == sorted(f"canary in {name}" for name in publishable)


def test_no_flag_is_written_in_plain_text_anywhere_in_the_repository():
    """Not in another file, and not in its own handout either: every challenge takes a step."""
    assert Path(__file__).resolve() in repository_files(), "git's file list for the repository misses this file"
    flags = {challenge_id(f): SOLVERS[challenge_id(f)](f).encode() for f in CHALLENGES}
    assert flag_leaks(REPO, flags) == []


EXECUTABLE_MAGIC = (
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\xfe\xed\xfa\xce", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal or Java class"),
)


def executable_problems(name: str, data: bytes, mode: int) -> list[str]:
    """Why `data`, or anything packed inside it, counts as an executable; [] if nothing does."""
    problems = [f"{name}: mode {mode:o} is executable"] if mode & 0o111 else []
    problems += [f"{name}: {kind} magic bytes" for magic, kind in EXECUTABLE_MAGIC if data.startswith(magic)]
    if data.startswith(b"PK\x03\x04"):  # look inside archives too, as unpacking them would
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                problems += executable_problems(f"{name}!{info.filename}", archive.read(info), info.external_attr >> 16)
    elif data.startswith(b"\x1f\x8b"):
        problems += executable_problems(f"{name}!gunzip", gzip.decompress(data), 0)
    return problems


def test_nothing_in_the_set_is_executable_or_a_symlink():
    problems = []
    for root, dirs, names in os.walk(PRACTICE):
        links = [name for name in dirs + names if (Path(root) / name).is_symlink()]
        problems += [f"{(Path(root) / name).relative_to(PRACTICE)}: a symlink" for name in links]
        for path in (Path(root) / name for name in names if name not in links):
            problems += executable_problems(str(path.relative_to(PRACTICE)), path.read_bytes(), path.stat().st_mode)
    assert problems == []


def test_each_handout_is_under_1_mb_and_the_whole_set_under_2_mb():
    sizes = {folder.name: sum(p.stat().st_size for p in files_under(folder)) for folder in CHALLENGES}
    assert {name: size for name, size in sizes.items() if size >= 1_000_000} == {}
    assert sum(p.stat().st_size for p in files_under(PRACTICE)) < 2_000_000


def test_the_wheel_ships_every_file_of_the_set_byte_for_byte(tmp_path):
    """`flightdeck practice` must work right after `pip install`, with no clone of the repository."""
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is not installed, and building the wheel needs it")
    build = subprocess.run(
        [uv, "build", "--wheel", "--offline", "--out-dir", str(tmp_path), str(REPO)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
    )
    if build.returncode != 0 and "network was disabled" in build.stderr:
        pytest.skip("uv cannot build the wheel offline here: the build backend is not in uv's cache")
    assert build.returncode == 0, f"uv build failed:\n{build.stderr}"
    (wheel,) = tmp_path.glob("*.whl")
    missing, changed, executable = [], [], []
    with zipfile.ZipFile(wheel) as archive:
        for path in files_under(PRACTICE):
            name = "ctf_flightdeck/practice/" + path.relative_to(PRACTICE).as_posix()
            try:
                info = archive.getinfo(name)
            except KeyError:
                missing.append(name)
                continue
            if archive.read(info) != path.read_bytes():
                changed.append(name)
            if (info.external_attr >> 16) & 0o111:
                executable.append(name)
    assert (missing, changed, executable) == ([], [], [])


def test_the_readme_says_how_to_play_and_that_honest_practice_uses_docker():
    readme = (PRACTICE / "README.md").read_text(encoding="utf-8")
    assert "flightdeck practice" in readme
    assert "host runtime" in readme and "docker runtime" in readme
    assert "tests/test_practice.py" in readme  # where the spoilers are
