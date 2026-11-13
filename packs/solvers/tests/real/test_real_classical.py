#!/usr/bin/env python3
"""solvers/common/classical.py on the classical-cipher challenges of Huntress 2024
(docs/toolkits/real-data.md).

  .venv/bin/python tests/real/test_real_classical.py

Three real challenges whose answer the write-up repository states:

  Cattle (warmups)              a COW program, a file of the repository: needs the cache
                                (challenges/_realdata/classical/cattle; that one part is skipped without it)
  No need for Brutus (crypto)   a Caesar text quoted in the challenge description
  Mystery (warmups)             an Enigma text and its settings, quoted in the description

The two quoted texts are short public challenge text and are written out below, so those parts
run everywhere. Source: github.com/ThisGuyNeedsABeer/Huntress-CTF-2024, the solve.txt of each.
"""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parent.parent))       # tests/, last: for loadclock only
import common_d as C                    # noqa: E402
import loadclock                        # noqa: E402  (tests/loadclock.py)
from common_d import check, timed       # noqa: E402
import classical                        # noqa: E402

CLI = C.REPO / "solvers" / "common" / "classical.py"
BRUTUS = "squiqhyiiycfbudeduutvehrhkjki"
BRUTUS_PLAIN = "caesarissimplenoneedforbrutus"                 # the write-up's reading; its MD5 in flag{} is the flag
BRUTUS_FLAG = "flag{c945bb2173e7da5a292527bbbc825d3f}"
MYSTERY = """Someone sent this to me...
such enigma, such mystery:

rkenr wozec gtrfl obbur bfgma fkgyq ctkvq zeucz hlvwx yyzat zbvns kgyyd sthmi vsifc ovexl zzdqv slyir nwqoj igxuu kdqgr fdbbd njppc mujyy wwcoy

Settings as below:
3 Rotor Model
Rotor 1: VI, Initial: A, Ring A
Rotor 2: I, Initial: Q, Ring A
Rotor 3: III, Initial L, Ring A
Reflector: UKW B
Plugboard: BQ CR DI EJ KW MT OS PX UZ GH
"""
MYSTERY_PLAIN = "MESSAGEWRAPPEDINLIGHTHIDDENDEEPEROUTOFSIGHTLOCKINGITMORETIGHTANYWAYYOURFLAGISHEREFLAGFDFEABCACBEBFBADAEFBECCAADDDBAFEZZZ"
MYSTERY_FLAG = "flag{fdfeabcacbebfbadaefbeccaadddbafe}"
CATTLE_FLAG = "flag{6cd6392eb609c6ae4c332ef6a321d9dd}"                # warmups/cattle_COMPLETED/flag.txt


def cli(*args):
    return subprocess.run([sys.executable, str(CLI), *[str(a) for a in args]], capture_output=True, text=True, timeout=120)


def test_brutus():
    # SH-10: crack()'s 2 s budget (time.perf_counter) and the 3 s bound count CPU seconds of this process
    # (tests/loadclock): under the suite's load the bound read 5.83 s of wall time, and a wall budget that
    # runs out early would drop readings. Work over either still fails.
    with loadclock.cpu_clock():
        got, took = loadclock.cpu_seconds(classical.crack, BRUTUS, None, None, 2.0)
    check("2024 No need for Brutus: the best-ranked reading of the 29 letters is the write-up's plaintext, by caesar16",
          got and got[0][1].startswith("caesar16") and got[0][2] == BRUTUS_PLAIN and got[0][0] == "score", got[:2])
    check("2024 No need for Brutus: the flag the challenge asks for is the MD5 of that reading (the last step is the question's own rule)",
          "flag{" + hashlib.md5(got[0][2].encode()).hexdigest() + "}" == BRUTUS_FLAG)
    check("2024 No need for Brutus: under 3 s of CPU", took < 3.0, round(took, 2))
    check("a reading ranked by letter statistics is never an answer: solve_set gives None for a text with no pattern match",
          classical.solve_set([{"qid": "flag", "id": "flag", "question": "Submit the original plaintext hashed with MD5.",
                                "answer_format": {"kind": "exact_text"}}], {"cipher.txt": BRUTUS.encode()}, {}) in ({"flag": None}, {}, None))


def test_mystery():
    kw = classical.enigma_settings(MYSTERY)
    check("2024 Mystery: the settings are read out of the challenge's own words",
          kw == {"rotors": ("VI", "I", "III"), "reflector": "B", "rings": "AAA", "start": "AQL", "plugboard": "BQ CR DI EJ KW MT OS PX UZ GH", "assumed": []}, kw)
    kw.pop("assumed")
    cipher = next(ln for ln in MYSTERY.splitlines() if ln.startswith("rkenr"))
    plain = classical.letters(classical.enigma(cipher, **kw)).upper()
    check("2024 Mystery: the simulator's output is the write-up's message, letter for letter", plain == MYSTERY_PLAIN, plain[:60])
    check("2024 Mystery: the flag is the 32 letters after FLAG in it", "flag{" + plain.split("FLAG", 2)[2][:32].lower() + "}" == MYSTERY_FLAG)
    tmp = Path(tempfile.mkdtemp(prefix="test_real_classical_")) / "mystery.txt"
    tmp.write_text(MYSTERY)
    out = cli(tmp, "--enigma")
    check("2024 Mystery: `classical.py <prompt> --enigma` prints the settings it read and the message", out.returncode == 0
          and "rotors=VI-I-III" in out.stdout and "start=AQL" in out.stdout and MYSTERY_PLAIN in out.stdout, out.stdout[:300] + out.stderr[-200:])
    out = cli(tmp, "--seconds", "1")
    check("2024 Mystery: without the switch the identification line says the text states Enigma settings", "states Enigma settings" in out.stdout, out.stdout[:300])
    check("settings that are not stated are listed as assumed, and a text with no rotors is no settings",
          sorted(classical.enigma_settings("Rotors: II IV V\nStart: X Y Z")["assumed"]) == ["plugboard=none", "reflector=B", "rings=AAA"]
          and classical.enigma_settings("the quick brown fox") is None)


def test_cattle():
    p = C.fetch_d.path("classical", "cattle")
    if p is None:
        print("note the Cattle part is skipped: no cache (run tests/real/fetch_d.py)")
        return
    code = p.read_text()
    out, took = timed(classical.cow, code)
    check("2024 Cattle: the COW program prints the write-up's flag", out == CATTLE_FLAG.encode(), out)
    check("2024 Cattle: under 2 s", took < 2.0, round(took, 2))
    r = cli(p, "--seconds", "1")
    check("2024 Cattle: the command's first line is the program's output", r.returncode == 0 and r.stdout.splitlines()[0].split() == ["KEYLESS", "cow", CATTLE_FLAG], r.stdout[:200])
    check("ordinary text and a Brainfuck program are not COW", classical.cow("the cow says moo and MOO and moo again today ok") is None
          and classical.cow("++++++++[>++++++++<-]>+.") is None)


def main() -> int:
    for t in (test_brutus, test_mystery, test_cattle):
        try:
            t()
        except Exception as e:      # noqa: BLE001
            check(f"{t.__name__} ran to its end", False, f"{type(e).__name__}: {e}")
    return C.finish("tests/real/test_real_classical.py")


if __name__ == "__main__":
    sys.exit(main())
