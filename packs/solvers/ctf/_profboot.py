"""cProfile shim for `ctf show replay --cprofile` (B-210). Started as

    <python> -I ctf/intake/_guardboot.py --mode M -- ctf/_profboot.py OUT.prof -- <ctf/engines/_boot.py> [args...]

It runs <script> as __main__ in this same interpreter under cProfile and writes the stats to OUT.prof when the
script ends (a normal return, a SystemExit or an exception). It is a script, not the stdlib `-m cProfile`,
because that one puts the script's folder first on sys.path (ctf/intake/ would then shadow flat engine
imports such as `engines`); this shim changes sys.path not at all. Self-contained: with -I the checkout is
not on sys.path until the engine boot puts it there. Not imported by anything; not a CLI for people.
"""
import sys


def main(argv: list) -> int:
    if len(argv) < 3 or argv[1] != "--":
        print("_profboot: usage: OUT.prof -- <script> [args...]", file=sys.stderr)
        return 2
    out, target = argv[0], list(argv[2:])
    import cProfile
    import runpy
    sys.argv = target
    prof = cProfile.Profile()
    code = 0
    prof.enable()
    try:
        runpy.run_path(target[0], run_name="__main__")
    except SystemExit as e:
        if e.code is None:
            code = 0
        elif isinstance(e.code, int):
            code = e.code
        else:
            print(e.code, file=sys.stderr)
            code = 1
    finally:
        prof.disable()
        prof.dump_stats(out)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
