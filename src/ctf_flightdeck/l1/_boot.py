"""flightdeck's boot script for a python L1 engine. Never imported; the runner runs it as

    python3 -I _boot.py <engine file> <function> <challenge dir>

in the engine's workspace, a copy of the challenge (the challenge dir is "."). It loads the
engine file by path, calls function(Path(challenge dir)) and prints the returned
SolverResult as JSON on the last line of stdout (after a newline, so it is a line of its
own whatever the engine printed). An engine may also return a plain dict in that shape, or
None (a text-output engine that prints its findings). If the engine raises, the traceback
goes to stderr, nothing more is printed, and the exit status is 1.

-I keeps the challenge copy (the working directory) off sys.path, so a handout file named
like a module (json.py, base64.py) is never imported, and ignores PYTHON* variables. The
engine's own folder is put first on sys.path, as `python3 engine.py` would, so it can import
its helpers. `import ctf_flightdeck` loads the flightdeck this script belongs to, whichever
python3 runs it, so an engine can use ctf_flightdeck.l1.result and its schema always
matches the runner's. No bytecode is written (not into the pack, not into flightdeck).

Python 3.8 syntax, standard library only.
"""

import importlib.util
import inspect
import json
import sys
import traceback
from pathlib import Path

ENGINE_MODULE = "__flightdeck_engine__"


def main(argv):
    if len(argv) != 4:
        sys.stderr.write("usage: python3 -I _boot.py <engine file> <function> <challenge dir>\n")
        return 2
    engine_file, function, challenge_dir = argv[1:]
    sys.dont_write_bytecode = True
    try:
        _use_this_flightdeck()
        solve = _load(Path(engine_file), function)
        result = solve(Path(challenge_dir))
        if inspect.iscoroutine(result):
            import asyncio

            result = asyncio.run(result)
        line = _line(result, function)
    except BaseException:  # the engine's failure (SystemExit included): shown on stderr, no result
        traceback.print_exc()
        sys.stderr.flush()
        return 1
    if line is not None:
        sys.stdout.write("\n" + line + "\n")
    sys.stdout.flush()
    return 0


def _use_this_flightdeck():
    package = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "ctf_flightdeck", str(package / "__init__.py"), submodule_search_locations=[str(package)]
    )
    if spec is None or spec.loader is None:
        raise ImportError("cannot load flightdeck from " + str(package))
    module = importlib.util.module_from_spec(spec)
    sys.modules["ctf_flightdeck"] = module
    spec.loader.exec_module(module)


def _load(path, function):
    sys.path.insert(0, str(path.parent))  # the engine's folder; never the challenge dir
    spec = importlib.util.spec_from_file_location(ENGINE_MODULE, str(path))
    if spec is None or spec.loader is None:
        raise ImportError("cannot load " + str(path) + " as a python module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[ENGINE_MODULE] = module
    spec.loader.exec_module(module)
    solve = getattr(module, function, None)
    if not callable(solve):
        raise AttributeError(path.name + " has no function " + function)
    return solve


def _line(result, function):
    """The result as one line of ASCII JSON; None when the engine returned None."""
    if result is None:
        return None
    to_dict = getattr(result, "to_dict", None)
    if callable(to_dict):
        data = to_dict()
    elif isinstance(result, dict):
        data = result
    else:
        raise TypeError(function + "() returned " + type(result).__name__ + ", not a SolverResult")
    return json.dumps(data)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
