"""flightdeck's boot script for a python L1 engine. Never imported; the runner runs it as

    python3 -I _boot.py <engine file> <function> <challenge dir>

in the engine's workspace, a copy of the challenge (the challenge dir is "."), with
FLIGHTDECK_L1_RESULT naming the engine's result file: a new name, random in part, in the
workspace's .flightdeck/. It loads the engine file by path, calls function(Path(challenge
dir)) and writes the returned SolverResult there as JSON. An engine may also return a
plain dict in that shape, or None (a text-output engine that prints its findings): then no
file is written. If the engine raises, the traceback goes to stderr, no file is written,
and the exit status is 1.

What the engine prints is never its result. The engine reads the challenge's files and may
print what it read (debug output, a decoded layer); a line the challenge's author wrote
could pose as a result line, so the result travels apart from stdout. The file is created
new, never through a symlink (O_CREAT | O_EXCL | O_NOFOLLOW), in the folder opened before the
engine runs, so an engine that changes directory, or unpacks an archive over .flightdeck,
changes nothing; a challenge cannot know the name.

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
import os
import sys
import traceback
from pathlib import Path

ENGINE_MODULE = "__flightdeck_engine__"
RESULT_ENV = "FLIGHTDECK_L1_RESULT"


def main(argv):
    if len(argv) != 4:
        sys.stderr.write("usage: python3 -I _boot.py <engine file> <function> <challenge dir>\n")
        return 2
    engine_file, function, challenge_dir = argv[1:]
    sys.dont_write_bytecode = True
    target = os.environ.get(RESULT_ENV, "")
    if not os.path.isabs(target):
        sys.stderr.write("flightdeck: " + RESULT_ENV + " does not name the result file; the runner sets it\n")
        return 2
    try:
        folder = os.open(os.path.dirname(target), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        sys.stderr.write("flightdeck: cannot open the folder of the result file: " + str(exc.strerror) + "\n")
        return 2
    try:
        _use_this_flightdeck()
        solve = _load(Path(engine_file), function)
        result = solve(Path(challenge_dir))
        if inspect.iscoroutine(result):
            import asyncio

            result = asyncio.run(result)
        text = _json(result, function)
        if text is not None:
            _write(folder, os.path.basename(target), text)
    except BaseException:  # the engine's failure (SystemExit included): shown on stderr, no result
        traceback.print_exc()
        sys.stderr.flush()
        return 1
    finally:
        os.close(folder)
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


def _json(result, function):
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


def _write(folder, name, text):
    """Write the result file, new, in the folder opened at the start, never through a symlink."""
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder)
    with os.fdopen(fd, "w", encoding="ascii") as out:
        out.write(text + "\n")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
