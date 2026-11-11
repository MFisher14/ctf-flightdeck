"""L1 solver packs: the player's no-model solvers, routed to a challenge and run sandboxed.

- result.py: `SolverResult`, what every engine reports (stdlib only, so an engine can
  import it under any python3).
- manifest.py: the sidecar `<anything>.manifest.toml` that describes one engine.
- router.py: which engines a challenge reaches, and why.
- runner.py: runs engines, each in its own copy of the handout.
- importer.py: wraps a folder of plain scripts with generated manifests.
- cli.py: `flightdeck l1 list | route | run | import`.

This file imports nothing on purpose: the boot script that runs a python engine (_boot.py)
makes this package importable for the engine, and the engine should load result.py and
nothing heavier.
"""
