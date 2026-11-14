"""Programmatic Codex build lanes (B-179).

A batch of build work is written once as a backlog file (YAML or TOML). From it:

    backlog.load(path)            -> Backlog (validated: ids, owned files, dependencies)
    prompt.render(backlog, lane)  -> one self-contained prompt per lane; prompt.write_pack()
    checkout.setup(...)           -> one git checkout per lane on its own branch, .venv linked
    runner.run(...)               -> `codex exec` per lane inside the B-219 fence, own concurrency cap
    results.collect(...)          -> each lane's machine-readable result.json, checked against the branch
    results.integrate(...)        -> engine-id / basename / route / CAPABILITIES-key collision checks,
                                     then (on request) merge the lane branches and apply the entries

CLI: `python -m ctf lanes check|prompts|setup|run|status|integrate` (ctf/cli/lanes.py).
Runtime state lives under paths.lanes_root()/<batch>/, never in the repo. See docs/lanes.md.
"""
