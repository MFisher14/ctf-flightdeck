"""Engines: manifests, routing, lint, coverage matrix, the runner (B-186, B-187).

    manifest   <module>.manifest.toml sidecars: schema, load, discover (docs/CONTRACTS.md section 6)
    layout     which modules are engines; the sys.path engines run with
    router     route a challenge to engines from their manifests
    lint       route lint (python -m ctf engines lint)
    generate   write inferred manifests for engines that lack one
    coverage   the generated docs/coverage/ENGINES.md matrix
    runner     resolve and run an engine (python -m ctf run, tools/ctfpy); ledger hook
    usage      real-use counts from the ledger
"""
