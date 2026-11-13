"""The pinned toolchain (B-188): images, assets, the per-lane environment, version notes, wheels.

    images     tools/images.toml: the pinned toolchain images (toolkit, tagged Sage, the sandbox and pwn
               images), a static Dockerfile lint, a content hash stamped as a label so an unchanged image
               is never rebuilt, the local status (`docker image inspect`, a read), the build plan and
               the in-image smoke checks
    assets     tools/assets.toml: wordlists and install folders that live outside the repo (rockyou,
               john's helper scripts, SecLists, Ghidra); resolved once, exported as variables
    lanes      the env-check a lane's agent runs first: every third-party module the lane's engines
               import, the binaries and assets it needs, the venv pins; and the exports for that lane
    versions   version notes in challenge files (SageMath 10.5, glibc 2.35, python:3.11, pins) and the
               tagged image that matches them
    wheels     the pre-provisioned wheelhouse for lanes with no network (every pin of requirements.txt)

Docs: docs/CONTRACTS.md section 37. CLI: `python -m ctf toolchain ...` (ctf/cli/toolchain.py).
The preflight doctor runs the asset and image checks (ctf/doctor.py, checks `assets`, `images`).
"""
