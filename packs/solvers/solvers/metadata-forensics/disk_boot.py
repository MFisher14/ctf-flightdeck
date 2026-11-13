#!/usr/bin/env python3
"""Disk-image boot planner: which handout files are bootable disk images and how to boot them (B-131).

A handout that is a bootable disk set (PINK+ "PINK OS": `uefi_disk.img` plus `data.img` in a zip that
triage read as stego) holds its answer in what the booted system shows. This engine does the static
part at intake and stops where challenge code would run:

  * identifies every disk image from its structure (GPT, MBR, a bare FAT/NTFS/exFAT/ext volume,
    qcow2, VMDK, VHDX, VDI, VHD, ISO 9660 with its El Torito catalog): format, partition table,
    firmware, and which image boots;
  * writes the boot plan to `recon/boot/plan.json`: the networkless, read-only QEMU/OVMF container
    command and the QMP transport (ctf/diskboot.py), with the default observe script;
  * reports the screenshots of an earlier observe run (`recon/boot/vision-handoff.json`) as evidence
    that still needs a vision read.

It never boots anything: booting runs challenge code, so `python -m ctf disk-boot start` is the
operator's step, and reading what the screen shows is a vision hand-off. The result is `unsure`
(a human or vision step is open) whenever an image is found, `none` when there is none, and
`blocked` with the reason when the plan cannot be made.

Entry: ``solve(challenge_dir, profile) -> SolverResult`` (an intake ``run = "challenge"`` adapter).
Options (``--opt key=value``): ``firmware`` (auto | uefi | bios), ``memory_mb``, ``cpus``,
``machine`` (q35 | pc), ``drive_if`` (ide | virtio | scsi).
"""
from __future__ import annotations

import json
from pathlib import Path

ENGINE = "metadata_forensics.disk_boot"


def solve(challenge_dir, profile, *, firmware: str = "auto", memory_mb: int = 2048, cpus: int = 2,
          machine: str = "q35", drive_if: str = "ide", **_opts):
    """Identify the handout's disk images and write the boot plan; never boots."""
    from ctf import diskboot
    from ctf.result import Evidence, SolverResult

    challenge_dir = Path(challenge_dir)
    try:
        infos = diskboot.find_images(challenge_dir)
    except diskboot.BootError as e:
        return SolverResult(status="blocked", engine=ENGINE, notes=str(e))
    if not infos:
        return SolverResult(status="none", engine=ENGINE, notes="no disk image in the handout")

    evidence = [Evidence(kind="disk-image",
                         detail=f"{i.path}: {i.format}, table {i.table}, firmware {i.firmware}, {i.role} "
                                f"({i.size} bytes): {i.why}", path=i.path) for i in infos]
    try:
        plan = diskboot.plan(challenge_dir, infos, firmware=firmware, memory_mb=memory_mb, cpus=cpus,
                             machine=machine, drive_if=drive_if)
    except diskboot.BootError as e:
        return SolverResult(status="blocked", engine=ENGINE, evidence=evidence,
                            notes=f"disk image(s) found but no boot plan: {e}")
    out = Path(plan.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / diskboot.PLAN_FILE).write_text(json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8")
    rel_out = out.relative_to(challenge_dir.resolve()).as_posix()
    evidence.append(Evidence(kind="boot-plan",
                             detail=f"{plan.firmware} boot of {plan.images[0]['path']} in {plan.image_tag}, "
                                    f"no network, images read-only ({len(plan.images)} image(s) attached)",
                             path=f"{rel_out}/{diskboot.PLAN_FILE}"))
    notes = list(plan.notes)
    notes.append(f"next (operator): python -m ctf disk-boot start {challenge_dir} --reason '...'; then "
                 f"python -m ctf disk-boot observe {challenge_dir}; then python -m ctf disk-boot quit {challenge_dir}")

    handoff = out / diskboot.HANDOFF_FILE
    if handoff.is_file():
        try:
            seen = json.loads(handoff.read_text(encoding="utf-8"))
            shots = [s["file"] for s in seen.get("shots", [])]
            crops = list(seen.get("crops", []))
        except (OSError, ValueError, KeyError, TypeError) as e:
            notes.append(f"{rel_out}/{diskboot.HANDOFF_FILE} is unreadable ({type(e).__name__}: {e})")
        else:
            evidence.append(Evidence(kind="screens",
                                     detail=f"{len(shots)} screenshot(s) and {len(crops)} crop(s) of the booted "
                                            "system wait for a vision read (what is drawn is not read here)",
                                     path=f"{rel_out}/{diskboot.HANDOFF_FILE}"))
            notes.append("vision hand-off: read the screenshots listed in "
                         f"{rel_out}/{diskboot.HANDOFF_FILE}; a partial flag on screen is reported as drawn, "
                         "never completed")
    else:
        notes.append("no observe run yet: nothing has been booted")
    notes.append("a shipped client inside the image is not driven from the guest (it has no network): "
                 "python -m ctf client-replay harvest finds its User-Agent and URLs")
    return SolverResult(status="unsure", engine=ENGINE, evidence=evidence, notes="; ".join(notes))
