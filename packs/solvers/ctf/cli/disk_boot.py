"""ctf disk-boot: boot a challenge's disk images networkless and look at the screen (B-131).

    python -m ctf disk-boot plan <challenge_dir> [--out DIR] [--firmware auto|uefi|bios]
        [--memory-mb N] [--cpus N] [--machine q35|pc] [--drive-if ide|virtio|scsi] [--script FILE] [--json]
    python -m ctf disk-boot start <challenge_dir> --reason R [--out DIR] [--event SLUG]     # the operator's
    python -m ctf disk-boot observe <challenge_dir> [--out DIR] [--script FILE] [--qmp unix:PATH|tcp:127.0.0.1:PORT]
    python -m ctf disk-boot quit <challenge_dir> [--out DIR]

`plan` identifies the images and writes the boot plan (recon/boot/plan.json); it runs nothing.
`start` boots the plan in the ctf-qemu-boot container. Booting runs challenge code, so it is the
operator's step: it shows the person at an interactive terminal the exact `docker run` command and
asks them to type the challenge folder's name, and no flag stands in for that. A plan.json that is
not what `plan` writes for the folder now (edited, or the folder changed) is refused. `observe` drives the booted VM over QMP (the session `start`
recorded, or `--qmp` for a QEMU started by hand) with an observe script and writes PNG screenshots,
crops of what animates and `vision-handoff.json`: reading the screen is a vision step. `quit` asks
QEMU to exit over QMP and retires the session. Exit status 0, 2 on an error (named), 3 when `start`
was refused because no person confirmed it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HELP = "plan, start (operator only), observe and quit a networkless boot of a challenge's disk images"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sp = parser.add_subparsers(dest="action", required=True)

    def common(p):
        p.add_argument("challenge_dir")
        p.add_argument("--out", help="output folder (default <challenge_dir>/recon/boot)")

    pl = sp.add_parser("plan", help="identify the images and write the boot plan; runs nothing")
    common(pl)
    pl.add_argument("--firmware", default="auto", choices=("auto", "uefi", "bios"))
    pl.add_argument("--memory-mb", type=int, default=2048)
    pl.add_argument("--cpus", type=int, default=2)
    pl.add_argument("--machine", default="q35", choices=("q35", "pc"))
    pl.add_argument("--drive-if", default="ide", choices=("ide", "virtio", "scsi"))
    pl.add_argument("--script", help="a JSON observe script to store in the plan (default: wait, shot, burst)")
    pl.add_argument("--json", action="store_true")
    st = sp.add_parser("start", help="boot the plan (the operator's step: interactive confirmation)")
    common(st)
    st.add_argument("--reason", required=True, help="why this image is booted (goes into the ledger)")
    st.add_argument("--event", help="event slug for the ledger record (default: CTF_EVENT)")
    ob = sp.add_parser("observe", help="drive the booted VM over QMP and collect screenshots for a vision read")
    common(ob)
    ob.add_argument("--script", help="a JSON observe script (default: the plan's)")
    ob.add_argument("--qmp", help="unix:PATH or tcp:127.0.0.1:PORT of a QEMU started by hand (default: the session)")
    ob.add_argument("--guest-out", help="the out folder as that QEMU names it (default with --qmp: the out folder)")
    ob.add_argument("--event", help="event slug, for the flag prefixes named in the hand-off (default: CTF_EVENT)")
    ob.add_argument("--json", action="store_true")
    qt = sp.add_parser("quit", help="ask the session's QEMU to exit over QMP and retire the session")
    common(qt)


def _out(args) -> Path:
    return Path(args.out).resolve() if args.out else Path(args.challenge_dir).resolve() / "recon" / "boot"


def _read_script(path: str):
    from .. import diskboot
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise diskboot.BootError(f"{path}: not a readable JSON observe script ({type(e).__name__}: {e})") from e


def _load_plan(out: Path):
    from .. import diskboot
    p = out / diskboot.PLAN_FILE
    try:
        return diskboot.BootPlan.from_dict(json.loads(p.read_text(encoding="utf-8")))
    except FileNotFoundError:
        raise diskboot.BootError(f"no boot plan at {p}: run `python -m ctf disk-boot plan` first") from None
    except (OSError, ValueError) as e:
        raise diskboot.BootError(f"{p}: unreadable boot plan ({type(e).__name__}: {e})") from e


def _profile(slug: str | None):
    from .. import event
    return event.load(slug) if slug else event.current()


def run(args: argparse.Namespace) -> int:
    from .. import diskboot, event
    out = _out(args)
    try:
        if args.action == "plan":
            script = _read_script(args.script) if args.script else None
            plan = diskboot.plan(args.challenge_dir, out_dir=out, firmware=args.firmware,
                                 memory_mb=args.memory_mb, cpus=args.cpus, machine=args.machine,
                                 drive_if=args.drive_if, script=script)
            out.mkdir(parents=True, exist_ok=True)
            (out / diskboot.PLAN_FILE).write_text(json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8")
            if args.json:
                print(json.dumps(plan.to_dict(), indent=2))
                return 0
            for i in plan.images:
                print(f"image  {i['path']}: {i['format']}, table {i['table']}, firmware {i['firmware']}, "
                      f"{i['role']}: {i['why']}")
            print(f"plan   {out / diskboot.PLAN_FILE} ({plan.firmware} boot in {plan.image_tag}, no network)")
            for n in plan.notes:
                print(f"note   {n}")
            print(f"next   python -m ctf disk-boot start {args.challenge_dir} --reason '...'   (the operator)")
            return 0
        if args.action == "start":
            plan = _load_plan(out)
            cdir = Path(args.challenge_dir).resolve()
            if Path(plan.challenge_dir).resolve() != cdir or Path(plan.out_dir).resolve() != out:
                raise diskboot.BootError(f"{out / diskboot.PLAN_FILE} is a plan for {plan.challenge_dir} with out "
                                         f"folder {plan.out_dir}, not for {cdir} and {out}: re-plan with "
                                         "`python -m ctf disk-boot plan`")
            try:
                profile = _profile(args.event)
            except event.EventError as e:
                raise diskboot.BootError(f"no event for the boot's ledger record: {e} (set CTF_EVENT or "
                                         "pass --event)") from e
            diskboot.check_plan(plan, None)                 # before the person is asked, not after
            try:
                approval = diskboot.approve_interactive(plan, args.reason)
            except PermissionError as e:
                print(f"ctf disk-boot: {e}", file=sys.stderr)
                return 3
            session = diskboot.start(plan, approval, profile=profile)
            print(f"started {session['container']} ({session['image']}); next: python -m ctf disk-boot observe "
                  f"{args.challenge_dir}")
            return 0
        if args.action == "observe":
            try:
                prefixes = list(_profile(args.event).flag.prefixes)
            except event.EventError as e:
                prefixes = []
                print(f"ctf disk-boot: no event profile ({e}): the hand-off names no flag prefix", file=sys.stderr)
            if args.qmp:
                script = _read_script(args.script) if args.script else list(diskboot.DEFAULT_SCRIPT)
                qmp = diskboot.QMP.connect(args.qmp)
                guest_out = args.guest_out
            else:
                plan = _load_plan(out)
                session = diskboot.load_session(out, args.challenge_dir)
                script = _read_script(args.script) if args.script else plan.script
                qmp = diskboot.connect_session(session)
                guest_out = args.guest_out or session.get("guest_out") or plan.guest_out
            with qmp:
                obs = diskboot.observe(qmp, script, out, guest_out=guest_out, flag_prefixes=prefixes)
            if args.json:
                print(json.dumps(obs.to_dict(), indent=2))
                return 0
            print(f"{len(obs.shots)} screenshot(s) in {out / 'shots'} ({obs.duplicates_dropped} identical frame(s) dropped)")
            for a in obs.animated:
                print(f"animated  burst {a['name']!r}: region {a['box']}" + ("" if a["cropped"] else " (most of the screen: not cropped)"))
            if obs.crops:
                print(f"{len(obs.crops)} crop(s) of the animated region in {out / 'crops'}")
            print(f"vision hand-off: {out / obs.handoff} (what is drawn is read by a person or a vision model; "
                  "a partial flag is reported as drawn, never completed)")
            return 0
        if args.action == "quit":
            session = diskboot.end_session(out, challenge_dir=args.challenge_dir)
            print(f"asked {session.get('container')} to exit; session retired")
            return 0
    except diskboot.BootError as e:
        print(f"ctf disk-boot: {e}", file=sys.stderr)
        return 2
    return 2
