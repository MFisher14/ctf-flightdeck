# Runbook: a challenge that is a bootable disk image (B-131)

For a handout that is a disk set (`*.img`, `*.iso`, `*.qcow2`, ...) whose answer is what the booted
system shows, or that ships its own client (a browser, a script) with a hard-coded User-Agent. The
interfaces are in `docs/CONTRACTS.md` section 55; the code is `ctf/diskboot.py` and
`ctf/clientreplay.py`.

Who does what:

| step | who | why |
|---|---|---|
| plan, harvest, observe, replay | an agent or the operator | static reads, QMP on a VM that is already up, GETs inside the event's scope |
| build the image, **start** the boot | the operator only | building pulls from the network; booting runs challenge code |
| read the screens | a person or a vision model | what is drawn is not text |
| open a URL the scope refuses | the player decides | an organizer host outside `rules.live_service_scope`, or the event platform |

## Once per machine (operator)

```sh
.venv/bin/python -m ctf toolchain lint                              # the Dockerfile's static checks
.venv/bin/python -m ctf toolchain build --apply --only qemu-boot    # builds ctf-qemu-boot:1
.venv/bin/python -m ctf toolchain smoke qemu-boot                   # qemu, socat and the OVMF files are there
```

The image has never been built by the build work (no builder builds or pulls images). The first build
is the check that Debian still ships `/usr/share/OVMF/OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd`: the
Dockerfile fails there if not.

## 1. Plan (no boot)

```sh
.venv/bin/python -m ctf disk-boot plan workspace/<id>
```

Prints each image (format, partition table, firmware, which one boots) and writes
`workspace/<id>/recon/boot/plan.json`: the `docker run` line, the QEMU line and the observe script.
Intake writes the same plan by itself (engine `metadata_forensics.disk_boot`). Options when the
default does not come up: `--firmware bios`, `--machine pc`, `--drive-if virtio|scsi`, `--memory-mb`.

## 2. The shipped client, offline

```sh
.venv/bin/python -m ctf client-replay harvest workspace/<id>
```

Reads every file as data, the raw images included, and lists the custom User-Agent constants and the
URLs beside them. Nothing is contacted.

## 3. Start the boot (operator, at a terminal)

```sh
.venv/bin/python -m ctf disk-boot start workspace/<id> --reason "look at the desktop"
```

It shows you the exact `docker run` command it will run and asks you to type the challenge folder's
name: read the command first (one `-v` of the folder `:ro`, one of the out folder, `--network none`,
no `--privileged`). It refuses when it is not run from an interactive terminal, when `plan.json` is
not exactly what `plan` writes for this folder now (edited by hand, made for another folder, or the
images changed since: re-plan), when the image is not built, or when a session is already recorded.
The ledger gets a `diskboot.start` record with the outcome (`started`, `failed`, or `unknown` when
docker did not return: then look for the container by the name the error prints). The guest has no
network: the container runs `--network none` and QEMU `-nic none`. The handout is mounted read-only
and QEMU runs with `-snapshot`.

On Linux the container user (uid 10001) must be able to write the out folder
(`workspace/<id>/recon/boot`); on macOS Docker Desktop maps it.

## 4. Observe

```sh
.venv/bin/python -m ctf disk-boot observe workspace/<id>                    # the plan's script
.venv/bin/python -m ctf disk-boot observe workspace/<id> --script steps.json
```

A script is a JSON list of steps:

```json
[{"wait": 45}, {"shot": "desktop"}, {"key": "meta_l-d"}, {"type": "startx\n"},
 {"mouse": [640, 400]}, {"click": "left"},
 {"burst": {"name": "wall", "count": 30, "interval": 1.0}}]
```

- `key` takes QEMU qcodes joined by `-` (`ctrl-alt-f2`, `ret`, `esc`, `meta_l`); `type` types on a US
  layout. A guest with another layout (PINK OS was QWERTZ) needs `key` steps for the keys that differ.
- `mouse` parks the pointer top-left and moves relatively: exact only when the guest moves it 1:1.
- `burst` is for animations: identical frames are dropped, and when only a small region changes it is
  cropped out of each distinct frame into `recon/boot/crops/`.

Output: `recon/boot/shots/*.png`, `recon/boot/crops/*.png`, `recon/boot/vision-handoff.json`.

## 5. Read the screens (vision)

Open the files `vision-handoff.json` lists. Report what is drawn literally. A partial flag (PINK OS
drew `PINK{W0w,_P1nk+_0S_1s`, one glyph at a time) is a fragment: write it down as drawn and do not
complete it. The other part is found, not guessed.

## 6. Replay the client's User-Agent (network, inside the scope)

```sh
.venv/bin/python -m ctf client-replay run workspace/<id> --challenge-id <id> --head 'PREFIX{first_part'
```

Each client URL the event's scope allows, and each of its first-level links, is fetched once normally
and once with the shipped User-Agent, and the replies are compared. `--head` is a literal first part
(from step 5): it is joined to a literal tail the replay receives only when the two are exactly one
flag. A URL the scope guard refuses is listed with its reason and never fetched; whether to open it
by hand with that User-Agent is the player's decision. At PINK+ the page that answered the client was
on the event platform's own host, which the guard never contacts, so that last request was the
player's.

The notes carry the submit gate's count for the challenge. When it says STOP, stop.

## 7. End the boot

```sh
.venv/bin/python -m ctf disk-boot quit workspace/<id>
```

Asks QEMU to exit over QMP; the container (started `--rm`) goes with it. The harness never stops or
removes a container itself. If the VM no longer answers, the error names the container
(`ctf-boot-<12 hex>`); remove that one container by that exact name, then delete
`recon/boot/session.json`.
