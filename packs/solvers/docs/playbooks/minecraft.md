# Minecraft and game-world playbook

For a challenge whose answer is inside a game: a Minecraft world or server (category "Minecraft" on some
boards), or an Unreal Engine game handed out as files. Two halves, and only one is automated:

- **Scriptable (built, B-120):** anything that arrives as files. A world folder, a region file, a
  schematic, a `.pak`, a game executable. Also the one thing a live Minecraft server tells a client
  that has no account: its status.
- **Not automated:** playing. Joining a server, walking to a place, talking to an NPC, reading a sign
  that only exists on the live server. No headless client is built (see "Why there is no bot"). The
  fallback is the **player checklist** below: a person plays, the tools read what they capture.

Nothing here executes a game, a mod, a plugin or a handout binary.

## First moves

1. Read the brief. Does it hand out files, name a server, or both? Note the exact commands it mentions
   (`/something`), any coordinates, and whether screenshots are part of it.
2. Files in the handout: intake has already run the engines below on them
   (`recon/intake.json`, `triage.md`). Read those before running anything again.
3. A server address: run the status ping (no account, no login). Then decide who plays (the checklist).
4. Screenshots to match against a location: that is image-to-location work (B-113), not this lane. Do
   the metadata and stego checks from `docs/playbooks/stego.md`, describe each picture, and hand the
   in-game part to the player.

## Engines (verified CLIs)

Run every command from the ctf-tools checkout root with `.venv/bin/python` (or `.venv/bin/python -m ctf run <engine>`), with `CTF_EVENT` set to the event slug (`events/<slug>/event.toml`). The workdir comes from `ctf.paths`: `$CTF_WORKDIR`, else `~/ctf-work/<event>`; `.venv/bin/python -m ctf workdir` prints it, and `workspace/` on this page means it.

### A world folder: `solvers/toolkits/minecraft_world.py` (engine `toolkits.minecraft_world`)

```
.venv/bin/python solvers/toolkits/minecraft_world.py <world-folder-or-parent> [--json] [--budget S] [--no-deep]
.venv/bin/python -m ctf run toolkits.minecraft_world workspace/<id>-<slug> [--opt budget=120] [--opt report=out.json]
```

Give it the world folder (the one holding `level.dat`), a folder that contains worlds, one `.mca`, or
one NBT file (`.dat`, `.nbt`, `.schem`, `.schematic`, `.litematic`). It reads, cheapest first:
`level.dat`, `playerdata/`, `data/`, every other file (datapack functions, `server.properties`), then
every region file of every dimension, nearest the world spawn first.

What the lines mean:

- `FLAG [direct]`: the flag is whole in one stored string. `[component]`: it only appears once a text
  component is flattened (the game shows it whole; the file stores it in pieces). `[joined]`: it only
  appears when a sign's lines or a book's pages are put together. A joined hit is a candidate: check
  whether the pieces need a space or a different order before submitting.
- `sign`, `book`, `item-name`, `lore`, `custom-name`, `command`, `text-display`: every readable thing,
  with its dimension and block position. When there is no flag-format hit, **read these**: the answer
  is often a sentence, a coordinate or an encoded string on a sign.
- `orphaned chunk data (deleted or replaced in the world)`: the text was removed or edited in the game
  but its old chunk is still in the region file. A sign that "is not there any more" is found here.
- `anomaly`: a chunk stored in a slot that does not match its coordinates (moved by hand).
- `skipped`: named, never silent. `CPU budget spent` means part of the world was not read (files, or
  the rest of one region's chunks: the budget is read before each chunk is inflated): rerun with a
  larger `--budget` (`0` for no limit). LZ4-compressed chunks and Bedrock worlds are not decoded. A
  region whose slots point at the same sectors has them read once, and one region's chunks may inflate
  to 128 MiB in all; both are skips with a count.
- `dropped`: a cap cut a list (flags, text records, anomalies, skips). The count is given; the full
  JSON report has the rest of what was kept.

Map items (`data/map_*.dat`) are counted but their picture is not rendered: a flag drawn on a map needs
a map renderer or a look in the game.

### One region or one NBT file, in depth

```
.venv/bin/python solvers/toolkits/ffgame_anvil_semantics.py <r.X.Z.mca> --region-x X --region-z Z
.venv/bin/python solvers/toolkits/research_ff_nbt.py <file.dat|file.mca> [--kind nbt|mca]
```

`solvers/toolkits/ffgame_anvil_semantics.py` prints one region's chunks, block palettes, entity ids,
allocation slack and coordinate checks; `solvers/toolkits/research_ff_nbt.py` prints the whole NBT tree
of one file. Use them when the walker points at a region and you need everything in it.

### A live server, with no account: `solvers/toolkits/minecraft_netplay.py` (engine `toolkits.minecraft_netplay`)

```
.venv/bin/python -m ctf run toolkits.minecraft_netplay workspace/<id>-<slug> --opt host=<server> [--opt port=25565] [--opt favicon_out=icon.png]
.venv/bin/python solvers/toolkits/minecraft_netplay.py <server> [port] [--favicon-out icon.png]
```

One Server List Ping: the MOTD, the version string, the sampled player names, the mod list and the
server icon, each searched for the flag format. It is the handshake and the status request and nothing
else: **no login, no account, no chat**. The host must be in the event's `rules.live_service_scope`
and must not be the event platform; anything else is refused before a connection is opened (exit 4).
Loopback gets no exemption, and with no event set every host is refused. `--opt timeout=S` (default
10, at most 120) is one deadline for the connection attempts (to every address the host resolves to),
both sends and the whole reply, so a server that drips its reply cannot hold the engine. The one step
it does not bound is the name lookup, which has no timeout of its own: give an IP address if the
lookup hangs. Send the icon to the stego lane if nothing else turns up.

A server icon that does not decode (base64 with a stray character or no padding) never costs the
status: the MOTD, version, players and flags are reported as usual, with `favicon_error` in the
report and a note from the engine. An icon field that is not an icon at all is searched as text
(surface `favicon-text`).

Intake never runs this engine (it needs the network and a target you name).

## In-game work: the player checklist

When the answer needs someone in the world, a person plays and captures; do not improvise a client.
Before anyone connects, check the event rules for a clause on bots or automation and on how many
accounts may join, and record the answer in the challenge's `notes.md`.

The player captures, as text wherever possible:

1. **Chat and NPC dialogue.** The client writes all of it to `logs/latest.log` in its game folder. Copy
   that file into the challenge folder after the session: it is the single most useful capture.
2. **Signs:** both sides, all four lines, with the F3 coordinates of the sign.
3. **Books:** every page, title and author. Lecterns and chests included.
4. **Items:** the name and the lore (hover text) of anything named or enchanted oddly, and what
   container or mob it came from.
5. **Commands the brief names:** run each once, capture the full reply (it is in the log).
6. **Where things are:** F3 screenshot (coordinates, facing, biome, dimension) at every place the brief
   or a screenshot points to. A screenshot without F3 cannot be placed again.
7. **What the server sends:** a server resource pack is saved by the client under
   `server-resource-packs/` (`downloads/` on newer clients). Copy it: a zip of textures, sounds and language files that goes
   through the normal file sweep.

Then put the captures in the challenge folder and run the flag search and the decoders over them
(`.venv/bin/python -m ctf intake <id> --force`). Text on a sign that is not a flag is still a lead:
coordinates, a book cipher, a base64 line.

If the organisers publish the world, or the player can save it (single-player, or a server that allows
a world download), run the walker on it: it reads every sign and book at once, including removed ones.

## Why there is no bot

A headless client was tried once and never reached a server: the Microsoft sign-in failed on the Java
token step (the account had no Java edition entitlement). So whether an event's server accepts a bot at
all is untested, and none is built here. Human steps before this could be built:

- a Microsoft account that owns Minecraft Java edition, with the device-code sign-in tested before an
  event, never during one;
- an event whose rules allow an automated client, checked per event.

## Unreal Engine games (same lane): `solvers/toolkits/unreal_pak.py` (engine `toolkits.unreal_pak`)

```
.venv/bin/python solvers/toolkits/unreal_pak.py <Game.pak> --list                 # the file table
.venv/bin/python solvers/toolkits/unreal_pak.py <Game.pak> --extract-to out/      # unpack it
.venv/bin/python solvers/toolkits/unreal_pak.py <Game.pak> --key 0x<64 hex>       # an AES-encrypted pak
.venv/bin/python solvers/toolkits/unreal_pak.py <Game-Win64-Shipping.exe>         # literal pool of a binary
.venv/bin/python -m ctf run toolkits.unreal_pak workspace/<id>-<slug> [--opt aes_key=0x<64 hex>]
```

- **Archive:** pak versions 1 to 11, stored, zlib and gzip entries. Config files inside (`*.ini`,
  `*.json`) are searched for URLs and server settings: the game's server address is usually in
  `DefaultGame.ini` or `DefaultEngine.ini`.
- **Encrypted index or entries:** reported as blocked, naming the AES-256 key. The key is in the game
  executable; recovering it is reverse-lane work. A wrong key is detected (index SHA-1).
- **Not decoded, and named when met:** Oodle, LZ4, Zstd and custom compression; a frozen index; pak
  versions past 11; IoStore containers (`.utoc` / `.ucas`). The literal pool still runs on all of them.
  An IoStore container is a `skipped` row and a note; when nothing else in the handout gave a flag or
  a lead the engine is `blocked` on it (unpack it with a tool that reads `.utoc` / `.ucas`, then rerun).
- **Cooked assets** (`.uasset`, `.umap`, `.locres` ...) go through the literal pool: a UTF-16 flag or
  a URL in one is reported with the file.
- **A cut flag scan is said:** more than 256 flag-format hits in one file or entry, or a flag lead
  found 20,000 times, shows as `flag_scan_cuts` in the report and in the engine's notes.
- **An `error` row about compression blocks** ("more than its compression can need") is an entry
  whose blocks declare more stored bytes than a file of its size can compress to: a malformed or
  hostile archive. The entry is not read; look at it by hand. `skipped: CPU budget spent` can
  fall in the middle of one entry (the budget is read before each block): rerun with a larger
  `--budget`.
- **Literal pool:** on the executable or the game module it lists the flag format, URLs, every
  `/Script/<Module>` name, the module names that are not the engine's (`game_modules`), and the UTF-16
  literals stored next to the game module's name (`module_literals`, `endpoints`). In a C++ game the
  client/server protocol (paths such as `/v1/session`, header names, JSON keys) is usually right there.
  It is a reading aid: the checks the client makes on its own data still have to be reversed by hand.

Never run the game binary. A live game server is in scope only when the event profile says so, and
talking to it needs a client written for that challenge: no protocol driver is built for Unreal games.

## What is not built

- A headless Minecraft client (join, walk, read, chat). Blocker above.
- Screenshot-to-location matching (B-113).
- Bedrock worlds, LZ4 chunks, map-item rendering.
- IoStore, Oodle; a network play driver for Unreal games; other engines' containers (Unity,
  LevelImposter).
