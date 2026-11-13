# Mobile playbook (CSCTF 2026)

Android/iOS artifacts: APK, AAB, IPA, and the runtimes inside them (Dalvik dex, native
`.so`, Unity IL2CPP, React-Native Hermes, Flutter/Dart AOT, Xamarin/.NET). The flag is
`csctf{...}` / `chronos{...}` / `flag{...}` and almost always lives **inside the shipped
file** — in a resource, a string pool, a native lib, a keystore, or computed by the app's
own bytecode. Everything the engines here do is **static** (plain-Python readers, no
`androguard`/`aapt`).

> **One hard rule (player's standing preference + AGENTS.md):** an APK is an untrusted
> archive. *Decompiling* it statically (jadx/apktool) is fine on the Mac; **running or
> emulating** the app or its native code is Docker-only. Never execute an extracted `.so`,
> dex, or script on the host — copy it into `tools/sandbox.py`.

Setup for every run:

```sh
cd <ctf-tools checkout>                   # every command on this page runs from the checkout root
export CTF_EVENT=<event slug>             # the event profile, events/<slug>/event.toml
.venv/bin/python -m ctf workdir --create  # the workdir (ctf.paths): $CTF_WORKDIR, else ~/ctf-work/<event>
PY=.venv/bin/python
CH="$($PY -m ctf workdir)/<id>-<slug>"   # the challenge folder; its files are in $CH/files/
```

---

## First moves (the moment you open it)

1. `./csctf check <id>` — if the team already solved it, stop.
2. Identify the container, don't trust the extension: `file *` and `unzip -l app.apk | head`.
   APK/AAB/IPA/JAR are all ZIP (`PK\x03\x04`). The tells:
   - `classes.dex` + compiled `AndroidManifest.xml` → **APK**
   - `base/`, `BundleConfig.pb`, `*.pb` → **AAB** (Android App Bundle)
   - `Payload/<App>.app/` + a Mach-O → **IPA** (iOS)
   - `assets/bin/Data/Managed/Metadata/global-metadata.dat` + `lib*/libil2cpp.so` → **Unity IL2CPP**
   - `assets/index.android.bundle` / `main.jsbundle` → **React Native** (often Hermes bytecode)
   - `lib*/libapp.so` + `libflutter.so` → **Flutter/Dart AOT**
   - `assemblies/*.dll` or `assemblies.blob`/`XABA`/`XALZ` → **Xamarin/.NET (MAUI)**
3. Run the triage engines (triage already routes mobile here):
   ```sh
   $PY solvers/mobile-android/apk_resources.py app.apk    # manifest + resources + ELF/str
   $PY solvers/mobile-android/apk_facts.py     app.apk    # package facts, each plain/unsure
   ```
4. `grep -aobR 'csctf{\|chronos{\|flag{' .` across extracted members — many mobile flags are a
   plaintext run that `codec_search` (and a raw grep) find immediately.

---

## Engine CLIs

All verified in-repo; run as `$PY solvers/mobile-android/<mod>.py <args>`.

### APK structure, manifest & resources
```sh
$PY solvers/mobile-android/apk_resources.py app.apk
#   prints each compiled XML (AndroidManifest.xml, res/xml/*) as an element tree, every
#   resources.arsc string/int/bool value (e.g. string/puzzle_codec = "xor"), ELF string
#   counts for native libs, and expands .ab/tar/gz members. Pure bytes, no aapt/jadx.

$PY solvers/mobile-android/apk_facts.py app.apk
#   prints package, versionCode/Name, min/target SDK, permissions, every component with its
#   exported flag + intent-filters (scheme/host/port/path = deep links), launcher activity,
#   allowBackup/debuggable/cleartext, meta-data, and the signing cert SHA-256/SHA-1/MD5 +
#   subject/issuer/serial. Each line is tagged `plain` or `unsure`. Use for "what is the
#   package / exported activity / deep-link host / signing fingerprint" questions.
```

### Android backup (.ab) and app databases (B-085; intake runs it on any .ab or WAL)
```sh
$PY solvers/mobile-android/android_backup_sqlite.py backup.ab [--password P] [--out DIR]
#   unwraps the .ab (encrypted: needs --password, else a named BLOCKED), pairs every *.db with its
#   own -wal/-journal, recovers rows only a stale/superseded WAL frame or journal page holds,
#   diffs the main file against the WAL view (edited/withdrawn messages), and decodes BLOB cells
#   (zlib/gzip/raw deflate/protobuf fields/UTF-16, then embedded base64, then the codec graph).
#   Engine form: python -m ctf run mobile_android.android_backup_sqlite <challenge_dir>
```

### Deobfuscation (R8 / ProGuard / DexGuard `mapping.txt`)
```sh
$PY solvers/mobile-android/proguard_mapping.py mapping.txt      # or the APK if it ships one
#   prints "classes N  members N" and the class map (original <- obfuscated). Parses the
#   retrace grammar into a bidirectional class/method/field index. Answers "what is the
#   original name of a.b.c" / "what was com.example.X renamed to".
```

### Keystores & app secrets
```sh
$PY solvers/mobile-android/keystores.py app.apk [password ...]
#   finds PKCS12/JKS/JCEKS/BKS stores in the APK and prints each SECRET entry
#   (format, alias, value). Tries the passwords you pass, then usual ones
#   (changeit/android/password/""). NEVER brute-forces — a store that opens with none is
#   skipped. Where an app "uses the Keystore" to hide a token/data-key, it surfaces here.
```

### Bundles & runtimes — per **extracted member** (not the whole APK)
`app_bundles.py` reads ONE file you've unzipped out (a `classes.dex`, `libapp.so`,
`index.android.bundle`, a `.dll`, a Mach-O):
```sh
unzip -o app.apk -d app_x            # extract first
$PY solvers/mobile-android/app_bundles.py app_x/assets/index.android.bundle
#   detects the member kind and prints: Hermes bytecode strings/object-literals (RN),
#   JS-bundle literals, dex static-field values + per-method loaded strings, .NET #US user
#   strings and unpacked XALZ/XABA assemblies, native ELF/Mach-O/Dart-AOT printable runs,
#   and any flag sitting under a single-byte XOR/ADD. Run it on each interesting member.
```

### Unity IL2CPP (recon only)
```sh
$PY solvers/toolkits/il2cpp.py app_x/assets/bin/Data/Managed/Metadata/global-metadata.dat
#   prints metadata version, string-literal count, byte-exact string LITERALS (PLAIN), and
#   type/method/field NAMES (marked UNSURE — author labels). Pass --json for the full dump.
#   RECON ONLY: literals/version/counts are byte-exact; the flag itself is returned None —
#   you read it out of the literals yourself. A flag in literals is the usual IL2CPP win.
```

### Library-only readers (no CLI — import or let triage drive them)
- **`apk_container.py`** — reads data an APK hides where flat scans don't reach: a
  non-standard **APK Signing Block** ID-value payload (base64/hex/zlib/gzip) and ZIP entries
  the central directory **hides or misdescribes**. It runs automatically inside
  `codec_search` when nothing else found a code; no standalone CLI.
- **`dex_chain_codec.py`** — an offline **Dalvik interpreter** for a flag the app *computes*
  at runtime: a dex method assembles the flag through a chain of long/int transforms from a
  seed, surrounded by decoy methods that are never called. Python API (no CLI):
  ```sh
  $PY -c 'import sys,zipfile; sys.path.insert(0,"solvers/mobile-android"); import dex_chain_codec as d; \
          z=zipfile.ZipFile("app.apk"); f={i.filename:z.read(i) for i in z.infolist()}; \
          print(d.analysis_codes(f))'
  ```
  It is anchored to the Huntress `ANS-[0-9A-F]{16}` alphabet, so on CSCTF treat it as the
  **technique + template** for a computed-flag dex: read its interpreter trace, or adapt the
  anchor to `csctf{...}`. Use it when strings/jadx show the flag is built, not stored.

---

## Docker & host tools

### Host — static decompile only (never detonation)
These parse the APK without running it; good for reading Java/Smali and finding the flag
logic. Installed at `/opt/homebrew/bin`:
```sh
jadx -d app_jadx app.apk            # decompiled Java + resources; grep it for csctf{/chronos{
apktool d -o app_apktool app.apk    # smali + decoded AndroidManifest + resources
grep -arn 'csctf{\|chronos{\|flag{' app_jadx app_apktool
```
Do **not** install an emulator and run the app on the Mac, and do **not** `dlopen`/execute an
extracted native lib locally.

### Sandbox (`csctf-sandbox:2`) — for native members and anything that must be run
Copy the member in with `--in` and reference it as `{in}`; container is `--network none`,
read-only root, caps dropped:
```sh
$PY tools/sandbox.py run --in app_x/lib/arm64-v8a/libil2cpp.so rabin2 -z {in}   # strings
$PY tools/sandbox.py run --in app_x/lib/arm64-v8a/libapp.so     rabin2 -I {in}  # bin info
$PY tools/sandbox.py run --in classes.dex                       strings -n 6 {in}
$PY tools/sandbox.py run --in app.apk                           binwalk {in}
$PY tools/sandbox.py run --in app.apk                           7z l {in}
$PY tools/sandbox.py run --in resource.png                      exiftool {in}
```
Sandbox carries: `r2`/`rabin2`/`rasm2`/`rafind2` (radare2 + **r2ghidra `pdg`** decompiler),
`strings`, `objdump`, `readelf`, `binwalk`, `7z`, `yara`, `exiftool`, `file`, `python3 -I`.
For deep native-arm64 disassembly of a `.so`/Mach-O, use `r2` here and the
**reverse-engineering playbook** (ghidra/radare2). `jadx`/`apktool` are **not** in the
sandbox — they're host decompilers, which is fine because they don't execute the app.

---

## Techniques → engines (CSCTF-relevant)

| What you suspect | Do this |
| --- | --- |
| Flag is a plaintext string in a resource/asset | `grep -aobR`, `apk_resources.py`, jadx grep |
| Flag/secret in `resources.arsc` or a hidden `res/xml` | `apk_resources.py` |
| Answer is a manifest/package fact (deep link, exported comp, signing hash) | `apk_facts.py` |
| Class/method names obfuscated, `mapping.txt` provided | `proguard_mapping.py` |
| App "uses the Android Keystore" to hide a token | `keystores.py` |
| Hidden in APK **Signing Block** or an unreferenced/misdescribed ZIP entry | `apk_container.py` (auto via `codec_search`) |
| React-Native / Hermes bundle | extract `index.android.bundle` → `app_bundles.py` |
| Xamarin / .NET MAUI (`assemblies.blob`, XALZ) | extract member → `app_bundles.py` |
| Unity game, C# compiled to native | `il2cpp.py` on `global-metadata.dat`; `rabin2 -z` on `libil2cpp.so` |
| Flutter/Dart AOT (`libapp.so`) | `app_bundles.py` (native/Dart string objects); `rabin2 -z` in sandbox |
| Flag **computed** by dex at runtime, with decoys | `dex_chain_codec.analysis_codes(...)` / read the interpreter trace |
| Single-byte XOR/ADD over a code in a `.so`/dex | `app_bundles.py` (reports it); or the crypto/warmups engines |
| Deep native logic (arm64/Mach-O) | `r2`+`pdg` in sandbox → reverse-engineering playbook |

---

## Get the flag out & submit

1. Read the flag from engine output (a literal, a resource value, a decoded/XORed string, or
   the interpreter's computed value). Confirm it matches `csctf{...}` / `chronos{...}`.
2. Record where it came from in `notes.md` (for the write-up).
3. Submit once:
   ```sh
   ./csctf submit <id> 'csctf{...}' --note 'IL2CPP string literal #12'
   ```
   Or from a solver: `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="...", team_solved=...)`
   — it format-checks, dedupes, paces, skips team-solved, and **stops after 3 wrong** on a
   challenge (then ask the player). Never loop candidate flags.

**Scope / rate (when a mobile challenge points at a live backend).** Most mobile challenges
are self-contained files — no network needed. If the APK embeds a backend URL and the
challenge expects you to talk to it, that host is in scope **only if it is the squad's
assigned target**. No scanning, no flooding, no flag brute-forcing (AGENTS.md). Analyze the
app offline first; touch a live endpoint only when it's assigned and only as much as the
solve needs.

## Android/iOS depth helpers

`solvers/mobile-android/mobile_depth.py` has five offline modes. `intent` parses an APK or normalized
manifest JSON and ranks `adb am start`/broadcast/service command strings for exported components and
deep links; `smali` suggests method-local, reviewable bypass patches; `bundles` inventories bounded
Flutter and React-Native strings/assets; `frida` generates hook source from JSON without running it;
and `ios` triages an IPA's Info.plist, entitlements, URL schemes, permissions, and strings.

Generated adb/Frida text is a player artifact, not an action. Run it only in the mobile Docker setup
or against the single assigned emulator/device, after reviewing the component and extras.

## Round-5 native runtime and iOS evidence

`solvers/toolkits/mobile_rf_depth.py` adds strict saved-artifact inspection without loading app code:

- `macho` validates thin/FAT Mach-O headers and load-command bounds, inventories dylibs, UUIDs,
  encryption ranges, entry points and code-signature blobs, and reports exact Frida Gadget dylib
  references. A reference is evidence only: it does **not** prove that instrumentation ran, and the
  code-signature blob is not reported as cryptographically valid.
- `dyld` inventories the mapping/image tables in classic dyld shared-cache headers. Modern split
  subcache/slide-info layouts still require a platform tool or manual analysis.
- `bundle` requires paired exact members before reporting Xamarin/MAUI, Unity IL2CPP, or Flutter AOT
  runtime evidence (`global-metadata.dat` + native IL2CPP binary, or Flutter AOT + runtime/assets).
  It does not claim that a runtime was executed or turn unvalidated strings into answers.

Examples: `.venv/bin/python solvers/toolkits/mobile_rf_depth.py bundle app.ipa` and the same command
with `macho` for an extracted executable. Extraction and any execution of untrusted native members
remain Docker-only (`--pull=never --network none`, read-only root, caps dropped).
