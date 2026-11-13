# CSCTF 2025 coverage matrix (all 54) → our engines

Every 2025 challenge mapped to how we'd solve it and our status. Legend:
**FAST** = covered + quick (rehearsal-proven or trivial) · **COVERED** = have the engine, works ·
**+NEW** = addressed by the pre-event speed builds (netplay / fast-enigma / audio-tones / fastlane) ·
**HARD** = low-solve tail, codex+orchestrator-guidance / SageMath · **LIVE** = docker target, can't pre-test
(works once the service is up). Solve counts show which are fast-points/first-blood targets.

## crypto (9)
| # | name | solves | our path | status |
|---|---|--:|---|---|
|1|Chef|137|crib_decode (hex→b64→url) / fastlane|FAST|
|2|Enigma|76|classical.py crib-first + parallel (was 40min→seconds)|+NEW|
|3|Friend Check|5|SageMath (LLL+isogeny+CRT) — pin the stated Sage version|HARD|
|4|iBadge|20|PRNG recovery (random.Random seed from boot hdr)|COVERED|
|5|Letter|111|hashlib per-char SHA-256 lookup|FAST|
|6|Noncesense|82|modern_crypto CTR-nonce-reuse / XOR|FAST|
|7|Norhtline Secrets|52|sops+age key-leak|FAST|
|8|Rstore|63|rclone crypt config|FAST|
|9|Secustoring|20|CBC padding oracle (live) — beware the local decoy|COVERED/LIVE|

## forensics (5) — all FAST/COVERED
Artifacts(68, firefox_decrypt+7z) FAST · Logs(23, EVTX 4104 + deobfuscation) COVERED · Time-gone(58,
network/NTP-RefID; minor: add a RefID header reader to network.py) FAST · Update(67, LNK→PS -enc) FAST ·
Volatile Questions(28, regipy SAM/SYSTEM hives) COVERED.

## linux (6)
Interview-1..4 (110/102/97/86 — SSH REPL system-command quizzes) **+NEW netplay** · MultiDB(500, DB pivot
chain) COVERED/LIVE (shell) · Shadow Home(500, setuid path-traversal) COVERED/LIVE.

## misc (9)
Brainrottalk(17, ggwave) FAST · CyberSonics-1/2/3 (27/11/3, FFT tone→ASCII, XOR streams, fine clustering)
**+NEW audio-tones** · Parano1d(59, ccrypt→KeePass→age) FAST · Rnd(500, LCG recovery) COVERED (+psearch) ·
Romeo and Julia(52, REPL shell-escape) **+NEW netplay** · Secret(66, git-crypt history) FAST ·
White Noise(36, strings filter) FAST.

## osint (6)
Domain/History/MITRE/Pwned/VulnDB (109/135/87/131/133 — web-check / Wayback / ATT&CK / HIBP / NVD lookups)
**+NEW fastlane** · Sakot(59, 3D-scan geolocation) COVERED (osint_geo; final pin is human).

## programming (6) — **+NEW netplay handlers**
Intreview-1..6 (~60 each): CLF byte-sum, XOR-hex, base64-sort, HMAC-SHA256, manual HS256, TLV — all
deterministic compute-over-nc, now driven by `tools/netplay.py`.

## pwn (2) — COVERED/LIVE
Blic(27) & Print(17): format-string → GOT → system, via pwn_exploit (try `%N$s` stack-read first).

## rev (3)
Chrono-key(40, PyInstaller + hash recompute) FAST · Covert(43, hidden localhost listener) FAST ·
Ransom(39, PyInstaller decompile → hardcoded pw) COVERED.

## sanity (1) / stegano (1)
Rules(124, read the rules page → flag) **+NEW fastlane** (free first-blood) · Specter(96, spectrogram)
FAST (carve_stego).

## web (6) — LIVE
Chatbot-1/2/3 (69/52/25: localStorage role, md5 IDOR, SQLi), Requests(73, REST+ETag chain) — COVERED by the
web engines + recon. Abnormalized(6, NFKC-normalization SQLi) & The Box(4, JSFuck→XXE/XInclude RCE→setuid
privesc) — **HARD**: codex (daybreak_blue) + orchestrator guidance.

## Takeaway
After the in-flight speed builds, **every 2025 family has a path**. The only genuinely hard tail —
Friend Check, Abnormalized, The Box, CyberSonics-3 (all ≤6 solves) — is where codex + guidance earns its
keep. The fast-points mass (sanity, 50-pt OSINT, Interview/Intreview, decode-chains, high-solve
crypto/forensics) is where we race for first blood; the fast-lane + netplay + fast-Enigma exist to win those.
