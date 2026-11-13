# CSCTF 2026 solver — capability map (carried, not maintained)

> Hand-written at CSCTF 2026 and kept as prose context only. It is not updated when engines change.
> The current map is [CAPABILITIES.md](CAPABILITIES.md), generated from the engine manifests by
> `python -m ctf engines generate` (R-10).

What this toolkit can solve, grouped the way a player thinks. Most engines are **offline** — they
analyse artifacts you've already downloaded (files, captures, binaries, images) and need no network.
A distinct set of **active, scope-locked** engines *do* talk to the challenge: the web/service recon
tools (`solvers/web/*`, `solvers/toolkits/web*.py`), the pwn exploit drivers (pwntools against the
remote instance), and the service/protocol clients. Those point at **only the squad's assigned
target/instance**, keep their request caps, and never scan off-target or flood — so yes, when a
challenge gives you a container, you point the active engines at it; "offline" describes the static
analysis lane, not a limit on reaching an assigned instance. Every engine, offline or active, is
fail-closed and candidate-producing: it reasons to a value for human review / guarded submit and
never probes a judge or auto-submits. Derived from engine filenames, the lane inventories, and
`docs/playbooks/`.

## Crypto — classical ciphers
- Substitution/shift: Caesar, ROT13, Atbash, affine, Vigenère, Beaufort, Porta, Gronsfeld, autokey (plaintext/ciphertext), running-key, book cipher
- Polygraphic/fractionating: Hill 2×2–4×4 (encrypt/decrypt/key-recovery/break), Playfair, two-square (horizontal+vertical), four-square, bifid, trifid, ADFGX/ADFGVX, nihilist, Polybius, Bacon, straddling checkerboard, fractionated Morse
- Transposition: rail-fence, columnar, Myszkowski, scytale
- Breakers support cribs, bounded candidate search, statistical scoring, and explicit re-encrypt verifiers
- Crib-less repeating-key XOR (`xor_repeat.py`: Hamming key-length + per-column frequency; xortool-style) — byte-level, no crib

## Crypto — RSA
- Wiener, Boneh–Durfee (low private exponent)
- Håstad broadcast, Franklin–Reiter / related-message, common-modulus
- Coppersmith univariate small-root, stereotyped-message, partial-prime known-bits, partial-d completion
- Fermat / close-prime factoring; Bellcore CRT-RSA signature-fault key recovery
- Parity/LSB oracle, Bleichenbacher PKCS#1v1.5, Manger OAEP

## Crypto — ECC / DLP
- Invalid-curve residue + private-scalar reconstruction, small-subgroup/Pohlig–Hellman, generalized-CRT
- Singular curves (cusp/node/non-split-node), anomalous (Smart), quadratic-twist residue/CRT
- MOV / Frey–Rück, embedding-degree analysis, pairing transcripts; BSGS, toy index calculus
- ECDSA: known/reused/delta-nonce, HNP, biased/partial/low nonce, low-S alternatives, fault pairs
- Ed25519/EdDSA reused-R and nonce-delta faults; DSA nonce-reuse/bias/HNP family

## Crypto — lattice / PRNG
- Exact integer LLL (verified), bounded BKZ-style block tours, optional fpylll adapter
- Hidden Number Problem (verified), ECDSA/DSA nonce-bias lattices, bounded multivariate small roots (≤16 vars)
- PRNG prediction: MT19937, Java Random (incl. truncated), LCG, xorshift/xoshiro, PCG — state replay-checked

## Crypto — symmetric cryptanalysis
- Reduced-round differential & linear key-recovery harnesses
- Meet-in-the-middle / 2DES double-encryption, slide, related-key
- Generic Feistel & SPN encrypt/decrypt + key/structure recovery
- Mode misuse: ECB cut-and-paste/pattern, CBC bit-flip/IV-reuse/IV-recovery/IV=key, CTR/OFB/CFB keystream reuse
- AES S-box, white-box XOR/S-box table recovery, noiseless trace-key recovery

## Crypto — AEAD / oracles / MAC
- CBC padding-oracle (verified plaintext), AES-GCM & ChaCha20-Poly1305 nonce-reuse → forgery
- Length extension (Merkle–Damgård secret-prefix), CBC-MAC variable-IV / raw forgery
- Multicollision (Joux), chosen-prefix collision validation, polynomial-hash key recovery, GF(2) CRC patch/forgery

## Crypto — stream
- Berlekamp–Massey / minimal-LFSR recovery, Geffe correlation, nonlinear filter, shrinking & alternating generators
- RC4 KSA/PRGA, WEP/FMS voting, RC4 bias, reused-keystream known-plaintext
- Keystream reuse (`crib_drag.py`): two-time-pad crib-dragging + many-time-pad per-column 'space is special' recovery

## Crypto — protocol / post-quantum / side-channel / formats
- Finalized PQC raw-object parser (`cryptodepth_pqc.py`): strict FIPS-203 ML-KEM, FIPS-204 ML-DSA, FIPS-205 SLH-DSA layouts with canonical packing/hash/hint checks, ambiguity-preserving ID
- PQC parameter-profile auditor (`cryptodepth_pqc_audit.py`): classifies finalized/legacy/toy/malformed ML-KEM/ML-DSA/SLH-DSA tuples, derives sizes, flags reuse/oracle/side-channel/fault weaknesses
- DH small-subgroup/weak-group/CRT, ElGamal reuse, Paillier weak randomness, Schnorr/Fiat-Shamir reuse, Shamir reconstruction (bounded errors), Pedersen/hash commitments
- Isogeny/pairing: SIDH/SIKE/CSIDH toy transcripts, invalid-aux-point leakage, BLS (aggregate/PoP/rogue-key), IBE reuse
- PQ toy params: LWE / module-LWE / NTRU / Kyber-like / Dilithium-like audits + bounded recovery
- Offline side-channel: CPA/DPA, timing, cache, DFA, instruction-skip/redundancy, fault clustering (supplied traces only)
- Format analyzers: OpenPGP, SSH keys, PKCS#8/PEM, TLS records/hellos/certs, age/SOPS, JWT/JWK (+ bounded HMAC key recovery)
- Shamir/TOTP, key-leak→decrypt chains (sops/age/git-crypt/rclone/KeePass/ccrypt)
- Hash/token identification (`hash_identify.py`): structural+length ID of MD5/SHA/NTLM/bcrypt/argon/crypt/Kerberoast/JWT/... with hashcat -m & john --format hints

## Encodings & codecs
- Base families: base16/32/32hex/Crockford32/z-base-32/45/58(+flickr/ripple/check)/62/64/url/Ascii85/base85/Z85/91/92/122 (canonical re-encode checked)
- Character encodings: 138 installed text codecs, fixed-width UTF, EBCDIC pages (strict round-trip)
- Compression: gzip/zlib/bzip2/LZMA/XZ/Brotli/LZ4/Zstandard/Snappy/LZO + adaptive arithmetic & range coders
- Esoteric symbol sets: Morse (+variants), ITA2/Baudot, tap/Polybius, Bacon, DTMF multi-tap, braille, DNA
- Layered/auto decode (CyberChef-style peeling) + crib/flag gating
- Embedded-blob extraction (`embedded_decode.py`): find+decode base64/base32/hex blobs hidden inside mixed text (HTML/JSON/logs/source)

## Error-correcting codes
- Hamming(8,4) SECDED, BCH (primitive narrow-sense binary), shortened Reed–Solomon over GF(2^m) with errors+erasures
- Convolutional/Viterbi, bounded exact & min-sum LDPC, bounded turbo/Chase
- CRC calc / parameter recovery / single-bit reversal; checksum family (xor8, sum8/16, Fletcher-16/32, Adler-32, Internet/BSD/SysV-16, CRC-32)

## Programming languages & esolangs
- Interpreted esolangs: Brainfuck (+families), Boolfuck, Brain-Flak, Befunge/Befunge-98, Whitespace, Malbolge, JSFuck, Ook, Deadfish, COW, Chef, Shakespeare (SPL), Rockstar, Fish/><>, LOLCODE, Unlambda, Lazy-K, Thue, FRACTRAN, Hexagony, Underload, FALSE, Piet, Whirl, Aheui, Core/Modular SNUSP
- Programming/quiz automation: saved-transcript state machines, bounded math/sequence/recurrence solving, finite-difference & rational recurrence, Berlekamp–Massey over prime fields, generalized CRT

## Reverse engineering
- Python 3.12/3.13 pyc depth (`redepth_pyc.py`): marshal-v4 code-object inventory + versioned wordcode lift with specialization normalization, inline-cache ownership, jumps and exception tables
- Modern JS depth (`redepth_js_bundle.py`): static javascript-obfuscator string-array/Base64/RC4 recovery + webpack 4/5 chunk/module extraction, no JS runtime
- Swift reflection (`redepth_swift.py`): thin-Mach-O Swift symbols, nominal/parent/module descriptors, fields/enum cases, lossless symbolic type strings
- .NET native (`redepth_nativeaot.py`): managed-IL / CoreCLR ReadyToRun / NativeAOT classification with validated RTR directories across PE/ELF/Mach-O
- Flutter/Dart AOT (`redepth_dart_snapshot.py`): raw snapshot headers + legacy/consolidated native snapshot symbols, build IDs, bounded string leads
- Go 1.20+ (`redepth_go.py`): validated pclntab/pcHeader/functab/_func and function-name recovery with exact offsets
- Modern Unity IL2CPP (`redepth_il2cpp_modern.py`): strict v29/v31 metadata validation + assembly/image/type/method/literal recovery
- Managed/runtime formats: .NET/CLR, Java/JVM bytecode, Kotlin, Go, Rust, Swift, WASM, eBPF, Unity/IL2CPP, Lua 5.1
- Bytecode lifters: Python 3.11 wordcode, Lua, .NET IL, JVM, WASM; PyInstaller/pyc extraction
- Packers: UPX, aPLib/AP32, Themida/VMProtect evidence; stream carving of embedded gzip/zlib/bzip2/XZ
- Deobfuscation: JS/PHP/PowerShell/VBA/.NET obfuscators, constant/XOR-array/layer peeling, control-flow-flattening recovery, opaque predicates
- VM-obfuscation: handler lifting (x86/ARM/MIPS/RISC-V) to typed IR, dispatch graphs, semantic clustering
- Symbolic/concolic: source-only angr harness, Triton taint plans, Qiling/Unicorn firmware-emulation plans (networkless-Docker execution)
- Crackme/keygen reasoning (reversible pipelines, linear constraints, Luhn/mod97), binary-patch diffing, anti-debug/anti-VM evidence
- XOR-encoded strings in a binary (`xor_strings.py`, FLOSS-lite): single-byte-XOR string recovery a plain `strings` run misses

## Pwn
- Non-glibc allocators + V8 sandbox (`pwnalloc_scudo_v8.py`): source-pinned Scudo compact-header decode/CRC, size-class allocation planning and Primary/Secondary chunk geometry, plus a fact-driven V8-sandbox object/pointer analyzer (sandboxed/compressed pointers, EPT/TPT handles, trust-boundary classification); offline, unknown versions fail closed
- glibc 2.40–2.43 allocator routing (`wpgap_glibc_binpath.py`): exact x86-64 request→tcache/fastbin/smallbin/largebin indices, release-default vs large-tcache tunables, num_slots/double-free transitions, 2.43 fastbin removal
- Linux page-exploitation geometry (`wpgap_pagegeo_planner.py`): caller-declared page-table compose/decompose, PFN/struct-page/direct-map conversions, partial descriptor-pointer patches, stale-page→slab field-overlap planning; unknown layouts fail closed
- Kernel config attack-surface profiling (`wpgap_kconfig_profile.py`): offline `.config` + sysctl/cmdline eval for kCFI/IBT/KASLR/KPTI, allocator isolation, module policy, primitive gates; build/runtime/effective states, missing facts = unknown
- eBPF verifier-log invariant auditing (`wpgap_ebpf_verifier.py`): cross-version register/stack-state parsing, exact tnum + 64/low-32 bound + scalar-ID + owning-reference checks, CVE-2024-41003 signature; never claims verifier acceptance
- CET + io_uring mitigation/capability profiling (`wpgap_mitig_cet_uring.py`): GNU-property IBT/SHSTK parsing with hardware/kernel/loader/thread verdicts + ENDBR checks; io_uring acquisition/mapping/op-intersection for an ORW-equivalent route
- ret2dlresolve verifier (`pwndepth_ret2dlresolve.py`): stripped amd64 feasibility + inverse Rela/Sym/name/VERSYM, writable-range, RELRO/NOW, PIE/bias, PLT0, CET checks; no execution
- Modern heap plans (`pwndepth_heap_plans.py`): deterministic House-of-Water, hardened large-bin constrained write, count-preserving House-of-Banana `_dl_fini` for glibc 2.35–2.41
- House-of-Apple-2 verifier (`pwndepth_fsop_verify.py`): caller-profiled inverse FILE/wide-data/wide-vtable/lock + exit/trigger predicate verifier (glibc 2.35–2.41)
- Pointer-guard planner (`pwndepth_pointer_guard.py`): x86-64 glibc ptr mangle/demangle + caller-addressed exit-function/jmp_buf control-slot planning (distinct from Safe-Linking)
- Linux kernel heap plans (`pwnkern_linux_heap.py`): msg_msg/msg_msgseg layouts, caller-tunable cross-cache SLUB math, DirtyCred timelines, USMA/TPACKET pg_vec coverage
- Multiarch gadget contracts (`pwnkern_multiarch_gadgets.py`): Capstone-validated AArch64/MIPS32/RISC-V gadgets, MIPS delay slots, RV compressed transfers, address-parameterized epilogues
- Windows kernel primitives (`pwnkern_windows_kernel.py`): CTL_CODE decode/encode, all four DeviceIoControl buffer methods, build-offset-parameterized EX_FAST_REF token-transfer records
- Heap (glibc 2.23–2.41 version-gated): tcache dup/poison + stashing-unlink, fastbin dup/poison, unsorted-bin leak, House of Force/Orange/Apple/Einherjar/Botcake/Spirit, large-bin attack, safe-linking aware
- Heap primitives: feng-shui, UAF, double-free, type-confusion, off-by-one, poison-null-byte, int-overflow, C++ vtable
- ROP/JOP: ret2win, ret2libc, syscall-ROP, ret2csu, ret2dlresolve (+_dl_fixup/link_map), stack pivot/migration, one-gadget constraint unification
- SROP/sigreturn (x86/ARM/AArch64/MIPS/RISC-V), FSOP/_IO_FILE/_IO_str_jumps/wide-data
- Format string: `%N$p` offset probe, positional leaks, `%hhn/%hn/%n` GOT overwrite, printf-count simulator
- Kernel: KASLR rebase, ret2usr, commit_creds/prepare_kernel_cred, modprobe_path, pt_regs, cred/pipe_buffer, KPTI trampoline
- Multi-arch shellcode/ROP (ARM/AArch64/MIPS/RISC-V), Windows SEH + egghunters, seccomp/BPF (ORW/bypass plans), race scaffolds (userfaultfd/FUSE/TOCTOU), bad-char XOR/polymorphic/alphanumeric transport
- Static ELF32/64 gadget catalog (AMD64/i386/ARM/AArch64/MIPS/RISC-V); builders are caller-address-parameterized, verified via pwn Docker/QEMU/Unicorn

## Web
- Deserialization CVE preconditions (`webdeser2_preconditions.py`): offline tri-state version/config/classpath/sink mapping for ActiveMQ CVE-2023-46604, Tomcat CVE-2025-24813, PyTorch CVE-2025-32434, .NET BinaryFormatter risk, and Log4Shell CVE-2021-44228; evidence-only, never deserializes or executes
- SAML lexical c14n linter (`wpgap_saml_lexical.py`): lexical QName/attribute-order preservation, relative/reserved/rebound namespace + local-name-collision detection, exclusive-C14N PrefixList audit, whole-doc c14n round-trip probes (complements the XSW decoder)
- OAuth/OIDC non-happy-path policy (`wpgap_oauth_policy.py`): offline config-vs-flow checks for response downgrade/modes, silent auth, mix-up/session policy, credential-forwarding redirects, Referer sinks, PAR/JAR enforcement, DPoP proof/token binding
- Web-server config confusion (`wpgap_webconf_analyzer.py`): Apache RewriteRule URL/filesystem/handler confusion, Nginx `$uri` response/upstream + alias-traversal sinks, Windows WorstFit best-fit (CVE-2024-4577) projection; evidence never asserts a confirmed vuln
- Package source-precedence auditor (`wpgap_depconf_sources.py`): offline pip/uv/npm/NuGet/Maven source-pool + ordering evaluation to prove cross-source-shadowable names; never queries a registry or claims availability
- HTTP desync state classifier (`wpgap_desync_state.py`): offline per-hop framing-evidence classifier for 0.CL/CL.0/double-desync (body-debt) from saved request/response/config; a raw CL mismatch alone is never promoted to 0.CL
- SAML XSW decoder (`webauth_saml_xsw.py`): offline SAML POST/Redirect/raw-XML decode + namespace-exact XMLDSig reference/XSW graph, signed-vs-consumed assertion analysis (no signature verify)
- WebAuthn/FIDO2 decoder (`webauth_webauthn.py`): client-data JSON, attestation CBOR, authenticator flags/counter, AAGUID/credential ID, COSE keys, RP/challenge/origin binding
- Browser trust-boundary catalog (`webauth_browser_catalog.py`): DOM clobbering chains, CSP3 fallback/strict-dynamic/Trusted-Types, SemVer-aware prototype-pollution gadgets
- JOSE edge analyzer (`webauth_jose_edge.py`): ECDSA P1363/Psychic-Signature, JWKS selection, injected kid, local x5c trust, versioned JWT-library CVEs
- OAuth/OIDC edge correlator (`webauth_oauth_edge.py`): PKCE downgrade, CSRF/nonce, redirect/native-URI policy, JAR/JARM/PAR bindings, issuer/subject/azp correlation (never token exchange)
- Client-side desync planner (`webdepth_csd_planner.py`): CL.0 / 0.CL / TE.0 / double-desync request-smuggling plans from supplied evidence
- GraphQL cost analyzer (`webdepth_graphql_cost.py`): query-cost / alias-overloading / field-duplication / batching DoS analysis
- Node SSPP planner (`webdepth_node_sspp_planner.py`): server-side prototype-pollution-to-RCE gadget plans
- SQLi-to-RCE templates (`webdepth_sql_rce_templates.py`): per-DB SQLi-to-RCE (MSSQL xp_cmdshell, PG COPY/lo_, MySQL INTO OUTFILE/UDF)
- SSTI bypass planner (`webdepth_ssti_bypass_planner.py`): SSTI filter/sandbox-escape payload plans per template engine
- SSTI engines: Jinja2, Twig, FreeMarker, Velocity, ERB, Smarty, Handlebars, Pug, Mako (context encodings, render/error/source detect)
- Injection: SQLi (+SQL-to-RCE plans per DB), NoSQL/Mongo operators, LDAP filters, XPath
- SSRF/XXE: parameter/nested entities, XInclude, cloud-metadata (AWS/ECS/GCP/Azure/OCI/Alibaba), IPv4-normalization bypasses, gopher chains
- Request smuggling/desync: CL.TE/TE.CL/TE.TE, duplicate/obfuscated framing, H2.CL/H2.TE downgrade; HTTP/2 & HTTP/3 structural evidence (pseudo-headers, QPACK, 0-RTT, Alt-Svc)
- Deserialization: PHP POP/PHAR, Python pickle/PyYAML/jsonpickle, Ruby Marshal/ERB, Java/ysoserial, .NET (signature-only inert plans)
- Auth/identity: JWT/JWS/JWE/JWK/JWKS (alg/kid/jku/x5u trust boundary), SAML XSW, OAuth/OIDC/PKCE, WebAuthn/FIDO ceremonies
- Client-side: DOM-XSS source→sink taint, prototype pollution, postMessage origin, clickjacking
- Cache: poisoning (cache-key/reflection), deception; upload/LFI: MIME/magic/polyglot bypass, traversal, PHP wrappers/filters
- APIs: GraphQL (depth/alias/batch/cost/introspection/field-policy), gRPC-web, WebSocket/CSWSH, REST/OpenAPI (BOLA/BFLA, mass-assignment, method override)
- CRLF/open-redirect/host-header, CORS, CSP, HPP/IDOR; WAF-bypass encoding catalog + pipelines
- Jail/sandbox escapes: pyjail (stripped builtins/no-import/no-dunder/audit-hook/bytecode), rbash/shell ($IFS/no-space/no-slash), eval/calculator/template, restricted-charset construction
- Flask/Werkzeug console PIN, session forgery
- Session-cookie forging from a leaked secret (`session_forge.py`): Flask/Django/Express/connect/Laravel (the offensive complement to `session_recon.py`)
- AWS SigV4 compute/verify (`aws_sigv4.py`): canonical request → string-to-sign → signing-key HMAC chain → signature; Authorization headers, query-presigned URLs, offline (validated against AWS's published vectors)

## Forensics & stego
- Boot/firmware containers (`fwboot_inventory.py`): strict U-Boot FIT (images/configs/hashes/signatures/control-FDT keys), FDT/DTB overlay fragments+fixups, UEFI capsule + firmware-volume FFS/section walk, and modern/legacy CBFS — span+SHA-256 inventory, static only, no decompression/extraction/verification
- Vendor camera RAW (`ff2_raw_vendor.py`): Nikon NEF / Sony ARW preview + bounded maker-IFD inventory, Fujifilm RAF header/records/FujiIFD/embedded-EXIF preview
- OneNote deep store (`ff2_onenote_store.py`): strict FileDataStoreObject + embedded-object extraction from .one revision stores
- iOS encrypted-backup metadata (`ff2_ios_backup_keybag.py`): Manifest.plist/Manifest.db + keybag wrap/KDF-iteration reporting; never attempts decryption without a supplied key
- Emulator save-states (`ffgame_emulator_states.py`): SNES9x named-block (raw/gzip), VBA-GBA stable-prefix, and Gens GSX v6/v7 region parsing with versions/blocks/hashes/flag offsets
- Minecraft Anvil semantics (`ffgame_anvil_semantics.py`): full `.mca` region/chunk walk over NBT — section palettes, entities/block-entities, coordinate validation, allocation-slack evidence; extends `research_ff_nbt`
- Cartridge artifacts (`ffgame_cartridge_artifacts.py`): N64 `.z64/.v64/.n64` byte-order normalization+headers, GBA logo/complement checks, GB battery-RAM banks with ROM correlation, PICO-8 cart
- Mail/chat archives (`maildepth_archives.py`): PST/OST node-BTree message/attachment walk, Outlook `.msg` CFB streams, mbox thread reconstruction, Slack/Discord/Teams JSON export parsing — read-only
- Console cartridge headers (`ff_rom_headers.py`): iNES/NES2.0 mapper/trainer/PRG-CHR, GB/CGB title + checksums, Genesis + Sega checksum; declared-vs-actual size findings
- PICO-8 cartridges (`ff_pico8_cart.py`): `.p8` section decode + `.p8.png` low-bit payload extraction, section sizes, appended bytes; never runs Lua
- PSD/PSB inventory (`ff_psd_inventory.py`): resources, layers, Unicode names, visibility/blends, additional-info keys, thumbnail/embedded extraction, section slack
- Camera RAW recovery (`ff_raw_inventory.py`): TIFF/BigTIFF/DNG/CR2 preview refs, DNG embedded-original, CR3 UUID/CMT/THMB/PRVW inventory; maker notes opaque
- WOFF/WOFF2/SFNT hidden-data (`ff_woff_inspect.py`): table directories, metadata/private blocks, TTC all-font traversal, overlap/gap evidence, SVG/bitmap inventory
- iWork ZIP/IWA (`ff_iwork_inspect.py`): assets/plists/previews, nested Index.zip, Snappy-framed IWA, opaque protobuf field/wire-type facts
- ZIP parser differentials (`ff_zipdiff_diagnostics.py`): local/central/descriptor divergences, Unicode-extra conflicts, alias/overlap, multiple-EOCD, ZIP64 metadata
- Android backups (`ff_androidab_backup.py`): `.ab` v1–5 header/AES-KDF metadata + checksum-validated tar inventory with path/link/ratio guards; no decryption
- ZPAQ static inventory (`ff_zpaq_inventory.py`): level-1/2 block/segment locations, filenames/comments, sizes/hashes; no decode, no ZPAQL execution
- LRZIP header inventory (`ff_lrzip_header.py`): LRZI 0.2–0.7 metadata, size/encryption/checksum flags, LZMA props; no payload decode
- Echo-hiding audio stego (`stegodepth_echo.py`): explicit-delay PCM recovery via normalized-autocorrelation windows
- DSSS audio stego (`stegodepth_spread.py`): explicit-PN/timing baseband matched correlation, candidate-byte recovery
- WebP structural audit (`stegodepth_webp.py`): codec-free WebP/animated walk, ANMF provenance, metadata/private chunks, post-RIFF tails
- FLAC metadata-carrier audit (`stegodepth_flac.py`): APPLICATION, nonzero PADDING, reserved, Vorbis-comment, PICTURE payloads (RFC 9639)
- JPEG cover/stego delta (`stegodepth_jpegcover.py`): known-cover baseline-JPEG coefficient deltas by component/frequency, texture concentration
- JPEG 2000 box/marker (`stegodepth_jp2.py`): raw-J2K/JP2/JPX box + SOC/SIZ/COD/QCD/COM structure, free/private artifacts, container tails; no EBCOT decode
- Matroska/WebM carrier audit (`stegodepth_matroska.py`): EBML attachment/tag/chapter/track/Void/BlockAdditional + post-Segment extraction; media blocks opaque
- Memory: Volatility3 Win/Linux/macOS plan+plugin inventory, process/handle/injection/credential artifacts, cross-view anomalies
- Disk/filesystem: NTFS (MFT/runlists/USN/deleted), FAT12/16/32, ext (+JBD2), APFS, btrfs, VSS; EWF/VHDX/QCOW2/VMDK images
- Network: PCAP/PCAPNG reassembly, HTTP/DNS/SMB2/WebSocket/HTTP2 object recovery, PCAP creds, NSS-keylog TLS1.3/QUIC decrypt (supplied secrets)
- Documents: PDF object graphs/revisions/actions, OOXML/XLM/VBA, CFB/OLE, RTF/OLE1, maldoc static deobfuscation
- Timeline: EVTX/registry/ShellBags/browser-SQLite/journald/shell-history super-timeline + causal correlation (download→execute, persistence→execute, execute→network)
- Carving: PNG/JPEG/GIF/ZIP/PDF/gzip/bzip2/XZ/zlib/RIFF/BMP/ELF/PE/7z/SQLite, polyglot detect, file-slack & unallocated extents
- Image stego: LSB (match/replace, all channels/traversals), JPEG DCT/JSteg, F5 (matrix k=1–7), Haar/CDF-5/3 DWT, keyed DSSS, edge-adaptive
- Audio/signal: FSK/ASK/OOK/BPSK/DBPSK, DTMF, Morse tones, spectrogram text, SSTV (Martin M1/M2), ggwave, POCSAG, covert tones/FFT
- Video stego: bitplanes, temporal/ASK, inter-frame parity, duplicate-frame runs; steganalysis
- Barcodes: QR, Data Matrix (all 18 ECC200 DMRE sizes), Aztec, PDF417/MicroPDF417 (34 variants), homography/cylindrical unwarp
- Mystery-timestamp decode (`timestamp_decode.py`): a number → every epoch/unit (Unix s/ms/us/ns, FILETIME, WebKit, HFS+/Cocoa, OLE, DOS)
- Font hidden-data (`font_inspect.py`): parse TTF/OTF/TTC SFNT name tables (flags hide in copyright/family/custom records), list tables, flag trailing-data/past-EOF anomalies
- XLSX hidden sheets (`xlsx_hidden.py`): OOXML .xlsx/.xlsm — surface hidden/very-hidden worksheets and their cell text (shared + inline strings) plus defined-name values, flag-ranked (BIFF .xls lives in maldoc)
- CRC32 forcing (`crc_force.py`): patch (or append) 4 bytes so a blob's CRC32 equals any chosen target, solved by GF(2) linear algebra with zlib as the oracle and verified before return

## Mobile / hardware-RF / ICS
- SSTV depth (`rf2_sstv_modes.py`): Scottie S1/S2/DX, Robot 36/72, PD 50/90/120 pixel decode reusing the existing VIS/PCM validator
- LoRa PHY (`rf2_lora_phy.py`): Tapparel-aligned symbol/IQ decode — SF/CR/LDRO, whitening, header checksum, FEC, payload CRC, explicit/implicit headers
- BLE advertising PHY (`rf2_ble_phy.py`): legacy LE-1M preamble/access-address/dewhitening/CRC-24 verification, then delegates the verified PDU to `radio_capture`
- IEEE 802.15.4 PHY (`rf2_ieee802154_phy.py`): 2.4 GHz PPDU/PSDU framing + CRC-16/KERMIT verification ahead of MAC/Zigbee decode
- 5G/VoIP depth (`telecom3_depth.py`): RFC 3711/4568 SRTP/SRTCP context + MKI/supplied-key AES-CM decrypt, RFC 7616/8760 SIP Digest + REGISTER/MESSAGE correlation, GTPv2-C bearer/session correlation, bounded PFCP/N4 session-state inventory
- Android app storage (`mobile2_android_storage.py`): shared_prefs XML, schema-less proto DataStore / `.preferences_pb`, app-database inventory — read-only
- Messenger databases (`mobile2_messenger_db.py`): WhatsApp msgstore / Signal / ChatStorage schema + table inventory; reports structure, never decrypts without a supplied key
- Mobile instrumentation artifacts (`mobile2_instrumentation.py`): Frida gadget configs/scripts and Objection-patched APK evidence
- iOS media (`mobile2_ios_media.py`): KTX 1.1/2.0 textures, SplashBoard/HEIC snapshots, APPLE-compression evidence
- iOS: Mach-O (thin/fat, both endians), dyld cache, IPA/entitlements/provisioning, ATS/keychain, Frida evidence
- Android: DEX/smali patch plans, ELF/JNI, Xamarin, IL2CPP, Flutter AOT/StandardMessageCodec, APK/AAB/splits; ProGuard mapping
- SDR/RF: IQ/WAV load, OOK/ASK/FSK/GFSK, LoRa chirp-bins, ADS-B/Mode-S, POCSAG BCH, AIS, RDS; UF2 reconstruction
- Hardware buses/faults: UART, SPI (all modes), I2C (repeated-start/10-bit/NACK), JTAG, SWD; glitch campaigns, Welch t-test, AES CPA
- Firmware: SquashFS/JFFS2/UBI/CramFS/uImage/FIT-DTB, Intel HEX, Motorola S-record, RFID/NFC
- ICS/SCADA: Modbus, DNP3, S7comm/S7comm-plus, BACnet, EtherNet/IP-CIP, IEC-104; OT PCAP reassembly & correlation
- Networking depth: OPC-UA, PNIO, MMS, QUIC extensions, VoIP, DB protocols

## Total-Warfare sector depth (critical-infrastructure file/protocol readers)

**Worldwide sector protocols (US + EU/international, offline/passive decoders — build on supplied captures, never touch a live target):**
- Rail signaling: ERTMS/ETCS Eurobalise + ETCS packets + EuroRadio (`sec_rail_ertms.py`, EU UNISIG Subset-036/026/037); US Positive Train Control — I-ETMS/ITCM, ATCS, 220 MHz EMP (`sec_rail_ptc.py`)
- Air-traffic surveillance: EUROCONTROL ASTERIX CAT048/021/034/062/240 (`sec_airsurv_asterix.py`); US/ICAO Mode S Comm-B BDS registers + 1090ES ADS-B + ARINC 429 (`sec_airsurv_modes.py`)
- Smart metering: EU Wireless M-Bus / M-Bus EN 13757 (ELL/AFL/TPL, DIF/VIF, supplied-key AES) (`sec_meter_wmbus.py`); US ANSI C12.18/19/22 PSEM/EPSEM/table model (`sec_meter_ansi_c12.py`)
- Public-safety radio: ETSI TETRA air-interface/MAC/CMCE + TEA keystream context (`sec_lmr_tetra.py`); US APCO P25 C4FM/NID/DUID + IMBE/AMBE + DES/AES context (`sec_lmr_p25.py`)
- EV charging: ISO 15118 V2G "Plug & Charge" (EXI) + OCPP 1.6/2.0.1 (`sec_evcharge_v2g.py`); US OpenADR 2.0b + SAE J2847/J2931 (`sec_evcharge_openadr.py`)
- Space + GNSS: CCSDS Space Packet / TM-TC transfer frames / ECSS PUS (`sec_space_ccsds.py`); GPS/Galileo/GLONASS/BeiDou navigation-message decode (`sec_gnss_nav.py`)
- Interbank payments: EU EBICS (H004/H005) + SEPA ISO 20022 pacs/camt depth (`sec_bank_ebics.py`); US FedNow/Fedwire + NACHA ACH + ISO 8583 (`sec_bank_us.py`)
- V2X: EU ETSI ITS-G5 GeoNetworking/BTP + UPER CAM/DENM/SPATEM + 1609.2 (`sec_v2x_etsi.py`); US SAE J2735 BSM/SPaT/MAP + IEEE 1609 WSMP (`sec_v2x_j2735.py`)
- Grid security: IEC 61850 GOOSE/SV + IEC 62351-6 auth / R-GOOSE (`sec_gridsec_goose.py`); US DNP3 Secure Auth (IEEE 1815) + ICCP/TASE.2 (`sec_gridsec_dnp3sa.py`)
- Building automation: EU KNX cEMI/KNXnet-IP + Data/IP Secure (`sec_bas_knx.py`); US ASHRAE BACnet APDU/objects + BACnet/SC (`sec_bas_bacnet.py`)
- Tactical data links: NATO Link 22 (NILE) + VMF (MIL-STD-6017) + JREAP-C (`sec_tdl_link22.py`); US Cursor-on-Target / ATAK XML + TAK protobuf (`sec_tdl_cot.py`)
- Real-time middleware: OMG DDSI-RTPS header/submessage/CDR (`sec_dds_rtps.py`); DDS-Security crypto submessages + governance/permissions (`sec_dds_security.py`)
- Emergency call: EU eCall MSD (EN 15722) + ERA-GLONASS (`sec_emerg_ecall.py`); US NENA i3 NG911 — ESInet/SIP, PIDF-LO, EIDD, LoST/ECRF (`sec_emerg_ng911.py`)

- TriStation/Triconex wire forensics (`ot_tristation_wire.py`): bounded raw UDP/1502 + PCAP/PCAPNG TCM/TS decode, session/transaction correlation, command-29 implant-body and command-55/59 program/project evidence — passive, no traffic crafting or execution (TRITON/TRISIS)
- Siemens STEP7 deep projects (`ot_s7deep_project.py`): strict MC7/SBB block inventory+CRC, compiled interface + scalar DB-value decode, dBASE/DBT recovery, BAUSTEIN↔SUBBLK correlation (deep Stuxnet-era project analysis)
- IEC 60870-5-101 serial FT1.2 (`ot_iec101_serial.py`): fixed/variable/single frames, checksum/length validation, balanced/unbalanced controls, shared IEC-104 ASDU decode
- MMS/ACSE/presentation (`ot_mms_services.py`): MMS services 0–77, named variables/lists/types, reports, files/journals, ACSE AARQ/AARE + presentation contexts over bounded BER
- IEC 61850 SCL integrity (`ot_scl_integrity.py`): semantic SCL diff, cross-reference + duplicate-address findings, GOOSE/SV PCAP-to-dataset correlation
- OPC UA PubSub/NodeSet2 (`ot_opcua_pubsub.py`): offline UADP network/dataset/security-header + NodeSet2 node/reference inspection
- CODESYS V3 native (`ot_codesys_native.py`): ZIP-backed project/archive inventory, boot-application strings/signatures, symbol XML + runtime CFG; protected content flagged
- Schneider native + UMAS (`ot_schneider_native.py`): STA/ZEF/APX inventory + XEF extraction; offline UMAS session/reservation/program-transfer decode with MBAP validation
- Stuxnet artifacts (`ot_stuxnet_artifacts.py`): documented Step7/WinCC + `~WR` TMP markers, DB888–DB891 inventory, OB hook signatures, bounded MC7 metadata
- SIPROTEC forensic IOC (`ot_siprotec_signature.py`): CVE-2015-5374 Industroyer payload + UDP/50000 detection, evidence-only
- BlackEnergy config (`ot_blackenergy_config.py`): BE2 XML + BE3 ASN.1 config extraction + BlackEnergy/KillDisk/SSHBearDoor IOC timeline
- EKANS/SNAKE profile (`ot_ekans_profile.py`): ICS-process/mutex/ransom-note/Go-PE profile matching with capped corroboration scores
Deep, offline, fail-closed readers for the sector formats the 2026 "Total Warfare" theme targets. Each
validated against a non-circular oracle (real library / published vectors / hand-built fixtures).
- Power & energy: IEC 61850 GOOSE/Sampled-Values (`power_iec61850.py`), DLMS/COSEM smart-meter APDUs + OBIS (`power_dlms.py`), IEEE C37.118 synchrophasor/PMU with CRC (`power_c37118.py`)
- ICS vendor project files: Rockwell L5X (`ics_vendor_l5x.py`), TwinCAT/PLCopen/XEF/CODESYS exports (`ics_vendor_exports.py`), GSD/GSDML/EDS/CID device descriptions (`ics_vendor_devices.py`) — extract logic, tags, comments, embedded secrets
- Telecom: SMPP (`telecom2_smpp.py`), RADIUS/Diameter AVP (`telecom2_aaa.py`), SCTP (`telecom2_sctp.py`), 5G NAS (`telecom2_nas.py`), NGAP (`telecom2_ngap.py`), deeper SS7 MAP operations (`telecom2_map.py`)
- Healthcare: deep DICOM pixel/encapsulated/tag extraction (`health2_dicom.py`), full HL7 v2 (`health2_hl7.py`), FHIR bundles (`health2_fhir.py`), ISHNE + SCP-ECG waveforms (`health2_ishne.py`, `health2_scp.py`)
- Financial messaging: ISO 20022 validation (`fin2_iso20022.py`), NACHA/ACH (`fin2_ach.py`), FIX session (`fin2_fix.py`), SWIFT MT (`fin2_swift.py`), BAI2 (`fin2_bai2.py`)
- Payment hardware: EMV cryptogram/DOL (`payment_hw_emv.py`), APDU traces (`payment_hw_apdu.py`), ISO 9564 PIN blocks (`payment_hw_pinblock.py`), TR-31 key blocks (`payment_hw_tr31.py`)
- Defense/secure-comms: MIL-STD-1553 (`defense_mil1553.py`), Link-16/TADIL-J (`defense_link16.py`), NITF (`defense_nitf.py`), PIV/FIPS-201 (`defense_piv.py`), ISM/CAPCO markings (`defense_markings.py`), USMTF (`defense_usmtf.py`), STANAG 4607/5066 (`defense_stanag.py`)
- Transport: GTFS(-RT) (`transport_gtfs.py`), AIS (`transport_ais.py`), NMEA 0183/2000 (`transport_nmea0183.py`, `transport_nmea2000.py`), SAE J1939/J1587 (`transport_j1939.py`), EDIFACT/IFTMIN (`transport_edifact.py`), air-cargo AWB/ULD (`transport_cargo.py`)

## Blockchain / cloud
- DeFi exploit-pattern trace (`chain2_defi_trace.py`): opcode-boundary reentrancy-via-callback, flash-loan, and oracle-manipulation signatures over supplied bytecode/trace; static, no RPC
- L2 / account-abstraction formats (`chain2_evm_formats.py`): ERC-4337 UserOperation/PackedUserOperation decode, Optimism/Arbitrum L2 tx envelopes and retryable tickets
- Solana IDL/account depth (`chain2_solana_idl.py`): Anchor IDL + program-account/discriminator/PDA decoding
- EVM: Solidity/bytecode static audit (reentrancy, tx.origin, delegatecall/proxy storage collision, selfdestruct, unprotected init, arithmetic), disassembly/CFG/selectors
- Chain formats: Ethereum ABI calldata/events/reverts, wallet/descriptor/xpub, PSBT v0/v2, Solana tx, WalletConnect
- Cloud identity: AWS IAM/STS trust & escalation graphs, Azure roles, GCP impersonation, Kubernetes RBAC/admission
- Containers/IaC: OCI/Docker-save layers (+whiteout secret recovery), Terraform/CloudFormation/K8s manifest exposure

## OSINT
- Offline-first: EXIF/XMP/IPTC/GPS provenance & conflict clustering, document metadata, OCR of signage, lead extraction/pivoting
- Guarded online (single-bound-lead, allowlisted, throttled): RDAP, DNS-over-HTTPS, certificate transparency, Wayback CDX, Nominatim geocode, narrow public/record/paste search, exact profiles
- Geo reasoning: great-circle distance/bearing, solar position/shadow-length, Polaris/celestial loci, terrain-horizon & skyline/landmark scoring — ranked constraints only
- Every result is `requires_human_pin`; reverse-image upload stays manual; identity/geolocation handed to player with ranked candidates

## AI / LLM security
- Prompt injection taxonomy (direct/indirect/multi-turn/tool/RAG), detector rules, jailbreak corpus (inert text)
- Obfuscation views: Unicode tags, zero-width, homoglyph/NFKC, HTML/percent/base64/hex/ROT13
- RAG poisoning: near-duplicate/chunk-split/authority/rank/conflict/canary analysis; prompt-leak patterns; model-extraction audit
- Model-file analysis: safetensors, GGUF, ONNX, Keras, PyTorch/pickle (opcode/BUILD/PERSID/REDUCE risk), joblib/numpy — static, never unpickled

## Linux / Windows / OpSec (platform categories)
Three of the nine official 2026 areas. They aren't a separate engine family — they're served by the
engines above, surfaced here the way the scoreboard groups them (playbooks: `docs/playbooks/{linux,windows,opsec}.md`):
- **Linux** (mostly LIVE/assigned-instance): interactive-service solving — eval/blacklist jail bypass and REPL/quiz drivers over nc/ssh (`tools/netplay.py` + pyjail/shell-escape reasoning), SQLite browse (`sqlite_artifacts.py`), remote DB pivots (`net_dbproto.py`), zip/`unshadow` cracking (`archive_passwords.py` + john/rockyou), setuid/path-traversal privesc reasoning
- **Windows** (overlaps Forensics): registry/hive, EVTX (4104/4688), ShellBags, LNK/jumplist (`jumplist.py`)/prefetch, browser-SQLite super-timeline (`timeline.py`, `windows.py`); Access `.mdb`/ESE (`ese_reader.py` + mdbtools)
- **OpSec / operational security** (overlaps Forensics + Blockchain/cloud): secrets that shipped — git-history exposure (`vcs_exposure.py`), config/backup/container-image walk (`fs_walk.py`/`cloud_container.py`/`nix_host.py`), supply-chain repos (`repo_supply_chain.py`), metadata/EXIF leaks, secret/flag scanning (`flagscan.py`)

## Misc / sanity / orchestration
- Sanity: read-the-rules flag, quiz/REPL TCP drivers
- Auto-solver: `autosolve` top-level classifier → crypto/forensics/exploit dispatchers, chains existing engines, returns ranked flag-shaped candidates with derivations (offline, never submits)
- Recursive archive unpacker + password store; POW solver; hash cracking
- Route/grid ciphers (`grid_read.py`): read a character grid in spiral/column/boustrophedon/diagonal orders, flag-ranked
