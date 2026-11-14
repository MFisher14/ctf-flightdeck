# Mobile code-container fixtures

Real compiler output of the small sources beside each file, built on 2026-10-08 for
`tests/test_mobile_code.py`. None of it is challenge data and nothing here is ever run: the
tests only read the bytes.

| File | Built from | With |
| --- | --- | --- |
| `obj.hbc`, `json.hbc`, `lone.hbc`, `big.hbc` | `obj.js`, `json.js`, `lone.js`, `big.js` | `hermesc -emit-binary` of npm `hermes-compiler` 250829098.0.19 (bytecode version 98) |
| `*_old.hbc` | the same sources | `hermesc` of npm `hermes-engine` 0.11.0 (bytecode version 84) |
| `fields.dex`, `parts.dex`, `method.dex`, `array.dex`, `xorbytes.dex`, `twomethods.dex` | the `.java` file of the same name (class `com.huntress.fixture.Puzzle`) | `javac --release 8`, then D8 of R8 8.5.35 with `--min-api 21` |
| `Fix.dll` | `Fix.cs` (a class library, `net10.0`, version 9.8.7.6, company `Huntress Fixture Co`) | `dotnet build -c Release`, SDK 10.0.400 |

`Fix.dll` is also the PE with a version resource that `tests/test_metadata_formats.py` reads.
