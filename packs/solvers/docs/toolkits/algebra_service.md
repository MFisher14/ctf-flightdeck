# algebra_service: lattices and polynomial ideals on a named backend

`solvers/common/algebra_service.py` (B-157). One JSON job in, one checked JSON result out. It exists so
a crypto solve starts from a working lattice and ideal stack (LLL, BKZ, Groebner bases, varieties,
elimination, resultants, roots, Coppersmith small roots) instead of provisioning Sage mid-solve.
Choosing the lattice or the ideal is still your reasoning; `lattice_templates` (its own page) holds
the common lattice constructions.

```sh
python -m ctf run common.algebra_service status                    # what each backend can do here, and what is missing
python -m ctf run common.algebra_service run job.json              # --backend auto|python|sage|sage-local|sage-image
python -m ctf run common.algebra_service run job.json --backend sage-image --sage-version 10.5 --timeout 900
python -m ctf run common.algebra_service selftest --backend sage-image   # one known-answer job per operation
```

Exit codes: 0 ok, 1 error or timeout, 2 bad job, 3 blocked (a backend is missing: `needs_tool` and `fix`
say which and how).

## Jobs

| op | job fields | result | proof |
|---|---|---|---|
| `lll` | `basis` (integer rows, independent) | `basis`, `transform` (U with U·B = R) | exact |
| `bkz` | `basis`, `block_size` (2..rows, default 20), `tours` (optional) | the same | exact |
| `groebner` | `ring`, `vars`, `polys`, `order` (`lex`, `deglex`, `degrevlex`) | `basis` (strings), `basis_terms` | none |
| `variety` | `ring` (QQ or GF), `vars`, `polys` | `points` ({var: value}) | exact |
| `eliminate` | `ring`, `vars`, `polys`, `eliminate` (names to remove) | `basis`, `basis_terms` | partial |
| `resultant` | `ring`, `vars`, two `polys`, `var` | `poly`, `poly_terms` | partial |
| `roots` | `ring` (QQ or GF), one var, one poly | `roots` | exact |
| `small_roots` | `modulus`, `poly` (univariate), `bound`, `beta` (default 1), `epsilon` | `roots` ({root, divisor}) | exact |

- `ring`: `"QQ"`, `"GF(<prime>)"`, `"Zmod(<n>)"`, or `{"kind": ..., "modulus": ...}`. Integers may be
  JSON numbers or decimal / `0x` strings.
- A polynomial is a string (`"x^2 + 3*x*y - 7/2"`: integers, the names in `vars`, `+ - * / ^ **`,
  parentheses; `/` only by an integer constant) or a term list `[[coeff, [e0, e1, ...]], ...]`. It is
  parsed by the module's own small parser and never evaluated: Sage receives exponent tuples and
  integers under names it makes itself.
- The string parser runs in the calling process, before the worker and its timeout exist, so it is
  bounded by work instead: parentheses nest at most `MAX_NESTING` (64) deep, and expanding a job's
  polynomials (`(x + 1)^3000`, a constant to a huge power) may cost at most `MAX_PARSE_WORK` units,
  about 2-3 s of CPU. Past either cap the job is refused (exit 2, named reason). Send a big expansion
  as a term list, which is read in linear time.
- A rational value in a result is an `"n/d"` string.

```json
{"op": "variety", "ring": "GF(170141183460469231731687303715884105727)", "vars": ["x", "y"],
 "polys": ["x + y - 1311768467294899695", "x*y - 5873374973378024329842141765701"]}
```

## What `proof` means

- **exact**: checked here, whatever the backend said. For `lll`/`bkz` the backend returns two integer
  transforms and the service multiplies them out (U·B = R and V·R = B), so the reduced rows span
  exactly the input lattice. For `variety`, `roots` and `small_roots` every returned value is
  substituted into your polynomials. One failing value turns the whole result into `error`.
- **partial**: only "the eliminated variable is absent" is checked. Confirm by substituting a known
  point, or take roots with `roots`/`variety` (those are exact).
- **none**: a Groebner basis cannot be checked by substitution. Do not read a secret off it without
  running `variety` or checking the value against the challenge.

Completeness (that a variety lists every solution) is the backend's claim, and a variety holds the
points of the ring's own field only (no algebraic extensions).

## Backends

| backend | runs | needs |
|---|---|---|
| `python` | in-repo exact LLL; BKZ through a local fpylll (`lattice_backends`); SymPy for ideals over QQ and GF(p); in-repo Coppersmith | fpylll for `bkz`; no `Zmod(n)` ideals |
| `sage-local` | a `sage` on PATH | SageMath installed |
| `sage-image` | the pinned `ctf-sage:<version>` image, no network, never pulled | the image built and fresh: `python -m ctf toolchain status` |
| `sage` | `sage-local` if there is one and no version was asked for, else `sage-image` | |
| `auto` | `python` when the job fits it (48 rows; 6 variables, 400 terms, degree 12; small-roots degree 6), else `sage` | |

Rules: the backend that ran is in the result (`backend`, `detail`). Nothing is installed, pulled or
built. BKZ with no fpylll and no Sage is `blocked`, never an LLL result. `--sage-version 10.5` always
uses the pinned image of that release (`python -m ctf toolchain versions <challenge files>` tells you
which release a challenge asks for); a Sage that reports another release is `blocked`. A job is killed
at `--timeout` (default 300 s; inside Sage it is also an alarm). The python child starts as `python -I`,
so PYTHONPATH and the working folder cannot plant modules in it. The image backend names its container
`ctf-algebra-<random>`; killing the `docker` client does not stop a container, so on the outer timeout
(the job's timeout plus 180 s for container start) the service runs `docker kill` on that name, and
only that one, and says in `reason` whether it worked.

## From Python

```python
import algebra_service as alg                       # flat import, like every solvers/common engine
res = alg.execute(job, backend="auto", sage_version=None, timeout=300)   # ServiceResult
res.status, res.backend, res.proof, res.result      # ok | blocked | error | timeout
res.require()                                       # the result, or BackendUnavailable / ServiceError
rows = alg.reduce_basis(basis, method="bkz", block_size=30, backend="sage-image")   # verified rows or it raises
alg.backend_status(); alg.selftest(backend="python")
```

## Limits, said plainly

- The Sage worker has never run under real SageMath in build work (no image may be built or pulled
  there). It is tested against a fake `sage` package, which proves the worker's and the service's own
  code but not Sage's API. Run `selftest --backend sage-image` once after building the images.
- The python backend is exact and slow: use it for small systems and as a cross-check.
- No lattice or ideal is chosen for you.
