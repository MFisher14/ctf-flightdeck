# lattice_templates: starting lattices for the common cases

`solvers/common/lattice_templates.py` (B-157). Each template builds an integer row basis, the basis is
reduced through `algebra_service` (so the backend is named and BKZ is never swapped for LLL), and the
template reads candidates off the reduced rows and returns only those that pass its own exact check.

```sh
python -m ctf run common.lattice_templates list
python -m ctf run common.lattice_templates basis job.json          # the basis only, to inspect or change
python -m ctf run common.lattice_templates solve job.json          # --method lll|bkz --block-size N --backend B
```

`job.json` is `{"template": "<name>", "args": {...}}`; integers may be numbers or decimal / `0x` strings.

| template | args | solves | returned value is checked by |
|---|---|---|---|
| `bounded_linear` | `matrix`, `rhs`, `moduli`, `bounds` | x with low <= x_j <= high and A·x = b (mod m_r, or over the integers where the modulus is null) | the bounds and every equation |
| `short_kernel` | `matrix`, `moduli`, `widths` | a non-zero x with \|x_j\| <= w_j and A·x = 0 | the widths and every equation |
| `hidden_number` | `modulus`, `samples` ([t, a] pairs), `bound`, `secret_bound` | x with (a_i + t_i·x) mod q < bound for every sample | every inequality |
| `truncated_lcg` | `multiplier`, `increment`, `modulus`, `highs`, `unknown_bits` | the first full state from truncated outputs | regenerating every output |
| `subset_sum` | `values`, `target` | 0/1 choices with the exact sum (low density) | the exact sum |
| `modular_ratio` | `h`, `modulus`, `f_bound`, `g_bound` | small f, g with f·h = g (mod q) | the bounds and the congruence |
| `integer_relation` | `values`, `bound` | small c with sum c_i·v_i = 0 | the bound and the sum |

```python
import lattice_templates as lt
t = lt.hidden_number(q, samples, bound)             # Template(name, basis, extract, notes)
lt.solve(t)                                         # LLL on the auto backend
lt.solve(t, method="bkz", block_size=30, backend="sage-image")
found, res = lt.solve_detailed(t, method="bkz")     # ([], blocked result) when no backend can run BKZ
t.extract(rows)                                     # your own reduced rows, from any tool
```

How to use them:

- An empty list means this reduction did not expose a solution. Raise the method (`bkz`), the block
  size or the number of samples, or rethink the lattice. It does not mean there is none.
- A returned value satisfies the stated constraints exactly. Whether it is *the* secret is the
  challenge's check (the public key, a decryption): do that before you call it an answer.
- `bounded_linear` is the general form: hidden number, truncated LCG, modular knapsack and partial-key
  problems all reduce to it. Its lattice has one extra row and column per modular equation; the
  dedicated templates use the compact classic lattice.
- For an ECDSA/DSA nonce leak with a public key in hand, `lattice_nonce` and `ecdsa_recovery` check the
  recovered key against the key for you; these templates are for the cases they do not cover.

Overlap with older engines (known, not yet merged): `lattice_tools.solve_subset_sum` builds the same
low-density subset-sum embedding (plus a meet-in-the-middle path), `common.lattice_nonce` covers the
hidden-number problem for signatures, and `toolkits.prng_recovery` routes "truncated lcg". Those
engines reduce on their own and do not call these templates, so there are two subset-sum lattice
constructions. The router keeps the dedicated engines first (this engine's route priority is 59).
Folding `solve_subset_sum`'s lattice path onto `lattice_templates.subset_sum` is follow-up B-157-F2.
