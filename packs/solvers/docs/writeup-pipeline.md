# Writeup and retro pipeline (B-098, B-097)

`python -m ctf writeup` turns the evidence saved while solving into writeup drafts and retros, checks
them for leaks, and builds the public tree with a publish plan. **Publishing is a dry run**: nothing
here runs git or gh, creates a repository or pushes.

```
workdir (<id>-<slug>/ folders + ledger.jsonl)
  └─ draft    -> <staging>/<id>-<slug>/README.md, solve/, STATUS.md        (private)
  └─ retro    -> <staging>/retro/<day or window>.md                        (private)
staging
  └─ assist   -> the TODO prose, drafted on models.docs                     (B-097)
  └─ review   -> the one pass on models.primary over pending drafted text   (B-097)
staging
  └─ check    -> leak findings, exit 1 on a blocking one
  └─ publish  -> <workdir>/writeups-public/ + writeups-public.publish-plan.json   (dry run)
```

Defaults: workdir `ctf.paths.workdir()` (`$CTF_WORKDIR`, else `~/ctf-work/<event>`), staging
`<workdir>/writeups`. Staging and public trees may not live inside the checkout, except under the
gitignored `writeups/` folder.

## Policy (from the event profile only)

| profile key | effect |
|---|---|
| `rules.flag_sharing = "forbidden"` | always redact; the profile may not set `redact_flags = false` |
| `writeups.redact_flags` | redact flags when true (default) |
| `writeups.publish_hold` | default true: the `hold` gate stays closed until the player's go |
| `writeups.public_repo` | the repo the plan names; the `repo` gate needs it |
| `dates.end` | the `ended` gate: a bare date ends at the next midnight UTC |
| `platform.base_url`, `rules.live_service_scope` | URLs on these hosts block as `instance-url`, bare hostnames on them (`nc host port`, `ssh user@host`) as `instance-host` |

## Draft

One README per challenge in the 2026 staging shape (Challenge, Status, Flag, Files, Recon, Solve path,
Dead ends, Reproduce, Takeaways) from `templates/writeup/challenge.md.tmpl`. Facts are filled from the
evidence: challenge.json, the file list, the engine runs and submissions in the ledger, the saved
solver scripts. The prose sections are `<!-- TODO -->` markers for a person or `ctf writeup assist`
(below), and publish refuses a file that still has one. The solve log (notes.md, and writeup.md when an
agent kept one) goes in a `<!-- private -->` block that never leaves staging. When the event redacts,
the draft holds no flag value at all.

Re-running refreshes drafts from new evidence, but keeps any file edited by hand
(`writeup-state.json` holds what the pipeline wrote); `--force` overwrites.

## Retro

`ctf writeup retro --day 2026-11-07` (or `--since/--until`, or nothing for the whole event) builds the
summary, where-the-time-went, spend, engine, stop and unsolved tables and the timeline from the ledger,
with TODO markers for recommendations and open questions. The timeline shows a fixed set of fields;
`flag`, `flag_sha256` and free-text fields such as `provenance` never appear.

## Assist and review (B-097): the prose on the docs model, one pass on the primary model

`ctf writeup assist` writes the `<!-- TODO -->` prose of every staged writeup and retro;
`ctf writeup review` is the one review pass. Both take `--dry-run` (no model is called: the jobs are
listed and each brief is written to `<staging>/.assist/briefs/`), `--only REL` (a staging-relative
file) and `--claude-bin`. A brief is a fixed template (`templates/writeup/assist-draft.md.tmpl`,
`assist-review.md.tmpl`) plus that one file's evidence and its solver scripts, clipped, and redacted
again when the event redacts. It is never a whole session's context.

Routing is by task type only, from the profile's `[models]` table. There is no `--model` option.

| task | what | model | pass after the draft |
|---|---|---|---|
| `writeup` | challenge README sections | `models.docs` (default Sonnet 5.5) | pending: `review` runs it |
| `writeup-primary` | README of a `models.docs_on_primary` category (default `pwn`) | `models.primary` | done (the draft is the pass) |
| `retro-recommendations` | retro rows that change a solver's behaviour | `models.primary` | done |
| `retro-questions` | retro open questions (private) | `models.docs` | none needed |
| `review` | every block the gate blocks, except `pass=none` | `models.primary` | done (pending again if the harness ran it outside the primary tier) |

Each call runs `claude -p --model <routed> --output-format json --tools ""` with the solver fence's
settings (B-219), from an empty scratch folder that is deleted afterwards. The brief goes in on stdin.
Drafted text is neutralized (it cannot open, close or forge a comment marker), redacted when the event
redacts, and wrapped as

    <!-- drafted by=<model that ran> task=<task> pass=pending|none|<model>|person -->
    ...
    <!-- /drafted -->

`check` and `publish` block `unreviewed-draft`, `unclosed-draft` and `stray-draft-close`. The gate
fails closed: a block clears only with `pass=person`, `pass=<models.primary>` or `pass=<a
models.fallback id>` of this event's profile, compared case-insensitively. `pending`, a missing pass,
a typo and any other model (the docs model included) block. `pass=none` passes `check` only on a
retro's open questions, and publish never accepts it. A person who reviewed a block by hand writes
`pass=person`. `STATUS.md` reports a README whose drafted text still blocks as `drafted, review
pending (N block(s))`, not `complete` (it is regenerated by `ctf writeup draft`).

The model named in `by=` (and in `pass=` after a review) is the one the CLI's `modelUsage` reports,
when that key is a valid model id. The routed model's dated form (`<model>-YYYYMMDD`) counts as the
routed model. Any other key is not trusted: the routed model is named and the ledger record says
`model_reported: false`.

Retro recommendations are drafted on the primary model directly, as their one pass. A retro has one
recommendations slot, and a review brief carries the same evidence as the draft brief, so drafting it
on the docs model first and then reviewing it would add a call and save only that slot's output
tokens.

A decline (the stop reason `refusal`, whatever the exit code, the model's `<<<DECLINE>>>` line, or a
reply with no answer block at all, which is how a refusal in prose looks) is recorded and the job is
not sent again with the same brief. It is never moved to another model: the sections stay TODO for a
person. A reply that has answer blocks but breaks the format is rejected whole (`bad-output`, and it may be
sent again), and so is one whose file changed while the model ran. Every call is a `writeup.assist` record in the event ledger, with the model asked for, the
model the harness reports it ran on (a classifier move shows here, and the block's `by=` says so),
the outcome, the harness's own `total_cost_usd` and the token count. The retro summary totals these
records on their own line, beside the `spend` line. Exit 1 when any job did not finish.

## Check and publish

Only text files with a known suffix leave staging. Private records (STATUS.md, SOURCE.md,
NEEDS-PLAYER-INPUT.md, event.json, solves.json, writeup-state.json, workspace bookkeeping) are excluded,
as are hidden and `_` paths and the `files/`, `retro/`, `attachments/` and `screenshots/` folders.
Images and binaries are listed in the plan as excluded, so publishing one is a visible human decision.

Redaction (when the event redacts): the body of every Flag section; every known value (confirmed flags,
every attempt, ledger flags, values harvested from any Flag section in the tree), in any case; every
token in the event format with the prefix in any case; bare inner bodies of known flags of six or
more characters; and every token whose sha256 matches a ledger `flag_sha256` (an event that forbids
sharing records submissions only as the hash). A hashed value is matched as a token: a
whitespace-separated word, or a piece of one split at quotes, brackets, `=`, `:`, `,` and `;`. Once
matched in any file, it is redacted everywhere, including inside longer tokens. A value containing
whitespace is not matched by hash (the event format still catches a wrapped one).

The scan blocks on secrets (JWT, bearer; authorization and cookie headers in raw, dict or JSON form;
`cookies={...}`, `cookies=dict(...)`, `cookies.set(...)` and `cookies[...] = ...` with a literal value; a
session or token key with a literal value in a dict; credentials in a URL; private keys; cloud and API
tokens), instance URLs and bare instance hostnames, non-loopback IPv4, UUIDs, 32+ hex runs, TODO and
CHECK markers and unclosed private blocks; and, when redacting, on any remaining event flag, known
value, fragment or flag-shaped `X{...}` token. Placeholder values (`<...>`, `{...}`, `$VAR`) are not
secrets. External URLs are notes, and their previews drop credentials, the query and the fragment.
`publish-allow.txt` in staging accepts an exact token, or `@<kind> <path glob>`, for the kinds
flag-shaped, uuid, longhex and external-url only.

`check` and `publish` read the known values and flag hashes from the workdir. Without one,
`--pattern-only` must be given, and the plan records it.

The publish plan (`<out>.publish-plan.json`, outside the tree, and like the trees never elsewhere in
the checkout than the gitignored `writeups/`) lists the gates, every file with its
sha256 and redaction count, the exclusions, the masked findings and `would_run`: the git and gh
commands a person runs after the player's go. Exit 0 means every gate passed.
