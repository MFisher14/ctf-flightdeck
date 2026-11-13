"""The look-ahead completeness gate (B-174): a forecast is green only when tomorrow's stated
deterministic work is covered, not when known readers have merely not become wrong.

Huntress Day 28: the pre-release look-ahead reported 11,964 specimens and 131,604 ids with zero wrong
answers and exited 0. It hid 11,362 unanswered answers, skipped all 190 Script members (44 Terraform
ids among them), and treated 1,018 deterministic gaps as information. Binary then met twenty stated
computations it had left as "safe None" (+15:56 on the base), Warmups crossed an untested 256 KiB
delivery threshold (+18:46 on the Mastery), and Metadata met one GPT field nobody had forecast. Every
coverage build followed a bad morning. This package makes the look-ahead a release gate:

    matrix    the forecast matrix on disk (matrix.toml, one folder per specimen: specimen.toml,
              questions.json, files/, optional key.json) and its rules: each question is
              deterministic unless declared judged; each specimen's encoding chain must really hold
              on its bytes (a substituted encoding is a gap, the Day 16 hidden bug)
    gate      runs a lane's `solve_set` reader over every specimen in one guarded child process
              (intake network guard, per-specimen cap) and evaluates: FAIL on a wrong answer, on an
              unanswered or unsure deterministic question, on a skipped, crashed or cut specimen, on a newest-
              base id no specimen asks, on a declared size threshold no specimen crosses, on a real
              encoding no specimen exercises, and on a lane with nothing exercised. One
              `lookahead.gate` ledger record per lane.
    computed  the computed-field tier: strictly gated stated computations over the delivered
              members (member count, size, digest, digest of digests). The gate runs it on ids the
              reader left unanswered to show the value that is ready; `wrap(solve_set)` is how a lane
              adopts it at run time. An id only the tier answers is still a gap.
    scale     size thresholds: `scan` finds size constants and len() comparisons in code, `undeclared`
              lists those a matrix neither declares nor waives, `replicate` builds the multi-set scale
              specimen that crosses a threshold
    forecast  `score` a forecast against the day (which new or changed ids it named, which it missed,
              which release gaps it missed; one `lookahead.score` record) and `plan` the next
              look-ahead: an agent only for a lane with a new shape or an open gap
    daily     the daily look-ahead of a rolling-release event (B-256): lanes from the profile through
              forecast.plan, the day-lookahead workflow args, and finish (README naming every lane,
              `<lane>: NOT staged` for one whose agent failed twice; forecast.toml for score)
    tagged    no-model staging of where the TAGGED copy lives, per language family (row 355)
    fixtures  no-model computed-field specimens through the lane's real encodings (row 494)

`python -m ctf lookahead gate|thresholds|scale|score|plan` is the command (ctf/cli/lookahead.py);
`python -m ctf lookahead-daily prepare|finish` runs the daily workflow's no-model halves. The
contract is docs/CONTRACTS.md section 35. Nothing here talks to a platform or starts a model.
"""
from __future__ import annotations


class LookaheadError(ValueError):
    """A matrix, specimen, forecast or report is unusable; the message names what and why."""


__all__ = ["LookaheadError"]
