"""Token ledger: read Claude Code / Codex session logs and price the usage in USD.

Ported from the token-ledger study (analysis/token_ledger.py + analysis/price_ledger.py, untracked):
same record shapes, same de-duplication, same rates (pricing.json). Used two ways:

    python -m tools.ledger price --harness claude LOG...          after the event: totals per model
    python -m tools.ledger feed --challenge ID --harness claude LOG...
                                                   during the event: charge new spend to the challenge's
                                                   budget (ctf.budget.LedgerMeter); exit 3 at the cap
    python -m tools.ledger fallback [--event E] [--record] LOG...
                                                   B-100: sessions a safety classifier moved off the
                                                   primary model, and the premium paid; exit 5 if any

Modules: pricing (rates and cost), scan (log parsers), live (incremental feed into a Meter),
fallback (the classifier-fallback detector), usage + sources (B-193: the shipped per-response usage
ledger behind `python -m ctf usage`, which does discover the event's logs by working folder).
Point it at the logs of agents working one challenge; it never discovers logs by itself.
"""
