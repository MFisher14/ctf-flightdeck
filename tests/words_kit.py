"""One word, one meaning: where help and the README say "key" or "token".

A bare "key" is one on the keyboard, so what is not one says what it is: an API key, the keys
file, or an option's own name (`--key-env`, `api-key`). The same for "token": an access token
(or a named kind of one), model tokens, tokens counted beside a price or a budget, an option's
name (`--token-env`, `--budget-tokens`); and "the token" only where the same passage has just
named which token.
"""

from __future__ import annotations

import re

_KEY_OK = (r"API keys?\b", r"keys file\b", r"[-\w]-keys?\b", r"\bkey-[a-z]")
_TOKEN_OK = (r"access tokens?\b", r"Game Master tokens?\b", r"model tokens\b", r"million tokens\b", r"budget in tokens\b",
             r"[-\w]-tokens?\b", r"\btoken-[a-z]")
_NAMED_TOKEN = re.compile(r"access token|Game Master token")


def bare(text: str, word: str) -> list[str]:
    """Each place `text` says `word` ("key" or "token", or its plural) without saying which
    kind, with the words around it: up to 40 characters before, and 20 after."""
    allowed = {"key": _KEY_OK, "token": _TOKEN_OK}[word]
    fine = [match.span() for pattern in allowed for match in re.finditer(pattern, text)]
    found = []
    for match in re.finditer(rf"\b{word}s?\b", text):
        if any(start <= match.start() and match.end() <= end for start, end in fine):
            continue
        if word == "token" and text[max(0, match.start() - 4):match.start()] == "the " \
                and _NAMED_TOKEN.search(text[max(0, match.start() - 220):match.start()]):
            continue  # "its name, not the token": the sentence before said which
        found.append(text[max(0, match.start() - 40):match.end() + 20].strip())
    return found


def bare_words(text: str) -> list[str]:
    """Every bare "key" and every bare "token" of `text` (bare())."""
    return bare(text, "key") + bare(text, "token")
