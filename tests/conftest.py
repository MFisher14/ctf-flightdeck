"""Shared test setup.

Textual reads a few environment variables that would make headless runs press keys or
take screenshots on their own; clear them so tests only see what they do themselves.
"""

from __future__ import annotations

import os

for _name in list(os.environ):
    if _name.startswith(("TEXTUAL_PRESS", "TEXTUAL_SCREENSHOT")):
        del os.environ[_name]
os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"  # plain CLI output in CliRunner
