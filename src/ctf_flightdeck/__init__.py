"""ctf-flightdeck: a terminal harness for playing CTFs with AI agents."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ctf-flightdeck")  # pyproject.toml's version, as installed: one place to bump
except PackageNotFoundError:  # the source tree imported without an install: say so rather than guess
    __version__ = "unknown (not installed)"
