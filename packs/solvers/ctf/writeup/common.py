"""Shared pieces of the writeup pipeline: template rendering, the output-folder guard and the
generated-file state that keeps a hand-edited draft from being overwritten.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .. import paths

TEMPLATE_DIR_PARTS = ("templates", "writeup")
PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")
STATE_NAME = "writeup-state.json"


class WriteupError(ValueError):
    """A configuration or input problem the pipeline will not guess around (named in the message)."""


def template_dir() -> Path:
    return paths.repo_root().joinpath(*TEMPLATE_DIR_PARTS)


def render(template: str, values: dict[str, str]) -> str:
    """Fill {{key}} placeholders in one pass (a value is never re-expanded). Every placeholder needs
    a value and every value needs a placeholder: a drifted template fails by name."""
    needed = set(PLACEHOLDER.findall(template))
    missing = sorted(needed - set(values))
    unused = sorted(set(values) - needed)
    if missing:
        raise WriteupError(f"template needs value(s) for: {', '.join(missing)}")
    if unused:
        raise WriteupError(f"template has no placeholder for: {', '.join(unused)}")
    return PLACEHOLDER.sub(lambda m: values[m.group(1)], template)


def load_template(name: str) -> str:
    p = template_dir() / name
    if not p.is_file():
        raise WriteupError(f"writeup template {p} is missing")
    return p.read_text(encoding="utf-8")


def neutralize(text: str) -> str:
    """Evidence text (challenge descriptions, solve logs) must not open or close a comment block in a
    draft: a stray `<!-- /private -->` in a solve log would end the private block early."""
    return text.replace("<!--", "&lt;!--").replace("-->", "--&gt;")


def cell(text: str) -> str:
    """One markdown table cell from untrusted text."""
    return " ".join(str(text).split()).replace("|", "\\|") or "-"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def guard_dir(p: Path | str, what: str) -> Path:
    """Staging and public trees hold flag values before redaction: they live outside the checkout
    (default under the workdir) or under the repo's gitignored writeups/ folder, never elsewhere in
    the repo where a commit could pick them up."""
    p = Path(p).expanduser().resolve()
    root = paths.repo_root().resolve()
    if p == root or root in p.parents:
        ok = root / "writeups"
        if not (p == ok or ok in p.parents):
            raise WriteupError(f"{what} {p} is inside the repo checkout; use a folder outside it (the default "
                               f"is under the workdir) or under the gitignored {ok}")
    return p


class State:
    """<staging>/writeup-state.json: the sha256 of each file as the pipeline last wrote it. A file
    whose bytes differ was edited by hand and is kept unless the caller forces a rewrite."""

    def __init__(self, folder: Path, slug: str):
        self.path = folder / STATE_NAME
        self.slug = slug
        data = {"event": slug, "generated": {}}
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                raise WriteupError(f"{self.path}: not valid JSON: {e}") from None
            if not isinstance(data, dict) or not isinstance(data.get("generated"), dict):
                raise WriteupError(f"{self.path}: not a writeup state file")
            if data.get("event") != slug:
                raise WriteupError(f"{self.path} belongs to event {data.get('event')!r}, not {slug!r}: "
                                   "use a separate staging folder per event")
        self.data = data

    def may_write(self, target: Path, rel: str, force: bool) -> bool:
        if force or not target.exists():
            return True
        return self.data["generated"].get(rel) == sha256_file(target)

    def record(self, rel: str, text: str) -> None:
        self.data["generated"][rel] = sha256_text(text)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
