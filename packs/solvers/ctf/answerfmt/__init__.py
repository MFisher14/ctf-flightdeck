"""The answer-format renderer: every answer formatted from its question's answer_format (B-232).

Contract (docs/CONTRACTS.md section 48; each module's docstring is the detail):

    contract.read(answer_format, question_text=None) -> Contract      what the format states
    rendering.render(value, answer_format=None, question_text=None, ordered=False, contract=None) -> Rendering
    rendering.render_answers(questions, answers, answer_ids=None) -> Batch  a whole delivery
    synth.route(answer_id) / synth.answer(...) / synth.covered(...)    multi-file synthesis by id suffix
    wire.wire(question, value, lane) / wire.to_wire(rendering, key)    to labels' plain / unsure form
    shellword.word(text, i) / words(text) / assignment(text)           shell word concatenation

Lane-blind and offline: no network, no model, no file read except synth.files_from_dir and wire's
load of solvers/common/labels.py through ctf.packs.
"""
from __future__ import annotations

from .contract import CONTAINERS, ORDERS, AnswerFormatError, Contract, read
from .rendering import (MAX_OPTIONS, OPTIONS, PLAIN, WITHHELD, Batch, Rendering, render, render_answers)

__all__ = ["AnswerFormatError", "Contract", "read", "ORDERS", "CONTAINERS", "Rendering", "Batch", "render",
           "render_answers", "PLAIN", "OPTIONS", "WITHHELD", "MAX_OPTIONS"]
