"""Platform adapters: where a board's challenges come from and how flags are checked.

M1 has the folder board (manual.py): challenge directories on disk, with an optional
answers file of flag hashes. A CTFd adapter follows in M2.
"""

from .manual import AnswerVerifier, Board, BoardChallenge, BoardError, cannot_check, load_board

__all__ = ["AnswerVerifier", "Board", "BoardChallenge", "BoardError", "cannot_check", "load_board"]
