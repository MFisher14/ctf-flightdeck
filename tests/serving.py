"""Serving a fake server on a background thread, and stopping it at once.

socketserver's serve_forever() sees shutdown() only between two polls of its socket: every
fake a test left cost half a poll on average (25 ms at the fakes' 50 ms, 250 ms at the
default), in a suite that starts thousands of them. The loop here waits on the listening
socket and on a wake-up socket together: stop() returns as soon as the loop is out, which is
as soon as the thread runs, and a server nobody talks to never wakes.

Stopping only ends the accept loop, as shutdown() did: what a fake does about connections
still open and requests still being answered (its close(wait=...)) is its own, after stop().

closed_port() is the other end: a port on 127.0.0.1 that refuses connections, for the tests
of a server that is not there.
"""

from __future__ import annotations

import selectors
import socket
import socketserver
import threading

# Ports only root can listen on (below 1024), none in use on a machine that runs no inetd
# services: discard, tcpmux, echo, daytime, chargen.
_NEVER_LISTENING = (9, 1, 7, 13, 19)


def closed_port() -> int:
    """A port on 127.0.0.1 that refuses connections, now and for as long as the test lasts.

    Not a free port taken and given back (bind to port 0, read its number, close): between
    giving it back and the test's connection, and through every retry after that, another
    test process may be given that very port for a fake server of its own (pytest -n runs
    several), and the test would then be answered instead of refused. A port below 1024 is
    never handed out that way. The one returned is checked to refuse a connection first; a
    machine where all of them answer fails here, by name."""
    for port in _NEVER_LISTENING:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
        except ConnectionRefusedError:
            return port
        except OSError:
            continue  # filtered rather than refused: not a port that answers "nobody here" at once
    raise AssertionError(f"every one of the ports {_NEVER_LISTENING} on 127.0.0.1 answers or is filtered: "
                         "the tests of a server that is not there need one that refuses connections")


class Serving:
    """`server` accepting connections on a daemon thread named `name`, from now until stop()."""

    def __init__(self, server: socketserver.BaseServer, name: str) -> None:
        self._server = server
        self._wake, self._woken = socket.socketpair()
        self._thread = threading.Thread(target=self._accept, name=name, daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        with selectors.DefaultSelector() as selector:
            selector.register(self._server, selectors.EVENT_READ)
            selector.register(self._woken, selectors.EVENT_READ)
            while True:
                ready = [key.fileobj for key, _ in selector.select()]
                if self._woken in ready:
                    return
                self._server.handle_request()  # a connection is waiting: this accepts it and hands it on

    def stop(self) -> None:
        """End the accept loop and join its thread. Connections not yet accepted stay unanswered."""
        self._wake.send(b"\0")
        self._thread.join()
        self._wake.close()
        self._woken.close()
