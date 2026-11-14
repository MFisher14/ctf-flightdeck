"""Network guard for engines that intake runs (B-002). Started as

    <python> -I ctf/intake/_guardboot.py --mode hook|os -- <script> [args...]

It installs a Python audit hook (it cannot be removed afterwards) and then runs <script> as __main__ in
this same interpreter; intake passes ctf/engines/_boot.py there, so the engine runs exactly as
`ctf run` would run it, with the hook in place. Self-contained on purpose: with -I the checkout is not
on sys.path until the engine boot puts it there, and the hook must be in before that.

The hook refuses, with PermissionError naming the event:
  - creating a socket of any family but AF_UNIX, and connect/bind/sendto/sendmsg on one;
  - every name lookup (getaddrinfo, gethostbyname, gethostbyname_ex, gethostbyaddr, getnameinfo);
  - mode hook only: everything that would leave the hook behind, because what runs there does not
    carry it: starting another program (subprocess, os.system, os.exec*, os.posix_spawn*, os.spawn*);
    `_posixsubprocess.fork_exec`, the call multiprocessing's spawn and forkserver use without the
    subprocess module (replaced by a refusing function before the hook goes in, and a fresh copy of
    the module may not be imported); a sub-interpreter (the modules that create one may not be
    imported); and ctypes (the import of `_ctypes` is refused). Import refusals are ImportError, so a
    library that treats ctypes as optional carries on without it. Mode os runs under an OS network sandbox (sandbox-exec, unshare) that every
    child inherits, so all of these are allowed there.
Not covered (docs/CONTRACTS.md section 19): a compiled extension module that opens a socket in C
without an audit event. Mode hook is a Python-level fence; mode os is the boundary.
"""
import sys

NAME_EVENTS = frozenset({"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex",
                         "socket.gethostbyaddr", "socket.getnameinfo"})
SOCKET_EVENTS = frozenset({"socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg"})
SPAWN_EVENTS = frozenset({"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
                          "os.startfile", "pty.spawn"})
# Mode hook only. A sub-interpreter gets none of this interpreter's audit hooks, and refusing its
# creation from the hook (cpython.PyInterpreterState_New) crashes CPython 3.12, so the modules that
# create one are refused at import instead.
REFUSED_IMPORTS = frozenset({"_ctypes", "_posixsubprocess", "_xxsubinterpreters", "_interpreters",
                             "_testinternalcapi", "_testcapi"})


def _disable_fork_exec(refuse) -> None:
    """Replace _posixsubprocess.fork_exec (imported now, before the hook) with a refusing function, so
    `multiprocessing.util.spawnv_passfds` and `subprocess` both get the refusal."""
    try:
        import _posixsubprocess
    except ImportError:               # not a POSIX build: nothing to replace
        return

    def fork_exec(*args, **kwargs):
        refuse("_posixsubprocess.fork_exec: starting another program needs the OS network sandbox, "
               "which this run does not have")
    _posixsubprocess.fork_exec = fork_exec


def install(allow_spawn: bool) -> None:
    import socket
    unix = getattr(socket, "AF_UNIX", None)

    def refuse(what: str):
        raise PermissionError(f"intake network guard: {what} refused (engines run with network denied)")

    if not allow_spawn:
        _disable_fork_exec(refuse)

    def hook(event, args):
        if not allow_spawn and event == "import" and args[0] in REFUSED_IMPORTS:
            raise ImportError(f"intake network guard: import of {args[0]} refused (it would get past the "
                              "audit hook; it needs the OS network sandbox, which this run does not have)",
                              name=args[0])
        if event == "socket.__new__":
            family = args[1]
            if family != unix and family != -1:      # -1: from a file descriptor; checked on use
                refuse(f"{event} (family {family})")
        elif event in SOCKET_EVENTS:
            family = getattr(args[0], "family", None)
            if family != unix:
                refuse(f"{event} (family {family})")
        elif event in NAME_EVENTS:
            refuse(event)
        elif not allow_spawn and event in SPAWN_EVENTS:
            refuse(f"{event}: what it starts would run without the audit hook, so it needs the OS "
                   "network sandbox, which this run does not have")

    sys.addaudithook(hook)


def main(argv: list) -> int:
    if len(argv) < 4 or argv[0] != "--mode" or argv[1] not in ("hook", "os") or argv[2] != "--":
        print("_guardboot: usage: --mode hook|os -- <script> [args...]", file=sys.stderr)
        return 2
    install(allow_spawn=argv[1] == "os")
    import runpy
    sys.argv = list(argv[3:])
    try:
        runpy.run_path(sys.argv[0], run_name="__main__")
    except SystemExit as e:
        if e.code is None:
            return 0
        if isinstance(e.code, int):
            return e.code
        print(e.code, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
