"""The egress proxy of a fenced Docker lane (agent/egress.py): a TCP forwarder with a fixed list.

flightdeck starts it in a container of its own, from the lane image, as
`python3 -I -c <this file's text> <config>`: standard library only, nothing imported from
flightdeck, and nothing read from the lane. The container is on Docker's bridge network (the
way out) and on the lane's internal network (the only network the lane's container is on).

<config> is JSON: {"routes": [{"listen": PORT, "host": HOST, "port": PORT}, ...],
"bind": ADDRESS (optional, default 0.0.0.0)}. Each route is one TCP service the lane may
reach: what connects to `listen` here is carried, byte for byte, to HOST:PORT, and nothing
else is listened on, so nothing else is reachable through it. No byte the lane sends picks
where a connection goes.

Every HOST is resolved once, before the first listener opens, and only those addresses are
used afterwards: once this container joins the lane's network it answers to the instance's
own name there, so a later lookup of that name would find this proxy. When every route is
resolved and every listener is open it prints READY on a line; when one cannot be, it prints
why and exits with status 2.
"""

import asyncio
import json
import socket
import sys

READY = "flightdeck-egress ready"
CONNECT_TIMEOUT = 15.0  # seconds to reach an instance before the lane's connection is closed
CHUNK = 65536


def read_config(text):
    """(bind address, [(listen port, host, port)]) from the JSON; ValueError when it is not that."""
    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError("the configuration is not JSON") from None
    routes = data.get("routes") if isinstance(data, dict) else None
    if not isinstance(routes, list) or not routes:
        raise ValueError("the configuration names no routes")
    bind = data.get("bind", "0.0.0.0")
    if not isinstance(bind, str):
        raise ValueError("bind is not an address")
    found, taken = [], set()
    for route in routes:
        listen, host, port = (route.get(key) for key in ("listen", "host", "port")) if isinstance(route, dict) else (None,) * 3
        if not (_is_port(listen) and _is_port(port) and isinstance(host, str) and host):
            raise ValueError("a route is not {listen: port, host: name, port: port}")
        if listen in taken:
            raise ValueError("two routes listen on port %d" % listen)
        taken.add(listen)
        found.append((listen, host, port))
    return bind, found


def _is_port(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 65536


def resolve(host, port):
    """The addresses of host:port, as (family, sockaddr), each once; OSError when it has none."""
    found = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        if (family, sockaddr) not in found:
            found.append((family, sockaddr))
    if not found:
        raise OSError("no address")
    return found


async def _connect(addresses):
    """A connection to the first address that takes one, each tried within what is left of
    CONNECT_TIMEOUT; None when none does."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + CONNECT_TIMEOUT
    for family, sockaddr in addresses:
        left = deadline - loop.time()
        if left <= 0:
            break
        try:
            return await asyncio.wait_for(asyncio.open_connection(sockaddr[0], sockaddr[1], family=family), left)
        except (OSError, asyncio.TimeoutError):
            continue
    return None


async def _carry(reader, writer):
    """Bytes from reader to writer until reader ends; then writer is told no more come."""
    try:
        while True:
            data = await reader.read(CHUNK)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (OSError, asyncio.CancelledError):
        pass


async def _serve(addresses, reader, writer):
    there = await _connect(addresses)
    if there is None:
        writer.close()
        return
    up_reader, up_writer = there
    try:
        await asyncio.gather(_carry(reader, up_writer), _carry(up_reader, writer))
    finally:
        for end in (writer, up_writer):
            try:
                end.close()
            except OSError:
                pass


async def serve(bind, routes, announce=print):
    """Resolve every route, open every listener, say READY, then forward until cancelled."""
    resolved = []
    for listen, host, port in routes:
        try:
            resolved.append((listen, resolve(host, port)))
        except OSError as exc:
            raise SystemExit("cannot find the address of %s: %s" % (host, exc.strerror or exc))
    servers = []
    for listen, addresses in resolved:
        try:
            servers.append(await asyncio.start_server(
                lambda reader, writer, addresses=addresses: _serve(addresses, reader, writer), bind, listen))
        except OSError as exc:
            raise SystemExit("cannot listen on port %d: %s" % (listen, exc.strerror or exc))
    announce(READY)
    await asyncio.gather(*(server.serve_forever() for server in servers))


def main(argv):
    if len(argv) != 2:
        print("usage: egress_proxy.py CONFIG_JSON")
        return 2
    try:
        bind, routes = read_config(argv[1])
    except ValueError as exc:
        print("flightdeck-egress: %s" % exc, flush=True)
        return 2
    try:
        asyncio.run(serve(bind, routes, announce=lambda line: print(line, flush=True)))
    except SystemExit as exc:
        print("flightdeck-egress: %s" % exc, flush=True)
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
