#!/usr/bin/env python3
# Copyright (c) 2026, LunLink contributors
# SPDX-License-Identifier: BSD-2-Clause

"""A TCP proxy for exercising the recovery of iSCSI sessions.

Forwards connections made to a local port to a target portal.  Terminating
the proxy severs all connections and makes the portal unreachable, which is
what a network outage looks like to the initiator; starting it again makes
the portal reachable again.

usage: tcpproxy.py <listen-port> <target-host> <target-port>
"""

import asyncio
import sys


async def pump(reader, writer):
    try:
        while True:
            data = await reader.read(1 << 16)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def handle(reader, writer, host, port):
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
    except OSError:
        writer.close()
        return
    await asyncio.gather(pump(reader, upstream_writer), pump(upstream_reader, writer))


async def main():
    listen_port, host, port = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])

    async def on_connect(reader, writer):
        await handle(reader, writer, host, port)

    server = await asyncio.start_server(on_connect, "127.0.0.1", listen_port)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
