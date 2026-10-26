"""Entry point: ``python -m ghidra_fleet`` (stdio MCP server).

stdio MCP puts the JSON-RPC channel on stdout, while the embedded Ghidra JVM
(and Ghidra's own logging) writes to file descriptor 1 natively. To keep the
protocol clean we:

1. dup the real stdout fd and hand the copy to the MCP layer via sys.stdout,
2. point fd 1 itself at stderr so all native/JVM output lands on stderr.
"""

from __future__ import annotations

import logging
import os
import sys


def main() -> None:
    real_fd = os.dup(1)
    os.dup2(2, 1)  # native/JVM stdout now goes to stderr

    stream = os.fdopen(real_fd, "w", encoding="utf-8", buffering=1)
    try:
        stream.reconfigure(write_through=True)
    except Exception:
        pass
    sys.stdout = stream

    level = os.environ.get("GHIDRA_FLEET_LOG", "INFO").upper()
    logging.basicConfig(
        level=level,
        stream=sys.stderr,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    from ghidra_fleet.server import mcp

    log = logging.getLogger("ghidra_fleet")
    log.info("ghidra-fleet starting (stdio), ghidra=%s", os.environ.get("GHIDRA_INSTALL_DIR"))
    try:
        mcp.run(transport="stdio")
    except KeyboardInterrupt:
        pass
    # stdio closed (client gone): the embedded JVM and analysis worker threads
    # are non-daemon and can hang a clean interpreter shutdown, leaving zombie
    # processes that hold the Ghidra project lock. Hard-exit instead.
    log.info("stdio closed, exiting")
    os._exit(0)


if __name__ == "__main__":
    main()
