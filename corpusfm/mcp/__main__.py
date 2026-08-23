"""Entry point: python -m corpusfm.mcp

Starts the corpusfm MCP server over HTTP/SSE.
Bind host/port resolve in this order: CLI args → MCP_HOST/MCP_PORT env → 127.0.0.1:8765.
The env path lets the co-located install drive host/port from .mcp_env (web-writable, so the
Settings → General tab can change the port), while the unit's ExecStart carries no hardcoded args.
"""

import argparse
import os
import sys

from corpusfm.mcp.server import mcp


def _env_default(name: str, fallback: str) -> str:
    v = os.environ.get(name, "").strip()
    return v or fallback


def main() -> int:
    parser = argparse.ArgumentParser(
        description="corpusfm MCP server — exposes diff tools over HTTP/SSE"
    )
    parser.add_argument("--host", default=None, help="Bind host (default: MCP_HOST env or 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default: MCP_PORT env or 8765)")
    args = parser.parse_args()

    host = args.host if args.host is not None else _env_default("MCP_HOST", "127.0.0.1")
    try:
        port = args.port if args.port is not None else int(_env_default("MCP_PORT", "8765"))
    except ValueError:
        port = 8765

    print(f"Starting corpusfm MCP server on {host}:{port}", flush=True)
    mcp.run(transport="sse", host=host, port=port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
