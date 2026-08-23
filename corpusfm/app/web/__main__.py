"""Runner: python -m corpusfm.app.web [--host H] [--port P]

Co-located deployment (the supported one) runs behind the FMS web server under a sub-path, so the
app emits prefixed URLs and trusts the proxy's `X-Forwarded-Proto` (HTTPS).

**The route facts come from the PUBLISHED INSTALLATION (packet 1246-10-04).** They used to be
switches the unit had to pass, and the unit passes none: the process started healthy on its
development default `:8501` while the FMS proxy forwarded to `:8533`, so `/corpusfm/` answered 502
beside a perfectly working app (fms-server, 2026-08-08). `install.yaml` is not consulted — the
manifest is the authority, and on a published installation a missing or invalid route fact is FATAL
rather than a fall-back to `8501` and a root mount, because that fallback is precisely what looked
like success while serving nowhere.

`--ssl-certfile`/`--ssl-keyfile` serve HTTPS directly instead (uvicorn terminates TLS).
"""

from __future__ import annotations

import argparse
import sys

import uvicorn

#: The development defaults. They apply ONLY when no installation is published — a checkout, the
#: test suite — never as a fallback from a published record that could not be read.
DEV_PORT = 8501
DEV_ROOT_PATH = ""

#: The proxy is the FMS web server on this same box. Trusting forwarded headers from anywhere else
#: would let a client choose its own scheme and host.
LOOPBACK = "127.0.0.1"


def published_route():
    """`(port, root_path)` from the published record, or `None` when nothing is published."""
    from corpusfm.lifecycle.published import (
        InstallationNotPublished, read_published_installation,
    )

    try:
        published = read_published_installation()
    except InstallationNotPublished:
        return None

    port = published.web_internal_port
    prefix = published.web_prefix
    if not isinstance(port, int) or isinstance(port, bool) or port <= 0:
        raise SystemExit(
            f"this installation publishes web_internal_port={port!r}, which is not a port. "
            "Refusing to serve on a development default while the proxy forwards somewhere else.")
    if not prefix or not str(prefix).startswith("/"):
        raise SystemExit(
            f"this installation publishes web_prefix={prefix!r}, which is not a mount path. "
            "Refusing to serve at the root while the proxy forwards a sub-path.")
    return port, str(prefix)


def main() -> None:
    parser = argparse.ArgumentParser(description="CORPUSfm web UI")
    parser.add_argument("--host", default=LOOPBACK)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--reload", action="store_true", default=False)
    # Reverse-proxy sub-path mount (e.g. "/corpusfm"); "" = served at root.
    parser.add_argument("--root-path", default=None, help="ASGI root_path / mount sub-path")
    # Trust X-Forwarded-* from the FMS proxy (loopback) so request scheme/host are correct.
    parser.add_argument("--proxy-headers", action="store_true", default=False)
    parser.add_argument("--forwarded-allow-ips", default=None, help="e.g. 127.0.0.1")
    # Direct TLS (alternative to fronting via the FMS web server).
    parser.add_argument("--ssl-certfile", default=None, help="PEM cert file (enables HTTPS)")
    parser.add_argument("--ssl-keyfile", default=None, help="PEM private key file")
    args = parser.parse_args()

    route = published_route()
    if route is None:
        port = DEV_PORT if args.port is None else args.port
        root_path = DEV_ROOT_PATH if args.root_path is None else args.root_path
        proxy_headers = args.proxy_headers
        forwarded_allow_ips = args.forwarded_allow_ips
    else:
        published_port, published_prefix = route
        # An explicit option still wins — an administrator running the app by hand for a reason is
        # not the case this closes. What is closed is the SILENT default.
        port = published_port if args.port is None else args.port
        root_path = published_prefix if args.root_path is None else args.root_path
        proxy_headers = True
        forwarded_allow_ips = args.forwarded_allow_ips or LOOPBACK

    uvicorn.run(
        "corpusfm.app.web.app:app",
        host=args.host,
        port=port,
        reload=args.reload,
        root_path=root_path or "",
        proxy_headers=proxy_headers,
        forwarded_allow_ips=forwarded_allow_ips,
        ssl_certfile=args.ssl_certfile,
        ssl_keyfile=args.ssl_keyfile,
    )


if __name__ == "__main__":
    main()
