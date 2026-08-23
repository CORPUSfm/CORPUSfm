"""Current FileMaker Server transport facts.

Transport answers only *where* a FileMaker Server is and whether its TLS certificate is verified.
It deliberately carries no database, account, password, token, or private key.  The co-located
answer comes from the published installation; a remote answer comes from the selected SERVER record.
There is no ServerConfig, environment, or hard-coded runtime fallback.
"""

from __future__ import annotations

from dataclasses import dataclass


class TransportUnavailable(RuntimeError):
    """The requested current transport cannot be resolved authoritatively."""


@dataclass(frozen=True)
class FileMakerTransport:
    host: str
    verify_ssl: bool


def colocated() -> FileMakerTransport:
    """Return the published co-located transport or raise with the installation reason."""
    from corpusfm.lifecycle import runtime_storage

    try:
        resolved = runtime_storage.resolve()
    except Exception as exc:
        raise TransportUnavailable(str(exc)) from exc
    if resolved is None:
        raise TransportUnavailable("no CORPUSfm installation is published")
    if not resolved.host:
        raise TransportUnavailable("the published co-located FileMaker host is empty")
    return FileMakerTransport(host=resolved.host, verify_ssl=bool(resolved.verify_ssl))


def for_server_ref(server_ref: str | None) -> FileMakerTransport:
    """Resolve ``local``/blank through the installation and a UUID through SERVER."""
    ref = (server_ref or "local").strip()
    if not ref or ref == "local":
        return colocated()

    from corpusfm.server.remote_servers import get_server_by_id

    server = get_server_by_id(ref)
    if server is None:
        raise TransportUnavailable(f"remote FileMaker server {ref!r} is not registered")
    if not server.host:
        raise TransportUnavailable(f"remote FileMaker server {server.name!r} has no host")
    return FileMakerTransport(host=server.host, verify_ssl=bool(server.verify_ssl))


__all__ = ["FileMakerTransport", "TransportUnavailable", "colocated", "for_server_ref"]
