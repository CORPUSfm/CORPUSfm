"""Deployment-shape helpers for the co-located reverse-proxy model.

CORPUSfm's only supported deployment is co-located behind FileMaker Server's web server
(nginx on FMS 2026, Apache on older FMS) at a sub-path, e.g. https://host/corpusfm/. The
installer applies that (proxy block + unit `--root-path` + the `web_prefix` marker in
install.yaml). These helpers read that marker so the app can:
  - lock an un-migrated server install to the "run the installer" warning page, and
  - set the session cookie Secure only once it's actually served over HTTPS via the proxy.

All fail-open: any error → treat as un-migrated/root (never hard-crash a box)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

_log = logging.getLogger(__name__)


def root_path(request) -> str:
    """The ASGI root_path (reverse-proxy mount prefix, e.g. "/corpusfm"); "" at root."""
    try:
        return request.scope.get("root_path", "") or ""
    except Exception:
        return ""


def route_path(request) -> str:
    """request.url.path with the root_path stripped — the in-app route (e.g. "/artifacts").

    Under root_path, request.url.path includes the prefix ("/corpusfm/artifacts"), so any
    path comparison (nav active state, the /api auth check) must use this instead."""
    rp = root_path(request)
    p = request.url.path
    return p[len(rp):] or "/" if rp and p.startswith(rp) else p


def prefixed(request, path: str) -> str:
    """Prepend root_path to an absolute in-app path for a redirect Location, so e.g.
    a redirect to /login lands at /corpusfm/login (not / on the FMS host)."""
    rp = root_path(request)
    return (rp + path) if (rp and path.startswith("/")) else path


def _published_route():
    """`(prefix, port)` from the published installation, or `None` when nothing is published.

    ONE read chain (packet 1246-10-04). `corpusfm.app.web.__main__` derives the server's own bind
    and mount from the same projection; duplicating the chain here would be a second authority that
    can disagree with the process it describes.
    """
    from corpusfm.lifecycle.published import (
        InstallationNotPublished, read_published_installation,
    )

    try:
        published = read_published_installation()
    except InstallationNotPublished:
        return None
    return published.web_prefix, published.web_internal_port


def web_prefix() -> str:
    """The reverse-proxy sub-path (e.g. "/corpusfm"), or "" when this install serves at the root.

    The published manifest is the authority; `install.yaml` is the retired store and is consulted
    only by a tree that publishes no installation.
    """
    route = _published_route()
    if route is not None:
        return (route[0] or "").rstrip("/")
    try:
        from corpusfm.install import read_install_config
        return (read_install_config().get("web_prefix") or "").rstrip("/")
    except Exception:
        return ""


def is_migrated() -> bool:
    """True when this install has been moved behind the FMS web server (marker present)."""
    return bool(web_prefix())


def local_base_url() -> str:
    """Loopback base URL of the co-located CORPUSfm app (e.g. ``http://127.0.0.1:8533``).

    ``fms_push`` is ALWAYS local — CORPUSfm is co-located on the FMS box and the FM push
    script POSTs ``<this>/api/upload`` — so the target is derived from the deployment, never
    configured (no public exposure, no /corpusfm-suffix footgun). Direct to the local uvicorn
    on the plain route path (the app routes the un-prefixed path; nginx only strips the prefix),
    so this works without TLS/cert and even if the FMS web server is down. The port comes from the
    PUBLISHED record — the same projection the server binds from — so this URL cannot name a port
    the app is not listening on. `install.yaml` remains the source only for an unpublished tree."""
    route = _published_route()
    if route is not None and isinstance(route[1], int) and route[1] > 0:
        return f"http://127.0.0.1:{route[1]}"
    try:
        from corpusfm.install import read_install_config
        port = int(read_install_config().get("web_port", 8533) or 8533)
    except Exception:
        port = 8533
    return f"http://127.0.0.1:{port}"


# ── MCP address — the one deployment-wide public identity (packet 1180) ──────────────
# The stable HTTPS base another machine uses to reach THIS installation, INCLUDING its deployed
# web-prefix — e.g. ``https://fms.example.test/corpusfm`` or ``https://192.168.1.50/corpusfm``. It is
# the single canonical value for: remote FileMaker push-job callbacks, MCP protected-resource /
# authorization-server identity, externally-usable MCP-generated links, and any future feature that
# must tell another machine how to reach this box. OAuth and job defaults MUST NOT independently
# advertise different bases — they consume this one resolver and one persisted value. Distinct from
# ``local_base_url()`` (loopback), which stays the co-located LOCAL push path and is NEVER returned as
# the external identity.

@dataclass(frozen=True)
class ExternalBase:
    """Resolved external CORPUSfm address + enough provenance for Settings and every consumer.

    ``value`` — the effective external base (``https://host<prefix>``), or ``""`` when none is usable.
    ``source`` — ``persisted`` | ``none``.
    ``error`` — actionable message when the authoritative source is invalid, or none is usable; else ``""``.
    ``warning`` — a migration/conflict/retired-env note (non-fatal); ``""`` if none.
    ``env_managed`` — retained as a FIELD, always False. The environment override it reported was
    removed with the global (packet 1219 Half C): with the address scoped to MCP and asserted by the box
    itself, an out-of-band variable had nothing left to override and made the UI lie about whether a save
    could take effect. Kept in the shape so every consumer and stored payload reads unchanged rather than
    being touched for a value that is now constant.
    """
    value: str
    source: str
    error: str
    warning: str
    env_managed: bool = False


def _validate_external_base(raw: str) -> Optional[str]:
    """The single validator for the external CORPUSfm address. Returns the normalized base (one trailing
    slash trimmed) iff ``raw`` is an absolute **https** URL with a real **non-loopback, non-unspecified**
    host, **no** userinfo/query/fragment/path-params, and a path **exactly equal** to the deployed
    ``web_prefix()``; else ``None``. Uses ``ipaddress`` semantics for literal loopback/unspecified — a
    private/LAN host or IP (e.g. ``10.0.0.5``, ``192.168.1.50``) is ALLOWED ("external" = reachable from
    another host, not necessarily internet-public). Certificate posture is NOT checked here (a
    self-signed/expired cert is a client-trust concern, not URL shape)."""
    from urllib.parse import urlparse
    import ipaddress
    val = (raw or "").strip()
    if not val:
        return None
    try:
        p = urlparse(val)
    except Exception:
        return None
    if p.scheme != "https":
        return None
    if p.username or p.password or p.query or p.fragment or p.params:
        return None
    try:
        _ = p.port      # accessing .port validates it — a malformed/out-of-range port raises ValueError
    except ValueError:
        return None
    h = (p.hostname or "").lower().rstrip(".")     # trailing-dot FQDN/IP forms collapse
    if not h or h == "localhost":
        return None
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_loopback or ip.is_unspecified):
        return None
    prefix = web_prefix()                          # "/corpusfm" (or custom); "" when not migrated
    if not prefix:
        return None
    # Accept EXACTLY the web prefix or the web prefix + one trailing slash — nothing is pre-stripped, so
    # ``<prefix>//`` (or any deeper path) is REJECTED, not silently collapsed (packet 1180 correction).
    if p.path != prefix and p.path != prefix + "/":
        return None
    return val[:-1] if val.endswith("/") else val   # normalize away the single accepted trailing slash


def _bracket_ipv6(host: str) -> str:
    """Wrap a bare IPv6 literal in ``[...]`` for use in a URL authority (``fd00::1`` → ``[fd00::1]``);
    a hostname or IPv4 literal (or an already-bracketed value) is returned unchanged. A URL authority
    REQUIRES brackets around an IPv6 literal, else the colons are misread as a port separator."""
    import ipaddress
    h = (host or "").strip()
    if not h or h.startswith("["):
        return h
    try:
        if isinstance(ipaddress.ip_address(h), ipaddress.IPv6Address):
            return f"[{h}]"
    except ValueError:
        pass
    return h


def external_base() -> ExternalBase:
    """Resolve the MCP address — the one value this box asserts as its own (packet 1180, scoped by 1219).

    ONE authority now: install.yaml ``public_base_url``. Two sources were removed in packet 1219 Half C,
    each for a measured reason rather than tidiness:

    * ``CORPUSFM_PUBLIC_BASE_URL`` — an out-of-band override for a value the box now asserts itself at
      startup and an admin corrects on the MCP tab. Its only remaining effect was to make Settings show a
      read-only field whose save could not take effect.
    * derivation from ``fm_host`` — it returned None for a loopback value, and on the only shipped
      deployment (co-located) ``fm_host`` IS loopback, so it could essentially never fire. Both gate
      boxes proved it: fms-dev needed a hand-set address, and the Windows box resolved to ``source:
      none``. A fallback that is dead on arrival is worse than none, because it is reasoned about.

    So: a valid persisted value, or ``none`` with an actionable error. Startup enumeration
    (:func:`assert_external_base_at_startup`) is what fills the gap for a box that has said nothing.

    A one-time atomic migration of the legacy persisted key still runs here (idempotent, via
    ``install.migrate_public_base_url_config``), and the retired push-callback environment variable is
    never consumed — if present it only surfaces a rename warning.
    """
    warning = ""
    try:
        from corpusfm.install import retired_push_env_warning
        warning = retired_push_env_warning()
    except Exception:
        warning = ""
    # The migration is honest about its own failures (read/parse/verify/restore → an ``error`` status +
    # warning); an UNEXPECTED exception here must NOT be swallowed and reported as "nothing to migrate"
    # (packet 1180 correction) — surface it as a warning so a broken install.yaml is visible in Settings.
    try:
        from corpusfm.install import migrate_public_base_url_config
        _status, mig_warn = migrate_public_base_url_config()
    except Exception:
        mig_warn = ("The MCP address migration check failed unexpectedly; verify "
                    "install.yaml is readable and well-formed.")
    if mig_warn:
        warning = (warning + " " + mig_warn).strip() if warning else mig_warn

    try:
        from corpusfm.install import read_install_config
        persisted = str(read_install_config().get("public_base_url", "") or "").strip()
    except Exception:
        persisted = ""
    if persisted:
        v = _validate_external_base(persisted)
        if v:
            return ExternalBase(v, "persisted", "", warning, False)
        return ExternalBase("", "persisted",
                            "The stored MCP address is not valid for this deployment (needs "
                            f"https://<host>{web_prefix() or '/corpusfm'}). Set a valid address in "
                            "Settings -> MCP.", warning, False)

    return ExternalBase("", "none",
                        "This box has no MCP address. Set it in Settings -> MCP (the HTTPS base another "
                        f"machine uses to reach this box, including the {web_prefix() or '/corpusfm'} "
                        "prefix).", warning, False)


# ── The box's own certificate (packet 1325 R4) ───────────────────────────────────────────────────
# Measured 2026-08-23 on fms-dev: the box had a valid certificate for its DNS name and asserted its
# IP anyway, and Claude Code refused the IP at transport (ERR_TLS_CERT_ALTNAME_INVALID) — the one
# locator a verifying client cannot use. Canon consequence 4 (take advantage of ideals when
# available; require none): read what the co-located proxy serves on 443 and PREFER a name it covers
# that resolves to this box; on any failure behave exactly as before. Trust stays the client's; this
# only chooses and describes the address.

_CERT_CACHE: dict = {"at": 0.0, "names": []}
_CERT_TTL_SECONDS = 60.0


def _served_certificate_pem(port: int = 443, timeout: float = 2.0) -> str:
    import ssl
    return ssl.get_server_certificate(("127.0.0.1", port), timeout=timeout)


def certificate_names() -> list:
    """DNS names and IP literals the box's own TLS certificate covers (SAN; Common Name as the
    fallback). ``[]`` when no certificate is readable — a dev box, a proxy not yet up — and every
    caller treats that as "unknown", never as "not covered"."""
    import time
    now = time.monotonic()
    if now - _CERT_CACHE["at"] < _CERT_TTL_SECONDS:
        return list(_CERT_CACHE["names"])
    names: list = []
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(_served_certificate_pem().encode())
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names += [str(n) for n in san.get_values_for_type(x509.DNSName)]
            names += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            pass
        if not names:
            names = [str(a.value) for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
    except Exception:
        _log.debug("served certificate not readable", exc_info=True)
        names = []
    _CERT_CACHE.update(at=now, names=list(names))
    return names


def certificate_covers(host: str, names) -> bool:
    """Exact (case-insensitive) or one-label wildcard match for a DNS name; equality for an IP."""
    h = (host or "").strip("[]").lower()
    if not h:
        return False
    for n in names or ():
        n = str(n).lower()
        if n == h:
            return True
        if n.startswith("*.") and "." in h and h.split(".", 1)[1] == n[2:]:
            return True
    return False


def certificate_coverage(base: str) -> dict:
    """``{"checked", "covered", "host", "names"}`` for the host of an external base — what the MCP
    surfaces state when a client is going to refuse the served address. ``checked`` False means the
    certificate could not be read and nothing should be said."""
    from urllib.parse import urlparse
    host = ""
    try:
        host = urlparse(base or "").hostname or ""
    except Exception:
        host = ""
    names = certificate_names() if host else []
    return {"checked": bool(names), "covered": certificate_covers(host, names) if names else False,
            "host": host, "names": names}


def _resolve_host(name: str) -> set:
    import socket
    try:
        return {ai[4][0].split("%")[0] for ai in socket.getaddrinfo(name, None)}
    except Exception:
        return set()


def preferred_named_base(candidates: list) -> Optional[str]:
    """Among the DNS names the box's certificate covers, the first that resolves to one of the
    box's own detected addresses, composed as an external base — or None. Wildcards and IP SANs are
    not names a client can be pointed at, so they are skipped."""
    from urllib.parse import urlparse
    local = set()
    for c in candidates or ():
        try:
            local.add((urlparse(c).hostname or "").lower())
        except Exception:
            continue
    for name in certificate_names():
        n = str(name).strip().lower()
        if not n or n.startswith("*") or n.replace(".", "").replace(":", "").isalnum() and n.replace(".", "").isdigit():
            continue
        if ":" in n:          # an IPv6 literal, never a DNS name
            continue
        if _resolve_host(n) & local:
            base = _compose_base(n)
            if base:
                return base
    return None


def enumerate_local_bases() -> list:
    """Every address THIS box answers on, composed into candidate external bases and validated.

    Deterministic, not clever: interfaces sorted by name, addresses in the order the OS reports them
    per interface, loopback / link-local / unspecified excluded by ``ipaddress`` semantics rather than
    by name-matching. No ranking, no probing, no attempt to guess which one a client can reach —
    ranking would be a guess dressed as knowledge, and the principle already says a detected address
    is a CANDIDATE.
    """
    import ipaddress
    out: list = []
    try:
        import psutil
        import socket as _s
        fams = {_s.AF_INET: 4, getattr(_s, "AF_INET6", None): 6}
        for iface in sorted(psutil.net_if_addrs()):
            for a in psutil.net_if_addrs()[iface]:
                ver = fams.get(a.family)
                if ver is None:
                    continue
                raw = (a.address or "").split("%")[0]     # strip an IPv6 zone id
                try:
                    ip = ipaddress.ip_address(raw)
                except ValueError:
                    continue
                if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
                    continue
                base = _compose_base(_bracket_ipv6(raw))
                if base and base not in out:
                    out.append(base)
    except Exception:
        _log.debug("interface enumeration failed", exc_info=True)
    return out


def _compose_base(authority: str) -> Optional[str]:
    """``https://<authority><web_prefix>`` through the one validator, or None.

    **The prefix comes from ``web_prefix()`` — the same function the validator below asks** (packet
    1250). It used to read ``install.yaml["web_prefix"]`` directly, which is the RETIRED store: a
    published installation records its prefix in the manifest's web block, and the marker written at
    install time is minimal. So on every published Linux box this composed ``https://<addr>`` with no
    path, ``_validate_external_base`` rejected it for not matching ``web_prefix()`` — the two
    functions in this module disagreeing about where the same fact lives — enumeration returned
    nothing, and the box reported ``source: none`` while answering perfectly well on
    ``https://<addr>/corpusfm``. Measured on `fms-dev` 2026-08-12.

    Calling the function rather than re-reading the projection is the point: one place in this module
    knows where the prefix comes from, so the composer cannot drift from the validator again.
    """
    prefix = web_prefix().strip("/")
    return _validate_external_base(f"https://{authority}/{prefix}" if prefix else f"https://{authority}")


def assert_external_base_at_startup() -> str:
    """Give an anonymous box an address BEFORE it answers anything. Returns what was written, else "".

    This replaces the request-driven auto-assert (packet 1219 ruling). The reason is mechanical, not
    aesthetic: the MCP auth stack is built at module import, so an address learned from the first
    request arrives AFTER the provider exists and cannot be used until a restart nobody knows to
    perform. Deciding at startup closes that by construction.

    The evidence is weaker than a real request's — this is *locally detected*, the first of the three
    grades the Unknowable-Install Principle names, and it CANNOT know a client can reach the address.
    That is accepted deliberately: available at the moment it is needed beats better-but-too-late. A
    wrong guess is the administrator's to correct on the MCP tab, and it must never be presented as
    verified.

    An env override or an operator-set value always wins — enumeration only speaks for a box that has
    said nothing at all.
    """
    try:
        current = external_base()
        if current.source != "none":
            # SAY IT ANYWAY. This used to return silently, so a box with a configured address wrote
            # nothing about it at startup and the only place stating the served address was a UI the
            # administrator had to already reach. Ordinary logs are one of the out-of-band channels the
            # Unknowable-Install Principle's consequence 5 requires, and the guessing path below has
            # always used them — this makes the two paths agree instead of leaving the *configured*
            # box, the ordinary case, the quiet one. (Packet 1194 closure, 2026-07-29.)
            _log.info("MCP address: %s (source: %s) - set by an operator or the environment, not "
                      "detected. Change it on Settings -> MCP.", current.value, current.source)
            return ""                       # already decided: env, operator, or derivation
        candidates = enumerate_local_bases()
        if not candidates:
            _log.info("No non-loopback address detected; CORPUSfm has no external address yet. "
                      "Set one on Settings -> MCP. Bearer-token MCP still works.")
            return ""
        named = preferred_named_base(candidates)
        chosen = named or candidates[0]
        from corpusfm.install import set_public_base_url
        set_public_base_url(chosen)
        others = [c for c in candidates if c != chosen]
        extra = f" (also detected: {', '.join(others)})" if others else ""
        _log.info("MCP address asserted at startup from %s: %s%s "
                  "- locally DETECTED, not verified from a client; correct it on Settings -> MCP if "
                  "clients cannot reach it.",
                  "a name this box's certificate covers" if named else "a local interface", chosen, extra)
        return chosen
    except Exception:
        _log.debug("startup external address assertion failed", exc_info=True)
        return ""


def external_base_url() -> str:
    """Just the effective MCP address string (``""`` when none is usable). Convenience for
    consumers that only need the value; use :func:`external_base` when source/error/warning matter."""
    return external_base().value


def public_callback_url_from_request(request) -> "Optional[str]":
    """The server callback base derived from the current browser request — scheme + host + the ASGI
    root_path from the trusted proxy headers (``--proxy-headers``/``X-Forwarded-Proto``) — e.g.
    ``https://<host>/corpusfm``, validated through the SAME external-base validator as a saved value
    (:func:`_validate_external_base`): https, a non-loopback/non-unspecified host (full ``127.0.0.0/8``
    + ``::1`` + unspecified rules, no userinfo/query/fragment/params), and a path exactly equal to the
    deployed ``web_prefix``. Returns the normalized candidate, or None when the request is not a usable
    external address. Only meaningful in a REQUEST context (the headless runner has none — it relies on
    the persisted MCP address).

    It SUGGESTS a default in the UI. It no longer feeds an auto-assert: packet 1219 moved assertion to
    startup (:func:`assert_external_base_at_startup`), because an address learned from a request arrives
    after the MCP auth stack is already built and cannot be used until a restart."""
    try:
        rp = root_path(request).rstrip("/")
        return _validate_external_base(f"{request.url.scheme}://{request.url.netloc}{rp}")
    except Exception:
        return None


def validate_callback_url(raw: str, *, require_public: bool = False) -> str:
    """Validate a remote-push callback URL and return it normalized (empty → "").

    The callback is where a REMOTE FMS box POSTs a file's full DDR **plus a live one-time bearer
    token** (packet 1015). That destination must be TLS unless it is loopback — a token and the schema
    must never cross the network in cleartext. Empty means "derive the default" (the External CORPUSfm
    address). Raises ``ValueError`` on a non-TLS off-box target.

    This is the PER-JOB override validator (looser than the deployment-wide MCP address:
    it does not require the path to equal ``web_prefix`` — a job may route to an unusual explicit URL).
    ``require_public=True`` (a REMOTE push, packet 1055): a loopback host is REJECTED — the remote box
    can't reach our loopback, so a loopback callback is a silent-failure trap. ("public" here means
    *reachable from another host*, i.e. not loopback — an internal/LAN address qualifies; it need not
    be internet-public, and https with a self-signed/expired cert is fine — we only check the scheme,
    never the certificate.) Default False keeps the LOCAL co-located push (loopback target) valid.

    Packet 1022: enforced at BOTH trust boundaries — the Jobs UI save route AND the runner's default
    resolution — because a stored/manual/FM-DB job record or an environment override otherwise bypasses
    the UI-only guard."""
    from urllib.parse import urlparse
    val = (raw or "").strip()
    if not val:
        return ""
    p = urlparse(val)
    host = (p.hostname or "").lower()
    is_loopback = host in {"localhost", "127.0.0.1", "::1"}
    if require_public and is_loopback:
        raise ValueError(
            "A remote push needs an https:// callback URL the remote FileMaker server can reach "
            "(an internal/LAN address is fine) — a loopback address (localhost / 127.0.0.1) can't be "
            "reached from another host. Set the server's Callback URL, or the MCP address in "
            "Settings."
        )
    # A real host is required. A scheme with no netloc (e.g. "https:example.com/cb",
    # "https:///corpusfm", "https://") parses as scheme=https / hostname=None and would otherwise
    # slip through the https branch — reject it BEFORE CORPUSfm fires the FM push, or the schema +
    # live one-time token could go to an unintended/undefined target.
    if host and (p.scheme == "https" or (p.scheme == "http" and is_loopback and not require_public)):
        return val
    raise ValueError(
        "Callback URL must be an absolute https:// URL with a host (http:// is allowed only for "
        "localhost) — a remote push posts the file's schema and a live one-time token to it."
    )


def needs_proxy_migration() -> bool:
    """True for a server-mode install that has NOT been put behind the reverse proxy yet —
    e.g. someone git-pulled the new code but didn't re-run `install.sh`. Such a box
    is gated to the warning page (we support only the co-located proxy deployment)."""
    try:
        from corpusfm.runtime import build_context
        return build_context().is_server and not is_migrated()   # via the runtime layer (S9)
    except Exception:
        return False
