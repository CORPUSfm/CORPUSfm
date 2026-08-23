"""The canonical marked block, and the ONE fingerprint contract (packet 1246-06 §4, ruling 4).

**Why this module exists.** Rendering used to live only inside the OS-native executors, which had
two consequences that a confirmation review measured rather than guessed:

1. **Planning could not see the DESIRED state.** `decide()` had the observed block and the stored
   fingerprint and nothing to compare them *to*, so "routing already matches the intended rendering"
   was a claim nothing had checked. Change `web.prefix` and `reconcile` would do nothing.
2. **The digests were incomparable.** The shell hashed the block with a trailing newline; Python
   hashed it without; PowerShell hashed the whole file. Measured on one real apache block, the first
   two differed (`e956d35e…` vs `777ec8df…`). Drift is *defined* as those two digests disagreeing,
   so every already-configured box would have been accused of operator tampering — and refused types
   record no candidate, so nothing would ever repair the stored value.

So the block is rendered HERE, once, and the executors are handed the exact text to write. The
canonical form is fixed and the same in all three languages:

    * newline normalized to LF
    * NO terminal newline
    * NO BOM

`fingerprint()` is SHA-256 of that. `tests/test_proxy_render.py` holds a cross-language
known-answer test that runs the shell and the PowerShell implementations against the same input and
requires all three digests to agree — because two implementations agreeing by inspection is exactly
what was believed before, and it was false.

**Writing is still the executors'.** They own each type's whole filesystem transaction; what moved
is the decision about WHAT the text should be, which planning cannot do without.
"""

from __future__ import annotations

import hashlib
import ntpath
from typing import Mapping

MARKER = "CORPUSFM"

# Fixed, FMS-owned names. Established by the project and not re-invented here.
INCLUDE_NAME = "corpusfm_https.conf"

# Fixed IIS names, already established by the project (install.ps1:1247).
IIS_POOL = "CORPUSfmProxy"


def metadata_routes(prefix: str) -> tuple[str, ...]:
    """The EXACT host-root metadata vpaths, prefix-derived (packets 1175/1179, proven).

    **These are not invented here and their shape is load-bearing.** RFC 9728 inserts
    `/.well-known/oauth-protected-resource` BEFORE the resource path, and RFC 8414 does the same for
    the authorization-server document — so they live at the HOST ROOT, outside `<prefix>`, and an
    application mounted at the prefix never sees them. That is why Windows needs a separate child
    application per exact path rather than one app at the prefix.

    Only these exact forms are claimed. Never a descendant (`…/mcp/x`), never a broad well-known,
    and never the bare host-root `/.well-known/openid-configuration` — a shared box's neighbours
    keep their own paths. `cfm-web-proxy.ps1:66-99` records the reasoning that established the set;
    it is reproduced rather than imported because 1246-09 deletes that file.
    """
    pfx = _normal_prefix(prefix)
    return (
        f"/.well-known/oauth-protected-resource{pfx}/mcp",
        f"/.well-known/oauth-authorization-server{pfx}/mcp",
        f"/.well-known/openid-configuration{pfx}/mcp",
    )


def forwarded_routes(prefix: str) -> tuple[str, ...]:
    """The vpaths a PROXY FRONT must forward: `metadata_routes` plus the protected-resource
    document's trailing-slash form.

    **The two sets are not the same and the difference is load-bearing** (packet 1272). FastMCP
    registers the protected-resource document at the resource path *with* a trailing slash, and the
    `resource` identifier it publishes carries that slash — so the one URL a compliant client
    derives and fetches is `…/mcp/`. The authorization-server documents have no slash form on either
    side, which is why only this one path is doubled.

    Measured 2026-08-18 on `fms-dev`, `winfms2026` and a third install: the slash form returned 404
    through the proxy while the no-slash form returned 200, and browser OAuth could not complete on
    any of them. The application already serves both (`mcp.server._with_no_slash_aliases`); only the
    front had stopped forwarding one.

    The retired `cfm-web-proxy.ps1` claimed both variants for exactly this reason. Packet 1246-09
    deleted that file and this module reproduced its path set from memory, dropping the slash form
    along with the comment that explained it — which is why `metadata_routes` is kept as the
    IIS **vpath** set and this is a separate answer rather than an edit to it.

    Still EXACT: two forms of one path, never a descendant (`…/mcp/x`), never a broad well-known.
    """
    pfx = _normal_prefix(prefix)
    out: list[str] = []
    for route in metadata_routes(prefix):
        out.append(route)
        if route.startswith("/.well-known/oauth-protected-resource"):
            out.append(route + "/")
    assert out[0] == f"/.well-known/oauth-protected-resource{pfx}/mcp"
    return tuple(out)


# MCP is not optional (ruling 10): it always installs, so a request cannot turn these off and no
# rendering may omit them. They are what a browser OAuth client fetches BEFORE it holds any CORPUSfm
# credential, which is why dropping them is a silent authorization regression rather than a missing
# convenience.


def canonical(text: str) -> str:
    """LF newlines, no terminal newline, no BOM. The one normalization, applied everywhere."""
    if text.startswith("﻿"):
        text = text[1:]
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")


def fingerprint(text: str | None) -> str | None:
    """SHA-256 of one canonical part. `None` in, `None` out — an absent block has no digest.

    **This is a PART digest, not an artifact digest.** Drift and currency are decided on the whole
    owned family (`family_digest`); hashing one part was measured to miss real changes — see below.
    """
    if text is None:
        return None
    return hashlib.sha256(canonical(text).encode("utf-8")).hexdigest()


def family_document(parts: Mapping[str, str]) -> str:
    """The deterministic, LENGTH-SAFE serialization every language hashes.

    Format, per part, in sorted name order:

        <name>\n<byte-length of the canonical body>\n<canonical body>

    joined by LF. **The length prefix is the point.** Without it, `{"a": "x", "b": "y"}` and
    `{"a": "x\nb\ny"}` serialize identically, so an operator could move content between an nginx
    include and its marked block and the digest would not notice. Sorted order makes the result
    independent of how a caller happened to build the mapping.
    """
    chunks = []
    for name in sorted(parts):
        body = canonical(parts[name])
        chunks.append(f"{name}\n{len(body.encode('utf-8'))}\n{body}")
    return "\n".join(chunks)


def family_digest(parts: Mapping[str, str] | None) -> str | None:
    """SHA-256 of `family_document`. THE fingerprint — observed, stored and desired all use it.

    **Why one part was not enough, measured.** The nginx marked block is a single `include`
    directive naming a path; the prefix, the port and every MCP metadata route live in the include
    BODY. Hashing the block alone left the desired fingerprint unchanged when any of them changed,
    so `reconcile` could not see a route it was supposed to converge on. IIS was worse: hashing the
    primary `web.config` ignored the pool, the applications, their physical paths and pool
    assignments, and every metadata child — an operator could repoint an application and nothing
    would register it.
    """
    if parts is None:
        return None
    return hashlib.sha256(family_document(parts).encode("utf-8")).hexdigest()


def marker_line() -> str:
    return f"# {MARKER}"


def render_block(proxy_type: str, *, prefix: str, port: int, include_path: str | None = None) -> str:
    """The marked block that belongs in the FMS-owned configuration, canonical form.

    For the two nginx fronts the block is a single `include` directive, because the routing itself
    uses `location`, which is only legal inside a `server` block — see `render_include`.
    """
    prefix = _normal_prefix(prefix)
    lines = [marker_line()]
    if proxy_type in ("fms-nginx", "claris-nginx"):
        if not include_path:
            raise ValueError("an nginx rendering needs the path of its include file")
        lines.append(f'    include "{include_path}";')
    elif proxy_type == "apache":
        # Stripped once, for the same reason as nginx above: the app serves unprefixed routes.
        lines.append(f"    ProxyPass {prefix}/ http://127.0.0.1:{port}/")
        lines.append(f"    ProxyPassReverse {prefix}/ http://127.0.0.1:{port}/")
        for route in forwarded_routes(prefix):
            lines.append(f"    ProxyPass {route} http://127.0.0.1:{port}{route}")
            lines.append(f"    ProxyPassReverse {route} http://127.0.0.1:{port}{route}")
    else:
        raise ValueError(f"{proxy_type!r} has no marked-block rendering")
    lines.append(marker_line())
    return "\n".join(lines)


_HSTS_LINE = 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'


def render_include(*, prefix: str, port: int) -> str:
    """The CORPUSfm-owned nginx include: the application route plus the mandatory MCP routes."""
    prefix = _normal_prefix(prefix)
    # THE PREFIX IS STRIPPED EXACTLY ONCE, HERE (packet 1246-10-04). The app serves UNPREFIXED
    # routes and uses the published prefix only to GENERATE urls (`root_path`), so a `proxy_pass`
    # carrying the prefix forward asked it for `/corpusfm/login`, which it does not have: measured
    # on fms-server 2026-08-08 as a 404 through FMS while `http://127.0.0.1:8533/login` answered
    # 200. The trailing slash on a bare-authority `proxy_pass` is what strips the matched location,
    # so `/corpusfm/login` arrives as `/login` — once, and never as `/corpusfm/corpusfm/login`.
    lines = [
        f"location {prefix}/ {{",
        f"    proxy_pass http://127.0.0.1:{port}/;",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Forwarded-Proto $scheme;",
        f"    proxy_set_header X-Forwarded-Prefix {prefix};",
        f"    {_HSTS_LINE}",
        "}",
    ]
    # `location = <path>` is the EXACT match: these claim their own vpath and nothing beneath
    # it, which is the same boundary the IIS child applications enforce on Windows.
    #
    # RESPONSE HEADERS ARE OURS IN THESE LOCATIONS (packet 1327). FileMaker Server's own nginx adds
    # `Access-Control-Allow-Origin $hostname` + `Allow-Credentials True` at SERVER level, and nginx
    # inherits server-level add_header into every location that declares none — so every CORPUSfm
    # response carried two Access-Control-Allow-Origin values (the app's `*` and nginx's hostname),
    # which browsers reject; VS Code's Copilot Agent Host could not even fetch discovery (measured
    # 2026-08-23 on fms-dev and devservice). Declaring ONE add_header in a block cancels that
    # inheritance for the block, making the app the single CORS authority. The one declared is HSTS,
    # re-stated with FMS's own value: cancelling inheritance would otherwise drop it, and it belongs
    # at the TLS terminator; the app already sends its other security headers itself.
    for route in forwarded_routes(prefix):
        lines.append(f"location = {route} {{")
        lines.append(f"    proxy_pass http://127.0.0.1:{port}{route};")
        lines.append("    proxy_set_header Host $host;")
        lines.append(f"    {_HSTS_LINE}")
        lines.append("}")
    return "\n".join(lines)


def render_web_config(*, prefix: str, port: int) -> str:
    """The isolated IIS application's own `web.config`. Never FMS's site-level rewrite rules."""
    prefix = _normal_prefix(prefix)
    rules = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<configuration>",
        "  <system.webServer>",
        "    <rewrite>",
        "      <rules>",
        '        <rule name="corpusfm-proxy" stopProcessing="true">',
        '          <match url="(.*)" />',
        # `{R:1}` IS ALREADY APPLICATION-RELATIVE (packet 1246-10-04). This is the isolated IIS
        # APPLICATION mounted at the prefix, so IIS has removed it before the rule matches;
        # prepending it again asks the app for `/corpusfm/login`, which it does not have — the same
        # doubled path that returned 404 through nginx on fms-server. The external prefix survives
        # where it belongs: the app takes it from the published record for URL generation, and the
        # metadata routes below keep their own exact paths.
        f'          <action type="Rewrite" url="http://127.0.0.1:{port}/{{R:1}}" />',
        "        </rule>",
        "      </rules>",
        "    </rewrite>",
        "  </system.webServer>",
        "</configuration>",
    ]
    return "\n".join(rules)


def render_metadata_web_config(*, route: str, port: int) -> str:
    """One exact-path MCP metadata child application's `web.config`.

    Each metadata document is its own IIS application at an EXACT path, because a browser OAuth
    client fetches `/.well-known/…` at the site root — outside `/corpusfm` — and an application
    mounted at the prefix would never see it.
    """
    rules = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<configuration>",
        "  <system.webServer>",
        "    <rewrite>",
        "      <rules>",
        '        <rule name="corpusfm-mcp-metadata-exact" stopProcessing="true">',
        # `^/?$` — the app ROOT only, in both of the forms a client sends it (packet 1272). The
        # empty relative URL is `…/mcp`; the bare slash is `…/mcp/`, which is the form FastMCP
        # publishes as `resource` and the one a compliant client actually fetches. Matching only
        # `^$` 404'd that request on IIS while nginx and Apache served it, measured on winfms2026.
        # A descendant (`x`, `/x`, `//`) still matches no rule and the application 404s it, which is
        # what keeps this an EXACT claim rather than a subtree one — the reason it is `/?` and not
        # `/.*`.
        '          <match url="^/?$" />',
        f'          <action type="Rewrite" url="http://127.0.0.1:{port}{route}" />',
        "        </rule>",
        "      </rules>",
        "    </rewrite>",
        "  </system.webServer>",
        "</configuration>",
    ]
    return "\n".join(rules)


def desired_family(proxy_type: str, *, prefix: str, port: int, include_path: str | None = None,
                   app_dir: str | None = None, metadata_dir: str | None = None) -> dict[str, str]:
    """Every part of the owned artifact family this installation SHOULD have, by name.

    The part names are the contract the executors read back against, so they are fixed here and
    reproduced in both executors rather than derived independently on each side.
    """
    prefix = _normal_prefix(prefix)
    if proxy_type == "apache":
        return {"block": render_block("apache", prefix=prefix, port=port)}
    if proxy_type in ("fms-nginx", "claris-nginx"):
        return {
            "block": render_block(proxy_type, prefix=prefix, port=port,
                                  include_path=include_path),
            "include": render_include(prefix=prefix, port=port),
        }
    if proxy_type == "iis":
        parts = {
            # The pool is part of the family: its existence and its runtime setting are things an
            # operator can change, and a fingerprint that ignored them would call a repointed
            # installation current.
            "pool": f"{IIS_POOL}\nmanagedRuntimeVersion=",
            f"app:{prefix}": f"path={prefix}\nphysicalPath={app_dir or ''}\npool={IIS_POOL}",
            f"config:{prefix}": render_web_config(prefix=prefix, port=port),
        }
        for route in metadata_routes(prefix):
            slug = metadata_slug(route)
            # `ntpath.join`, NOT a forward slash (packet 1246-10-04). IIS is Windows-only, and the
            # executor builds this same path with `Join-Path`, which produces a BACKSLASH. This side
            # produced `…\proxy-mcp/slug` and the box produced `…\proxy-mcp\slug`, so the desired
            # and observed family documents differed by one character per metadata route and the
            # digests could never agree: every IIS publication verified false and rolled itself
            # back, on a box with nothing pre-existing to blame. Measured on winfms2026,
            # 2026-08-09, generations 4-6. The comparison was right; the intended path was wrong.
            sub = ntpath.join(metadata_dir, slug) if metadata_dir else ""
            parts[f"app:{route}"] = f"path={route}\nphysicalPath={sub}\npool={IIS_POOL}"
            parts[f"config:{route}"] = render_metadata_web_config(route=route, port=port)
        return parts
    raise ValueError(f"{proxy_type!r} has no owned artifact family")


def metadata_slug(route: str) -> str:
    """The physical sub-directory name for one metadata vpath. Both executors derive it the same
    way, so it is defined once here and reproduced there rather than invented twice."""
    return "".join(c if c.isalnum() else "_" for c in route).strip("_")


def desired_fingerprint(proxy_type: str, *, prefix: str, port: int,
                        include_path: str | None = None, app_dir: str | None = None,
                        metadata_dir: str | None = None) -> str:
    """The digest planning compares against. The THIRD fact `decide` needs.

    Observed vs stored answers "did somebody else change it". Observed vs desired answers "is it
    what this installation should have". Conflating them is what made `reconcile` unable to converge
    on a changed prefix: a valid marker pair was treated as current without anyone rendering what
    current ought to be.
    """
    return family_digest(desired_family(proxy_type, prefix=prefix, port=port,
                                        include_path=include_path, app_dir=app_dir,
                                        metadata_dir=metadata_dir))


def _normal_prefix(prefix: str) -> str:
    if not prefix.startswith("/"):
        prefix = "/" + prefix
    return prefix.rstrip("/") or "/"


__all__ = [
    "IIS_POOL", "INCLUDE_NAME", "MARKER", "canonical", "desired_family", "desired_fingerprint",
    "family_digest", "family_document", "fingerprint", "forwarded_routes", "marker_line",
    "metadata_routes",
    "metadata_slug", "render_block", "render_include", "render_metadata_web_config",
    "render_web_config",
]
