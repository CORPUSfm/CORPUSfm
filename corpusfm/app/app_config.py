"""UI-level application configuration.

Stored as app_config.yaml at the project root.
Zero-config defaults work out of the box.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# FM addon locale codes (same set FileMaker addons ship with).
FM_ADDON_LOCALES = {"en", "de", "es", "fr", "it", "ja", "ko", "nl", "pt", "sv", "zh"}

# Secret keys that must NEVER live in the SETTING blob / jor / slots (packet 085 §8, generalized by
# 1007's table-wide fence). The AI provider key lives in the Corpus-Key-encrypted SETTING.AiKeys container;
# a legacy hand-copied config could still carry the old jor key, so the startup fence strips these from
# SETTING (fresh-install-only makes this a fence, not a migration). See projections.SECRET_JOR_KEYS.
SETTING_SECRET_KEYS = ("ai_summary_api_key",)


class ConfigWriteNotCommitted(RuntimeError):
    """PROOF that a settings write did not land: it failed before anything reachable by the server was
    sent (packet 1190-02). Retrying it unchanged is safe."""


class ConfigWriteIndeterminate(RuntimeError):
    """The settings write was DISPATCHED and its outcome cannot be established — the reread failed, or
    it shows values that differ from what was written, which a concurrent merge into the shared
    JSONOfRecord can also cause. Do not assume either way; in particular do not undo anything on the
    strength of it (packet 1190-02)."""


def _browser_connection_lifetime(raw) -> str:
    """Validate the stored browser-connection lifetime policy at the settings boundary. An absent or
    unrecognized value resolves to the documented default; the policy vocabulary itself lives in
    :mod:`corpusfm.app.web.oauth_policy` (imported lazily — app_config sits below the web layer)."""
    try:
        from corpusfm.app.web.oauth_policy import normalize_policy_id
        return normalize_policy_id(raw)
    except Exception:
        return "standard"


def _project_root() -> Path:
    return Path(__file__).parent.parent.parent


def default_app_config_path() -> Path:
    return _project_root() / "app_config.yaml"


def system_locale_code() -> str:
    """Return the two-letter system locale code, clamped to FM_ADDON_LOCALES."""
    try:
        import locale as _locale
        lang = (_locale.getdefaultlocale()[0] or "en")[:2].lower()
    except Exception:
        lang = "en"
    return lang if lang in FM_ADDON_LOCALES else "en"


@dataclass
class AppConfig:
    # "" means "detect from system locale at import time"
    preferred_addon_locale: str = ""
    # placeholder for future CORPUSfm UI localization; "" means use system locale
    ui_locale: str = ""
    # which page `/` lands on: "artifacts" (default) | "monitoring"
    landing_page: str = "artifacts"
    # default side the Documentation drawer opens from: "right" (default) | "left".
    # A per-device flip (the drawer header toggle) overrides via localStorage.
    docs_drawer_side: str = "right"
    # AI summary (chat) provider: "anthropic" | "openai_compat" | "azure_openai" | "" (disabled)
    ai_summary_provider: str = ""
    # Model string for the chosen provider; "" = provider default. For azure_openai this is the chat
    # DEPLOYMENT name (Azure routes it in the URL).
    ai_summary_model: str = ""
    # Base URL for openai_compat ("" = https://api.openai.com/v1); the Azure resource root
    # (https://<resource>.openai.azure.com) for azure_openai.
    ai_summary_base_url: str = ""
    # Azure api-version for the chat endpoint (azure_openai only); "" = ai._endpoints default.
    ai_summary_api_version: str = ""
    # Embedding (search) provider — packet 1151: decoupled from the chat side. "" = openai_compat
    # (legacy behavior); "openai_compat" | "azure_openai".
    ai_embedding_provider: str = ""
    # Embedding model for vector index; "" = "text-embedding-3-small". For azure_openai this is the
    # embedding DEPLOYMENT name.
    ai_embedding_model: str = ""
    # Embedding endpoint; "" = re-use ai_summary_base_url or OpenAI (legacy openai_compat only); the
    # Azure resource root for azure_openai.
    ai_embedding_base_url: str = ""
    # Azure api-version for the embedding endpoint (azure_openai only); "" = ai._endpoints default.
    ai_embedding_api_version: str = ""
    # (packet 1161) Embedding request batch size — how many objects go in one /embeddings call. 0 = Auto
    # (packet 1159: 16 for a local/loopback CPU embedder, _EMBED_BATCH_SIZE_REMOTE otherwise). An explicit
    # value in [1, 2048] (Azure's array cap) overrides for any endpoint; chunking only, never a vector
    # change → does NOT invalidate ai_embedding_verified and never forces a re-index.
    ai_embedding_batch_size: int = 0
    # Set True only after a successful live /embeddings round-trip from Settings.
    # Cleared whenever the embedding endpoint/model changes. Gates index features.
    ai_embedding_verified: bool = False
    # Set True only after a successful live chat round-trip (Test chat model) from Settings.
    # Cleared whenever the summary provider/model/base-url/key changes (packet 033, #13).
    ai_summary_verified: bool = False
    # (packet 053) Summarization input budget per object. We do NOT truncate — up to this many
    # chars we send the whole object in one call; over it, summarize map-reduces (extract per chunk
    # then synthesize) so the totality informs the one-liner. 0 = never chunk (single call).
    ai_summary_max_content_chars: int = 12000
    # (packet 053) When True, append each object's cross-references (Used by / Uses) to its summary
    # prompt, so summaries reflect usage, not just the body. Costs more tokens → default OFF.
    ai_summary_include_xref: bool = False
    # Store the original FM source XML (gzip-compressed) alongside each artifact. Packet 059: DEFAULT ON
    # (the "unasserted default is to retain") — source is the archived original for git export / download /
    # FMUpgradeTool / audit. The election is to DELETE it (User / MCP / Job) to reclaim space; re-derivation
    # is not a goal. A 146 MB export is ~15–30 MB gzipped.
    keep_source_xml: bool = True
    # Encrypt container blobs (artifact bodies / raw XML / deliverable XML) at rest with the
    # install's Fernet key. DEFAULT OFF: blobs stored plaintext gzip → the DB backup is
    # self-sufficient (readable directly, survives loss of the installation). ON: blobs are
    # key-locked → losing the installation's Corpus Key means losing this blob data. Toggling
    # this triggers a bulk re-encode of every stored blob (see routes/api/settings storage).
    encrypt_blobs: bool = False
    # (The AI provider API key is NOT here — packet 1007 stores it in the Corpus-Key-encrypted
    # SETTING.AiKeys CONTAINER, read via corpusfm.server.ai_env. A secret never sits in any
    # table's JSONOfRecord / indexed slots — only in an encrypted container.)
    # Expose the broad FMS-admin tools (fms_*) over MCP. DEFAULT OFF (opt-in): the FMS
    # control surface is the sharpest thing on the bus, so it is hidden from tools/list and
    # refused at call time unless an admin turns this on. Orthogonal to the per-user `fms_api`
    # gate — this is a server-wide kill switch; the gate is still required when it is on.
    enable_fms_admin_mcp_tools: bool = False
    # Expose the MCP patch/apply MUTATOR surface (the `patching`-gated tools: dry_run_patch,
    # plan_apply, apply_patch, generate_db_file, plan/execute_promote_generated_db,
    # reimport_after_patch) over MCP. DEFAULT OFF (opt-in): applying/materializing against
    # production FM files is the other high-blast-radius surface, so it is hidden from tools/list
    # and refused at call time unless an admin turns this on. Orthogonal to the per-user `patching`
    # gate and the `is_storage_database` guard — both still apply when it is on. The static/read-only
    # + catalog-write patch tools (`library_mcp`-gated) stay available regardless (packet 1059).
    enable_patching_mcp_tools: bool = False
    # Packet 1326: the first settings-gated sign-in on an installation is prompted ONCE to confirm the
    # MCP address the box asserted for itself. Durable and per-INSTALL by developer ruling (a second
    # administrator does not see it), so it lives here rather than in a user pref, a cookie or a session.
    initial_mcp_address_acknowledged: bool = False
    # How long an OAUTH CONNECTION stays usable before OAuth sign-in is required again (packet 1183).
    # One of "standard" (30 days inactive / 1 year maximum — the default), "reduced" (7 days / 90 days)
    # or "strict" (1 day / 30 days); the durations live in corpusfm.app.web.oauth_policy. This is NOT the
    # access-credential lifetime (a fixed 8 hours, rotated silently) — it bounds the connection. Read
    # fresh at authorization and at every refresh, so a change needs no service restart. Tightening
    # shortens existing connections immediately; loosening never extends one granted under a tighter
    # policy.
    browser_connection_lifetime: str = "standard"
    # Restrict every apply/patch target to CORPUSfm's own file COMPARTMENT. DEFAULT ON: a
    # patch/apply/dry-run may target only a file hosted from the ONE verified compartment the
    # installation manifest records; anything hosted from the default Databases directory (top level
    # or any other subfolder) is refused BY CONSTRUCTION, and a target whose hosted path can't be
    # resolved fails CLOSED. Turning it OFF ("pull the stops" for a dedicated patch box) widens the
    # eligible set to any hosted DB EXCEPT the storage DB.
    #
    # **It is a PREFERENCE, never an authorization (packet 1246-05-02 §3).** The verified-compartment
    # prerequisite is decided BEFORE this is consulted: with no verified compartment, OFF widens
    # nothing, because there is nothing authorized to widen. This config no longer defines the
    # compartment — the {support_dir, hosting_dir} mirror that used to live here is gone, and
    # db_helper.load_published_patch_authority() reads the manifest instead. The gate lives at
    # db_helper.check_apply_target — the shared chokepoint behind the human ISV/Patch-ops UI,
    # plan_apply, dry_run_patch, and the apply loop — so it is broader than the MCP-only
    # enable_patching switch.
    restrict_apply_to_compartment: bool = True
    # External auth (packet 1065) — FMS-parity OIDC/OAuth + AD/LDAP for the web UI. NON-SECRET config
    # only (the OIDC client_secret + LDAP bind password live in the Corpus-Key-encrypted SETTING.OidcSecret
    # container, read via corpusfm.server.oidc_secrets — never here / in jor). One nested dict, shape:
    #   {"oidc": {enabled, issuer, client_id, redirect_uri, scopes, groups_claim},
    #    "ldap": {enabled, server_uri, base_dn, bind_dn, user_filter, group_attr},
    #    "group_gate_map": {"<idp-group>": ["settings", ...], ...}}   # Ph2 authorization parity
    # Local username/password is always retained (per-user + break-glass) regardless of this.
    external_auth: dict = field(default_factory=dict)


def _try_fm_backend():
    """Return FileMakerODataBackend if FM OData is configured, else None.

    Raises RuntimeError when storage_backend=fm_odata but the backend cannot
    be instantiated — FM unreachable is a hard error in server mode, not a
    silent fallback to the filesystem.
    """
    from corpusfm.lifecycle import runtime_storage

    active = runtime_storage.fm_storage_active()
    if active is None:                        # nothing published — the dev/test path, unchanged
        from corpusfm.install import read_install_config
        if read_install_config().get("storage_backend") != "fm_odata":
            return None
    elif not active:
        raise RuntimeError(
            "this installation is published but has composed no corpus; refusing to keep settings "
            "on the filesystem while its storage authority is incomplete.")
    from corpusfm.storage import get_backend
    b = get_backend()
    if not hasattr(b, "load_fm_settings"):
        raise RuntimeError(
            "the storage backend could not be loaded as a FileMaker OData store."
        )
    return b


class SettingsUnavailable(RuntimeError):
    """The authoritative settings store could not be READ — distinct from having nothing stored.

    Packet 1189. Ordinary callers never see this: they keep the historical behavior where an outage and
    a fresh install both produce defaults. A caller whose setting is a SECURITY CEILING passes
    ``require_authority=True``, because for it "we could not read the policy" and "no policy is set" are
    opposite answers — the first must refuse, the second is documented Standard.

    Only the FM authority can be unavailable. The local-YAML path is a present-or-absent file with no
    network in between, and an absent or unparseable file is the documented fresh-install case
    (`oauth_policy.normalize_policy_id`), so it keeps resolving to defaults under either flag."""


def load_authoritative_setting(key: str, default=""):
    """One RAW stored setting, read from the authority, with nothing else interpreted (packet 1189).

    ``load_app_config(require_authority=True)`` was the first attempt and was WRONG for a security
    ceiling: it constructs the whole ``AppConfig`` after the read, so a malformed UNRELATED field (say
    ``ai_embedding_batch_size="x"`` hitting ``int()``) raised, and the policy caller could not tell that
    apart from an unreadable authority — refusing a policy it could in fact have read. Found by review.

    So this reads the authoritative dict and returns one key from it. Raises :class:`SettingsUnavailable`
    only when the AUTHORITY itself could not be read. Everything about the VALUE — absent, empty, the
    wrong type, unrecognized — is the caller's to normalize, per the absent-vs-unavailable rule.

    A misconfigured install (``storage_backend: fm_odata`` with an FM backend that cannot be
    instantiated) is reported as unavailable too, and deliberately: we genuinely cannot reach the
    authority. It is a distinct message so a log reader can tell the two apart.

    Deliberately takes no ``path``, unlike :func:`load_app_config`: that parameter exists so a test can
    point the LOCAL-YAML fallback at a temporary file, and a security ceiling should be read from the
    one authority this deployment actually runs on — not from a caller-supplied location.
    """
    try:
        b = _try_fm_backend()
    except Exception as exc:
        raise SettingsUnavailable("the storage backend holding settings could not be loaded") from exc
    if b is not None:
        try:
            fm = b.load_fm_settings(strict=True)
        except Exception as exc:
            raise SettingsUnavailable("the authoritative settings store could not be read") from exc
        # A SUCCESSFUL read is the answer, including an empty one. Falling through to the local file
        # here (as an earlier version did) lets a stale YAML `browser_connection_lifetime` override the
        # authority's "nothing is set" — silently enforcing a policy the administrator removed, from a
        # file FM mode does not even maintain (found by review). Absent-at-the-authority is Standard.
        return fm.get(key, default)
    # No FM authority at all (dev/LocalBackend): the local file IS the authority, and an absent or
    # unparseable one is the documented fresh-install case — an ANSWER, never an outage.
    try:
        import yaml
        data = yaml.safe_load(default_app_config_path().read_text(encoding="utf-8")) or {}
        return (data or {}).get(key, default)
    except Exception:
        return default


def load_app_config(path: Optional[Path] = None, *, require_authority: bool = False,
                    backend=None) -> AppConfig:
    """Read the app settings, freshly, every call.

    `backend` lets a caller that has ALREADY resolved a storage backend hand it in rather than make
    this function resolve one (packet 1361-01). Resolution is the expensive half — it re-reads the
    installation record, loads the held credential, and builds a backend whose first request pays a
    TLS handshake — so a request that reads settings through a backend it already holds pays for the
    read alone. It changes nothing about WHEN settings are read: there is no memo here, and the next
    call still goes to the authority.

    A supplied backend that is not a FileMaker store (the LocalBackend dev/test path) falls through
    to the YAML file, exactly as an unset `storage_backend` does.
    """
    # FM OData mode: read preferences from FM SETTINGS.
    if backend is not None:
        b = backend if hasattr(backend, "load_fm_settings") else None
    else:
        try:
            b = _try_fm_backend()
        except Exception as exc:
            # Packet 1396: a require_authority caller must not see a backend that will not load as a
            # 500 or a silent stale-YAML fallback — it is the authority being unavailable.
            if require_authority:
                raise SettingsUnavailable(
                    "the storage backend holding settings could not be loaded") from exc
            raise
    if b is not None:
        try:
            fm = b.load_fm_settings(strict=True) if require_authority else b.load_fm_settings()
            if fm:
                return AppConfig(
                    encrypt_blobs=bool(fm.get("encrypt_blobs", False)),
                    preferred_addon_locale=str(fm.get("preferred_addon_locale", "")),
                    ui_locale=str(fm.get("ui_locale", "")),
                    landing_page=str(fm.get("landing_page", "") or "artifacts"),
                    docs_drawer_side=str(fm.get("docs_drawer_side", "") or "right"),
                    ai_summary_provider=str(fm.get("ai_summary_provider", "")),
                    ai_summary_model=str(fm.get("ai_summary_model", "")),
                    ai_summary_base_url=str(fm.get("ai_summary_base_url", "")),
                    ai_summary_api_version=str(fm.get("ai_summary_api_version", "")),
                    ai_embedding_provider=str(fm.get("ai_embedding_provider", "")),
                    ai_embedding_model=str(fm.get("ai_embedding_model", "")),
                    ai_embedding_base_url=str(fm.get("ai_embedding_base_url", "")),
                    ai_embedding_api_version=str(fm.get("ai_embedding_api_version", "")),
                    ai_embedding_batch_size=int(fm.get("ai_embedding_batch_size", 0) or 0),
                    ai_embedding_verified=bool(fm.get("ai_embedding_verified", False)),
                    ai_summary_verified=bool(fm.get("ai_summary_verified", False)),
                    enable_fms_admin_mcp_tools=bool(fm.get("enable_fms_admin_mcp_tools", False)),
                    enable_patching_mcp_tools=bool(fm.get("enable_patching_mcp_tools", False)),
                    initial_mcp_address_acknowledged=bool(fm.get("initial_mcp_address_acknowledged", False)),
                    browser_connection_lifetime=_browser_connection_lifetime(
                        fm.get("browser_connection_lifetime", "")),
                    restrict_apply_to_compartment=bool(fm.get("restrict_apply_to_compartment", True)),
                    external_auth=dict(fm.get("external_auth") or {}),
                )
            if require_authority:
                # A SUCCESSFUL but EMPTY authoritative read is "nothing is set" → defaults, NEVER the
                # local YAML file, which FM mode does not maintain (packet 1396). Falling through here
                # would let a stale YAML value (e.g. browser_connection_lifetime, external_auth)
                # resurrect a policy the administrator cleared. The permissive path below keeps its
                # historical fall-through, where an outage and a fresh install both produce defaults.
                return AppConfig()
        except SettingsUnavailable:
            raise
        except Exception as exc:
            # Packet 1396: under require_authority, an unreadable OR MALFORMED authoritative record is
            # "unavailable" — both the store that will not read and the record whose fields will not
            # parse (a bad int/dict) must refuse the same way, never a bare 500 and never stale YAML.
            # The permissive path keeps its historical behavior (propagate).
            if require_authority:
                raise SettingsUnavailable(
                    "the authoritative settings store could not be read or is malformed") from exc
            raise
    p = path or default_app_config_path()
    try:
        import yaml
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return AppConfig(
            keep_source_xml=bool(data.get("keep_source_xml", True)),
            encrypt_blobs=bool(data.get("encrypt_blobs", False)),
            preferred_addon_locale=str(data.get("preferred_addon_locale", "")),
            ui_locale=str(data.get("ui_locale", "")),
            landing_page=str(data.get("landing_page", "") or "artifacts"),
            docs_drawer_side=str(data.get("docs_drawer_side", "") or "right"),
            ai_summary_provider=str(data.get("ai_summary_provider", "")),
            ai_summary_model=str(data.get("ai_summary_model", "")),
            ai_summary_base_url=str(data.get("ai_summary_base_url", "")),
            ai_summary_api_version=str(data.get("ai_summary_api_version", "")),
            ai_embedding_provider=str(data.get("ai_embedding_provider", "")),
            ai_embedding_model=str(data.get("ai_embedding_model", "")),
            ai_embedding_base_url=str(data.get("ai_embedding_base_url", "")),
            ai_embedding_api_version=str(data.get("ai_embedding_api_version", "")),
            ai_embedding_batch_size=int(data.get("ai_embedding_batch_size", 0) or 0),
            ai_embedding_verified=bool(data.get("ai_embedding_verified", False)),
            ai_summary_verified=bool(data.get("ai_summary_verified", False)),
            enable_fms_admin_mcp_tools=bool(data.get("enable_fms_admin_mcp_tools", False)),
            enable_patching_mcp_tools=bool(data.get("enable_patching_mcp_tools", False)),
            initial_mcp_address_acknowledged=bool(data.get("initial_mcp_address_acknowledged", False)),
            browser_connection_lifetime=_browser_connection_lifetime(
                data.get("browser_connection_lifetime", "")),
            restrict_apply_to_compartment=bool(data.get("restrict_apply_to_compartment", True)),
            external_auth=dict(data.get("external_auth") or {}),
        )
    except Exception:
        return AppConfig()


def settings_to_fm_dict(config: AppConfig) -> dict:
    """The non-secret team settings persisted into the SETTING singleton's JSONOfRecord.

    The single source for both a normal save and the startup 'full default template'
    (``settings_to_fm_dict(AppConfig())``)."""
    return {
        "encrypt_blobs": config.encrypt_blobs,
        "preferred_addon_locale": config.preferred_addon_locale or "",
        "ui_locale": config.ui_locale or "",
        "landing_page": config.landing_page or "artifacts",
        "docs_drawer_side": config.docs_drawer_side or "right",
        "ai_summary_provider": config.ai_summary_provider or "",
        "ai_summary_model": config.ai_summary_model or "",
        "ai_summary_base_url": config.ai_summary_base_url or "",
        "ai_summary_api_version": config.ai_summary_api_version or "",
        "ai_embedding_provider": config.ai_embedding_provider or "",
        "ai_embedding_model": config.ai_embedding_model or "",
        "ai_embedding_base_url": config.ai_embedding_base_url or "",
        "ai_embedding_api_version": config.ai_embedding_api_version or "",
        "ai_embedding_batch_size": int(config.ai_embedding_batch_size or 0),
        "ai_embedding_verified": config.ai_embedding_verified,
        "ai_summary_verified": config.ai_summary_verified,
        # The AI provider key is NOT persisted here — it lives in the SETTING.AiKeys container
        # (packet 1007). No secret in jor/slots.
        "enable_fms_admin_mcp_tools": config.enable_fms_admin_mcp_tools,
        "enable_patching_mcp_tools": config.enable_patching_mcp_tools,
        "initial_mcp_address_acknowledged": config.initial_mcp_address_acknowledged,
        "browser_connection_lifetime": _browser_connection_lifetime(config.browser_connection_lifetime),
        "restrict_apply_to_compartment": config.restrict_apply_to_compartment,
        # NON-secret external-auth config (packet 1065); the OIDC client_secret + LDAP bind password
        # ride the SETTING.OidcSecret container, never here.
        "external_auth": dict(config.external_auth or {}),
    }


def _reconcile_fm_settings_write(b, intended: dict) -> None:
    """Classify a SETTING write that raised AFTER being dispatched (packet 1190-02).

    Reread the authority and compare only the keys this write intended — the JSONOfRecord is shared
    with independent writers (tags, file_tracking), so their keys are none of our business.

    **A match is CONFIRMED COMMITTED even if the values were already there.** This path's
    postcondition is STATE ("the stored configuration says X"), not EVENT ("my PATCH landed"), and
    every caller with consequential follow-on work asks the former: blob conversion must run iff the
    setting says encrypt, secrets must be written iff the config says that provider is configured. So
    the redundant-no-op-save case that would be unprovable as an event is a *satisfied postcondition*
    here — which is why this needs none of packet 1190-01's witness machinery.
    """
    try:
        stored = b.load_fm_settings(strict=True)
    except Exception as exc:
        raise ConfigWriteIndeterminate(
            f"the settings write was dispatched and the reread failed: {exc}") from exc
    differing = [k for k, v in intended.items() if k not in stored or stored[k] != v]
    if differing:
        # NOT proof of non-commit. A concurrent merge by another writer can overwrite a value that
        # DID land, so "the stored value is not what I wrote" has innocent explanations (the parent
        # packet's reread rule). Only a pre-dispatch failure proves nothing happened.
        raise ConfigWriteIndeterminate(
            "the settings write was dispatched and the stored configuration does not match it "
            f"({len(differing)} key(s) differ, first: {differing[0]})")


def save_app_config(config: AppConfig, path: Optional[Path] = None) -> None:
    """Persist ``config``. **Returns normally only when the configuration is confirmed to say what
    was asked** — that is the postcondition, and a caller with no follow-on work needs nothing else.

    Under an FM backend the outcome is one of three (packet 1190-02):

    * confirmed committed → returns normally;
    * confirmed NOT committed → :class:`ConfigWriteNotCommitted`, safe to retry unchanged;
    * indeterminate → :class:`ConfigWriteIndeterminate`, do NOT assume either way.

    The **YAML dev path keeps its two-outcome shape** (return, or raise whatever went wrong); it is
    the local/no-backend path and is deliberately out of the contract. Every caller keeps its bare
    ``Exception`` handler, so the asymmetry costs nothing — but do not read a plain exception from
    this function as proof that nothing was stored.
    """
    # FM OData mode: team settings are authoritative in FM SETTING. A write failure FAILS VISIBLY
    # (packet 1009/S2) — it is NOT swallowed into a local-YAML fallthrough. The old fallthrough wrote a
    # YAML that FM-mode load_app_config then IGNORES, so the save LOOKED successful while FM SETTING
    # stayed unchanged (silent authority split). Let the exception propagate; the settings route turns
    # it into a real error the admin sees. YAML is only the genuine local/dev path (no FM backend).
    b = _try_fm_backend()
    if b is not None:
        # Lazy, and safe: reaching here means fm_odata is the configured backend and already imported.
        from corpusfm.storage.fm_odata import SettingsWriteNotDispatched
        try:
            # Building the payload is PRE-DISPATCH — a value that will not coerce proves nothing was
            # sent, so it belongs inside the proof rather than escaping unclassified.
            intended = settings_to_fm_dict(config)
        except Exception as exc:
            raise ConfigWriteNotCommitted(f"the settings payload could not be built: {exc}") from exc
        try:
            b.save_fm_settings(intended)
        except SettingsWriteNotDispatched as exc:
            raise ConfigWriteNotCommitted(str(exc)) from exc
        except Exception:
            _reconcile_fm_settings_write(b, intended)
            # The reread proved the configuration says what was asked. The postcondition holds, so
            # this IS success — raising here would make every caller handle a success as a failure.
        return
    p = path or default_app_config_path()
    import yaml
    payload: dict = {}
    if config.preferred_addon_locale:
        payload["preferred_addon_locale"] = config.preferred_addon_locale
    if config.ui_locale:
        payload["ui_locale"] = config.ui_locale
    if config.landing_page:
        payload["landing_page"] = config.landing_page
    if config.docs_drawer_side and config.docs_drawer_side != "right":
        payload["docs_drawer_side"] = config.docs_drawer_side
    if config.ai_summary_provider:
        payload["ai_summary_provider"] = config.ai_summary_provider
    if config.ai_summary_model:
        payload["ai_summary_model"] = config.ai_summary_model
    if config.ai_summary_base_url:
        payload["ai_summary_base_url"] = config.ai_summary_base_url
    if config.ai_summary_api_version:
        payload["ai_summary_api_version"] = config.ai_summary_api_version
    if config.ai_embedding_provider:
        payload["ai_embedding_provider"] = config.ai_embedding_provider
    if config.ai_embedding_model:
        payload["ai_embedding_model"] = config.ai_embedding_model
    if config.ai_embedding_base_url:
        payload["ai_embedding_base_url"] = config.ai_embedding_base_url
    if config.ai_embedding_api_version:
        payload["ai_embedding_api_version"] = config.ai_embedding_api_version
    if config.ai_embedding_batch_size:
        payload["ai_embedding_batch_size"] = int(config.ai_embedding_batch_size)
    if config.ai_embedding_verified:
        payload["ai_embedding_verified"] = True
    if config.ai_summary_verified:
        payload["ai_summary_verified"] = True
    # Packet 059: default True, so write it ALWAYS (an explicit False must round-trip, not be dropped).
    payload["keep_source_xml"] = bool(config.keep_source_xml)
    if config.encrypt_blobs:
        payload["encrypt_blobs"] = True
    if config.enable_fms_admin_mcp_tools:
        payload["enable_fms_admin_mcp_tools"] = True
    if config.enable_patching_mcp_tools:
        payload["enable_patching_mcp_tools"] = True
    # Written unconditionally (packet 1326): the acknowledgement must round-trip as an explicit value,
    # never be inferred from absence — an absent key is a box that has not been prompted yet.
    payload["initial_mcp_address_acknowledged"] = bool(config.initial_mcp_address_acknowledged)
    # Packet 1183: written ALWAYS — a deliberate non-default policy (the tighter choices) must round-trip,
    # and an explicit "standard" must not read back as "the setting was never made".
    payload["browser_connection_lifetime"] = _browser_connection_lifetime(config.browser_connection_lifetime)
    # Packet 1066: default True, so write it ALWAYS (an explicit False — "pull the stops" — must
    # round-trip, not be dropped back to the restrictive default).
    payload["restrict_apply_to_compartment"] = bool(config.restrict_apply_to_compartment)
    if config.external_auth:
        payload["external_auth"] = dict(config.external_auth)
    p.write_text(yaml.dump(payload, default_flow_style=False), encoding="utf-8")
