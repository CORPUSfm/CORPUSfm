"""Monitor configuration.

Primary store (co-located / fm_odata mode): the non-secret config lives in the storage DB's SETTING
singleton JSONOfRecord under the ``"monitor"`` key (so it TRAVELS with the corpus, the way
team settings do), and the SMTP password rides the Corpus-Key-encrypted SETTING ``NotifySecret`` container —
never jor (the universal no-secret-in-jor fence). This mirrors ``app.app_config`` exactly.

Dev/local fallback (no FM backend): ``monitor.yaml`` at the project root, password encrypted at rest.
Zero-config defaults to display-only.

Public API:
    MonitorConfig
    default_monitor_config_path()
    load_monitor_config()
    save_monitor_config(config)
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import yaml

_PROJECT_ROOT = Path(__file__).parent.parent.parent

# The SETTING JSONOfRecord key holding the non-secret monitor config (the whole sub-dict is owned by
# this writer; save_fm_settings merges at the top level so sibling team settings are preserved).
_MONITOR_JSON_KEY = "monitor"

log = logging.getLogger("corpusfm.monitor.config")


@dataclass
class MonitorConfig:
    # Alert thresholds
    suppress_hours: int = 4
    overdue_grace_minutes: int = 15     # how long after cron fire time before alerting
    zero_diff_threshold: int = 3        # consecutive zero-diff runs before alerting
    disk_min_gb: float = 1.0           # free GB threshold for disk_low alert

    # Notification channels (None = disabled)
    webhook_url: Optional[str] = None  # POST alert JSON here
    email: Optional[dict] = None       # smtp_host, smtp_port, username, password, from_addr, to_addrs


def default_monitor_config_path() -> Path:
    return _PROJECT_ROOT / "monitor.yaml"


def _try_fm_backend():
    """Return FileMakerODataBackend when FM OData is the configured store, else None.

    Mirrors ``app.app_config._try_fm_backend``: FM unreachable in server mode is a hard error, not a
    silent fall-through to the filesystem (a swallowed write would leave the SETTING blob unchanged
    while the save LOOKED successful — the same authority-split bug packet 1009/S2 closed)."""
    from corpusfm.lifecycle import runtime_storage

    active = runtime_storage.fm_storage_active()
    if active is None:                        # nothing published — the dev/test path, unchanged
        from corpusfm.install import read_install_config
        if read_install_config().get("storage_backend") != "fm_odata":
            return None
    elif not active:
        raise RuntimeError(
            "this installation is published but has composed no corpus; refusing to fall through "
            "to the filesystem for monitor configuration.")
    from corpusfm.storage import get_backend
    b = get_backend()
    if not hasattr(b, "load_fm_settings"):
        raise RuntimeError(
            "storage_backend is fm_odata but FileMakerODataBackend could not be loaded. "
            "Check FM connection config in install.yaml."
        )
    return b


def _config_from_dict(data: dict) -> MonitorConfig:
    fields = MonitorConfig.__dataclass_fields__
    return MonitorConfig(**{k: v for k, v in (data or {}).items() if k in fields})


def _monitor_to_fm_dict(config: MonitorConfig) -> dict:
    """The non-secret monitor config for the SETTING JSON blob. The SMTP password is EXCLUDED — it
    rides the Corpus-Key-encrypted NotifySecret container, never jor (the universal secret fence)."""
    email = None
    if isinstance(config.email, dict):
        email = {k: v for k, v in config.email.items() if k != "password"}
    return {
        "suppress_hours": config.suppress_hours,
        "overdue_grace_minutes": config.overdue_grace_minutes,
        "zero_diff_threshold": config.zero_diff_threshold,
        "disk_min_gb": config.disk_min_gb,
        "webhook_url": config.webhook_url,
        "email": email,
    }


def _encode_notify_pw(pw: str) -> bytes:
    from corpusfm.core.crypto import compress, encode_blob
    return encode_blob(compress(pw.encode("utf-8")), encrypt_on=True)  # ALWAYS Corpus-Key-encrypted


def _decode_notify_pw(raw: bytes) -> str:
    from corpusfm.core.crypto import decode_blob, decompress
    return decompress(decode_blob(raw)).decode("utf-8")


def load_monitor_config(path: Path = None) -> MonitorConfig:
    """Load MonitorConfig. In fm_odata mode: non-secret config from the SETTING ``monitor`` blob +
    the SMTP password from the NotifySecret container (decrypted into memory so senders authenticate
    with the plaintext). In dev/local mode: from ``monitor.yaml``. Defaults if unset/unreadable."""
    b = _try_fm_backend()
    if b is not None:
        try:
            fm = b.load_fm_settings() or {}
            cfg = _config_from_dict(fm.get(_MONITOR_JSON_KEY, {}))
            if cfg.email and hasattr(b, "read_notify_secret"):
                raw = b.read_notify_secret()
                if raw:
                    cfg.email = {**cfg.email, "password": _decode_notify_pw(raw)}
            return cfg
        except Exception:
            log.debug("monitor: FM load failed", exc_info=True)
            return MonitorConfig()

    # Dev/local fallback: monitor.yaml, password encrypted at rest (a legacy plaintext value with no
    # marker is read as-is and re-encrypted on the next save).
    p = path or default_monitor_config_path()
    if not p.exists():
        return MonitorConfig()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        cfg = _config_from_dict(data)
        if isinstance(cfg.email, dict) and cfg.email.get("password"):
            from corpusfm.core.crypto import decrypt_secret
            cfg.email = {**cfg.email, "password": decrypt_secret(cfg.email["password"])}
        return cfg
    except Exception:
        return MonitorConfig()


def save_monitor_config(config: MonitorConfig, path: Path = None) -> None:
    """Persist MonitorConfig. In fm_odata mode: non-secret config MERGES into the SETTING ``monitor``
    blob and the SMTP password is written to (or cleared from) the Corpus-Key-encrypted NotifySecret
    container. A write failure PROPAGATES (no silent local-YAML fallthrough — packet 1009/S2). In
    dev/local mode: ``monitor.yaml``, PRIVATE-AT-CREATION (0600), SMTP password encrypted at rest."""
    b = _try_fm_backend()
    if b is not None:
        b.save_fm_settings({_MONITOR_JSON_KEY: _monitor_to_fm_dict(config)})
        if hasattr(b, "write_notify_secret"):
            pw = config.email.get("password", "") if isinstance(config.email, dict) else ""
            if pw:
                b.write_notify_secret(_encode_notify_pw(pw))
            else:
                b.clear_notify_secret()
        return

    p = path or default_monitor_config_path()
    data = asdict(config)
    email = data.get("email")
    if isinstance(email, dict) and email.get("password"):
        from corpusfm.core.crypto import encrypt_secret
        data["email"] = {**email, "password": encrypt_secret(email["password"])}
    from corpusfm.core import secure_fs
    secure_fs.write_text_private(p, yaml.dump(data, allow_unicode=True, sort_keys=False),
                                 secure_parent=False)
