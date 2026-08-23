"""Central logging configuration for corpusfm.

Called once at web-app startup (corpusfm/app/web/app.py). Without it Python's
default NullHandler applies — no output unless the caller configures logging
themselves.
"""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
_BACKUP_COUNT = 3
_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"

# Third-party loggers that produce too much noise at INFO
_QUIET = ("watchdog", "urllib3", "httpx", "httpcore", "asyncio", "git")

_configured = False


def log_dir() -> Path:
    from corpusfm.lifecycle import app_paths
    return app_paths.log_dir()


def log_path() -> Path:
    return log_dir() / "corpusfm.log"


def setup_logging(level: int = logging.INFO, _log_file: Path = None) -> Path:
    """Configure the root logger with a rotating file handler. Returns the log file path.

    Safe to call multiple times — only configures on the first call.
    Pass _log_file to redirect output (used in tests).
    """
    global _configured
    if _configured:
        return _log_file or log_path()
    _configured = True

    path = _log_file or log_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(_FORMAT, datefmt=_DATE_FMT)
    handler = logging.handlers.RotatingFileHandler(
        path,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

    for name in _QUIET:
        logging.getLogger(name).setLevel(logging.WARNING)

    return path


def _reset_for_testing() -> None:
    """Remove all root handlers and reset the configured flag. Tests only."""
    global _configured
    _configured = False
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()


def reset_path_derived_handler() -> None:
    """Drop the file handler bound to the previously resolved log directory (packet 1246-03-01).

    A handler is a cache too, and a worse-behaved one than a variable: `RotatingFileHandler` opens
    the file at construction and keeps writing to that inode forever. Clearing the path cache while
    it lives means `log_path()` reports the NEW location while every line still lands in the old
    one — a log that lies about where it is. Only handlers pointing at a file are removed, so a
    caller that passed its own `_log_file` is not silently disconnected from something else.
    """
    global _configured
    root = logging.getLogger()
    removed = False
    for h in list(root.handlers):
        if isinstance(h, logging.FileHandler):
            root.removeHandler(h)
            h.close()
            removed = True
    if removed:
        _configured = False


def _register_with_app_paths() -> None:
    from corpusfm.lifecycle import app_paths

    app_paths.register_cache_reset(reset_path_derived_handler)


_register_with_app_paths()
