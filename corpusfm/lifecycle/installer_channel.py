"""Installer-channel eligibility: the decision, the record, and the service-side reader (packet 1399).

Settings used to offer `corpusfm-installer` as the remedy whenever an update needed the installer,
without knowing whether the configured channel held a package that would advance this installation.
fms-dev, running 0.2905, was offered published 0.2818, and the installer necessarily refused.

**Who knows what.** The channel is read by ROOT, inside the fixed privileged updater
(`installer_channel_observer`), because only root holds the channel credential. This module holds
no network code and no credential. It is the pure decision the observer applies, the one record
schema, and the reader the service uses, so the observer and the service cannot disagree about what
a record means.

**The predicate is the installer's own** (`install.ps1` external-source advance): the deployed HEAD
must be an ancestor of the package commit. A package at the deployed HEAD is accepted and advances
nothing, so it is never eligible.

**Three states, and `unknown` is never confident.** A missing, unreadable, stale or unprovable record
is `unknown`, never `unavailable`. Only `eligible` may present the installer as the remedy.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

RECORD_FILENAME = "installer_channel.json"
SCHEMA_VERSION = 1
KIND = "installer_channel_observation"

ELIGIBLE = "eligible"
UNAVAILABLE = "unavailable"
UNKNOWN = "unknown"
STATES = (ELIGIBLE, UNAVAILABLE, UNKNOWN)

#: Final freshness ruling (§7.5): two 2 h observer intervals, two 5 min outcome timeouts, 5 min margin.
FRESHNESS = timedelta(hours=4, minutes=15)
#: The stated ceiling (§7.1). It does not bind at the current cadence; it exists so a later cadence
#: change cannot silently extend staleness.
CEILING = timedelta(hours=6)
#: A record dated this far in the future is not a record of the past.
CLOCK_SKEW = timedelta(minutes=5)

# Reason codes. Each `unknown` cause is distinct, so whoever acts on it can tell them apart (§7.2).
R_ADVANCES = "advances"
R_SAME_COMMIT = "channel_package_is_deployed_commit"
R_NOT_DESCENDANT = "channel_package_not_ahead_of_installation"
R_BRIDGE = "bridge_package"
R_SERIES = "series_mismatch"
R_NOT_LOCAL = "channel_commit_not_local"
R_UNREADABLE = "channel_unreadable"
R_INVALID = "channel_metadata_invalid"
R_NOT_OBSERVED = "not_observed"
R_RECORD_INVALID = "record_invalid"
R_AUTHORITY = "record_authority_unproven"
R_OPERANDS = "operands_changed"
R_STALE = "observation_stale"
R_FUTURE = "observation_future_dated"
R_NO_INSTALLATION = "installation_state_unclear"
R_OBSERVER_FAILED = "observation_failed"

_COMMIT = re.compile(r"^[0-9a-f]{40,64}$")
_VERSION = re.compile(r"^0\.[0-9]+$")
_SERIES = re.compile(r"^series-[1-9][0-9]*$")
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def record_path(state_dir: Path | str) -> Path:
    from .update_boundary import outcome_dir

    return outcome_dir(state_dir) / RECORD_FILENAME


def _utc(when: Optional[datetime] = None) -> str:
    return (when or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def channel_facts(release: Mapping[str, Any], *, release_tag: str = "") -> dict:
    """The validated facts of one `release.json`. Raises ValueError on anything malformed."""
    if not isinstance(release, Mapping) or release.get("schema_version") != 1:
        raise ValueError("release.json schema_version is not 1")
    commit = str(release.get("commit", ""))
    app_version = str(release.get("application_version", ""))
    installer_version = str(release.get("installer_version", ""))
    series = str(release.get("installer_series", ""))
    bridge = release.get("bridge")
    if not _COMMIT.match(commit):
        raise ValueError("release.json commit is not a commit id")
    # application_version is read EXPLICITLY; it is never assumed equal to installer_version (§2).
    if not _VERSION.match(app_version) or not _VERSION.match(installer_version):
        raise ValueError("release.json versions are malformed")
    if not _SERIES.match(series):
        raise ValueError("release.json installer_series is malformed")
    if not isinstance(bridge, Mapping) or not isinstance(bridge.get("is_bridge"), bool):
        raise ValueError("release.json bridge block is malformed")
    if release_tag and not _TAG.match(release_tag):
        raise ValueError("release tag is malformed")
    return {
        "commit": commit,
        "application_version": app_version,
        "installer_version": installer_version,
        "installer_series": series,
        "release_tag": release_tag,
        "is_bridge": bool(bridge["is_bridge"]),
    }


def _record(state: str, reason: str, *, operands: Mapping[str, str], channel: Optional[dict],
            advances: bool, reaches_target: Optional[bool], observed_utc: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "state": state,
        "reason": reason,
        "advances": advances,
        "reaches_target": reaches_target,
        "observed_utc": observed_utc,
        "operands": dict(operands),
        "channel": channel,
    }


def unknown_record(reason: str, *, operands: Mapping[str, str], channel: Optional[dict] = None,
                   observed_utc: Optional[str] = None) -> dict:
    return _record(UNKNOWN, reason, operands=operands, channel=channel, advances=False,
                   reaches_target=None, observed_utc=observed_utc or _utc())


def decide(channel: dict, *, operands: Mapping[str, str],
           is_ancestor: Callable[[str, str], Optional[bool]],
           residual_requires_installer: Callable[[str, str], Optional[bool]],
           observed_utc: Optional[str] = None) -> dict:
    """Apply §1, §3, §4 and §7.2 to one set of validated channel facts.

    `is_ancestor(a, b)` is git's three-valued answer: True, False, or None when it could not be
    decided (most often: the package commit is not in the local object store). `None` is `unknown`.
    `residual_requires_installer(p, t)` is the update classifier over `p..t`; None means undecidable.
    """
    when = observed_utc or _utc()
    deployed, target = operands["deployed_head"], operands["target_head"]
    package = channel["commit"]

    if channel["is_bridge"]:
        return unknown_record(R_BRIDGE, operands=operands, channel=channel, observed_utc=when)
    if channel["installer_series"] != operands["installer_series"]:
        return unknown_record(R_SERIES, operands=operands, channel=channel, observed_utc=when)
    if package == deployed:
        # The installer accepts this as a no-op (`install.ps1`: seed head == deployed head). It is
        # also exactly what a refreshed observation finds after an intermediate install (§7.4).
        return _record(UNAVAILABLE, R_SAME_COMMIT, operands=operands, channel=channel,
                       advances=False, reaches_target=None, observed_utc=when)
    ancestry = is_ancestor(deployed, package)
    if ancestry is None:
        return unknown_record(R_NOT_LOCAL, operands=operands, channel=channel, observed_utc=when)
    if ancestry is False:
        return _record(UNAVAILABLE, R_NOT_DESCENDANT, operands=operands, channel=channel,
                       advances=False, reaches_target=None, observed_utc=when)

    reaches: Optional[bool]
    if package == target:
        reaches = True
    else:
        # The residual reaches the target by an ordinary code-only fast-forward only when the
        # package is behind the target on the same line and the residual needs no installer.
        on_line = is_ancestor(package, target)
        if on_line is not True:
            reaches = False if on_line is False else None
        else:
            needs = residual_requires_installer(package, target)
            reaches = None if needs is None else (not needs)
    return _record(ELIGIBLE, R_ADVANCES, operands=operands, channel=channel, advances=True,
                   reaches_target=reaches, observed_utc=when)


def validate_record(raw: Any) -> dict:
    """Refuse anything that is not exactly a v1 record. Raises ValueError, and ONLY ValueError:
    whatever shape a record arrives in, the reader's answer is `unknown`, never a traceback."""
    try:
        return _validate_record(raw)
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001 - any malformed shape is the same refusal
        raise ValueError(f"malformed record ({type(exc).__name__})") from None


_CHANNEL_KEYS = ("commit", "application_version", "installer_version", "installer_series",
                 "release_tag", "is_bridge")


def _validate_record(raw: Any) -> dict:
    if not isinstance(raw, Mapping) or raw.get("schema_version") != SCHEMA_VERSION or raw.get("kind") != KIND:
        raise ValueError("not an installer-channel record")
    state, reason = raw.get("state"), raw.get("reason")
    if state not in STATES or not isinstance(reason, str) or not reason:
        raise ValueError("state or reason is malformed")
    if not isinstance(raw.get("advances"), bool) or raw.get("reaches_target") not in (True, False, None):
        raise ValueError("advances/reaches_target are malformed")
    if state == ELIGIBLE and raw["advances"] is not True:
        raise ValueError("an eligible record must advance")
    if state != ELIGIBLE and raw["advances"] is not False:
        raise ValueError("only an eligible record may advance")
    operands = raw.get("operands")
    if not isinstance(operands, Mapping):
        raise ValueError("operands are missing")
    for key in ("deployed_head", "target_head"):
        if not _COMMIT.match(str(operands.get(key, ""))):
            raise ValueError(f"operand {key} is not a commit id")
    if not _SERIES.match(str(operands.get("installer_series", ""))):
        raise ValueError("operand installer_series is malformed")
    if any(not isinstance(operands.get(key), str) for key in
           ("deployed_head", "target_head", "installer_series", "channel_pointer_sha256")):
        raise ValueError("operands must be strings")
    pointer = operands["channel_pointer_sha256"]
    if pointer and not _SHA256.match(pointer):
        raise ValueError("operand channel_pointer_sha256 is malformed")
    channel = raw.get("channel")
    if channel is not None:
        if not isinstance(channel, Mapping) or set(channel) != set(_CHANNEL_KEYS):
            raise ValueError("channel facts are malformed")
        if not isinstance(channel.get("release_tag"), str):
            raise ValueError("channel release_tag is malformed")
        channel_facts({"schema_version": 1, "commit": channel.get("commit"),
                       "application_version": channel.get("application_version"),
                       "installer_version": channel.get("installer_version"),
                       "installer_series": channel.get("installer_series"),
                       "bridge": {"is_bridge": channel.get("is_bridge")}},
                      release_tag=str(channel.get("release_tag") or ""))
    elif state != UNKNOWN:
        raise ValueError("a confident state must carry the channel facts it was decided on")
    _parse_utc(raw.get("observed_utc"))
    return dict(raw)


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("observed_utc is missing")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def write_record(state_dir: Path | str, record: Mapping[str, Any]) -> Path:
    """ROOT writes this, beside the update outcome and under the same authority (§ invariant 2)."""
    from .atomic import atomic_write_text
    from .secret_guard import assert_no_secrets

    payload = validate_record(record)
    assert_no_secrets(payload, what="installer-channel record")
    path = record_path(state_dir)
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True), mode=0o644)
    return path


@dataclass(frozen=True)
class ChannelView:
    """What the service may say. `actionable` is the ONLY licence to offer the installer command."""

    state: str
    reason: str
    advances: bool = False
    reaches_target: Optional[bool] = None
    observed_utc: Optional[str] = None
    channel: Optional[dict] = None
    record: dict = field(default_factory=dict, repr=False)

    @property
    def actionable(self) -> bool:
        return self.state == ELIGIBLE and self.advances

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "reason": self.reason,
            "advances": self.advances,
            "reaches_target": self.reaches_target,
            "actionable": self.actionable,
            "observed_utc": self.observed_utc,
            "channel": dict(self.channel) if self.channel else None,
        }


def evaluate(record: Optional[Mapping[str, Any]], *, deployed_head: Optional[str],
             target_head: Optional[str], installer_series: Optional[str],
             now: Optional[datetime] = None) -> ChannelView:
    """Bind a record to the CURRENT operands, then — only then — to its age (§7.5 ordering).

    The channel-pointer operand cannot be re-read here (the service holds no route to the channel);
    it is bound inside the record, and a changed pointer is carried by the next root observation,
    which replaces this one.
    """
    if record is None:
        return ChannelView(UNKNOWN, R_NOT_OBSERVED)
    try:
        rec = validate_record(record)
    except Exception:  # noqa: BLE001 - validate_record raises only ValueError; belt and braces
        return ChannelView(UNKNOWN, R_RECORD_INVALID)
    ops = rec["operands"]
    current = {"deployed_head": deployed_head, "target_head": target_head,
               "installer_series": installer_series}
    if any(not value or ops.get(key) != value for key, value in current.items()):
        return ChannelView(UNKNOWN, R_OPERANDS, observed_utc=rec["observed_utc"], channel=rec["channel"])
    moment = now or datetime.now(timezone.utc)
    observed = _parse_utc(rec["observed_utc"])
    if observed - moment > CLOCK_SKEW:
        return ChannelView(UNKNOWN, R_FUTURE, observed_utc=rec["observed_utc"], channel=rec["channel"])
    if moment - observed > min(FRESHNESS, CEILING):
        return ChannelView(UNKNOWN, R_STALE, observed_utc=rec["observed_utc"], channel=rec["channel"])
    return ChannelView(rec["state"], rec["reason"], advances=rec["advances"],
                       reaches_target=rec["reaches_target"], observed_utc=rec["observed_utc"],
                       channel=rec["channel"], record=rec)


def read_record(state_dir: Path | str) -> Optional[dict]:
    """The raw record, or None when absent. Authority is the CALLER's check (`assert_outcome_authority`)."""
    path = record_path(state_dir)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {"unreadable": True}
