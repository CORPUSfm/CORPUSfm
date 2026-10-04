"""ROOT-ONLY: observe the installer channel and publish an eligibility record (packet 1399, Route C).

Run by the fixed privileged updater, from the administrator-owned library, after it has fetched and
validated both heads and before it classifies the update:

    python -I -c "$BOOT" <install>/lib <state_dir> <checkout> <git> <install_dir> <deployed_head> <target_head>

where `$BOOT` is `BOOT` below, byte for byte. **`PYTHONPATH` is not the mechanism**: the Windows
embeddable interpreter's `._pth` ignores it and places the deployed checkout on `sys.path`. The boot
line puts the protected library first itself, and `entry()` refuses to run unless every loaded
`corpusfm` module came from that library.

**This is the only module that touches the channel or its credential, and no service module may
import it** (`tests/test_installer_channel.py` enforces that). The credential is read from the
root-protected `<install>/.git-pat` into this process and sent to the channel host only. It never
reaches the record, the log or the service.

It downloads no package and verifies no archive: it reads the channel pointer and `release.json`
and decides with git on the already-fetched object store. **It never fails the update that runs
it.** Any error becomes an `unknown` record with a reason code. Only the process exit status reports
a failure to write.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from . import installer_channel as ic

#: The channel repository. Private: the installer repository, read with the installation's PAT.
#: The public projection rewrites this block to the public repository and its anonymous Latest
#: release (`tools/public_projection/profile.json`).
CHANNEL_REPOSITORY = "CORPUSfm/CORPUSfm"
CHANNEL_CREDENTIALED = False

#: The launch line both privileged updaters carry verbatim (tests compare them with this constant).
BOOT = ("import sys; sys.path.insert(0, sys.argv[1]); "
        "from corpusfm.lifecycle.installer_channel_observer import entry; "
        "raise SystemExit(entry(sys.argv[1], sys.argv[2:]))")

API = "https://api.github.com"
TIMEOUT_S = 15
#: The whole observation, network and git together, must finish well inside the updater's 300 s
#: outcome window, because it runs on the apply path too.
BUDGET_S = 90
GIT_TIMEOUT_S = 20
MAX_BYTES = 1 << 20
_PAT = re.compile(r"^(?:github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{20,})$")
_POINTER_MANIFEST = re.compile(r"^releases/0\.[0-9]+/release\.json$")
_PRIVATE_TAG = re.compile(r"^installer-series-[1-9][0-9]*-0\.[0-9]+$")
_PUBLIC_TAG = re.compile(r"^v0\.[0-9]+$")


class ChannelUnreadable(Exception):
    """The channel could not be read. Never carries response or credential text."""


class ObservationFailed(Exception):
    """The observation could not finish (budget exhausted, git timed out or could not run)."""


_DEADLINE: Optional[float] = None


def _remaining(cap: float) -> float:
    """The time a single call may take: its own cap, never past the observation's deadline."""
    import time

    if _DEADLINE is None:
        return cap
    left = _DEADLINE - time.monotonic()
    if left <= 0:
        raise ObservationFailed("budget exhausted")
    return min(cap, left)


class _StripAuthOnHostChange(urllib.request.HTTPRedirectHandler):
    """A release asset redirects to a presigned storage URL, which must not receive the PAT."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).hostname != urllib.parse.urlsplit(req.full_url).hostname:
            for name in list(new.headers):
                if name.lower() == "authorization":
                    del new.headers[name]
            new.unredirected_hdrs.pop("Authorization", None)
        return new


def _ssl_context():
    import ssl

    try:  # the Linux interpreter is python-build-standalone; certifi is in the venv beside it
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _get(url: str, *, token: str = "", accept: str = "application/vnd.github+json") -> bytes:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ChannelUnreadable("non-HTTPS channel URL")
    headers = {"Accept": accept, "User-Agent": "corpusfm-installer-channel-observer"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    opener = urllib.request.build_opener(_StripAuthOnHostChange(),
                                         urllib.request.HTTPSHandler(context=_ssl_context()))
    return _open_and_read(opener, urllib.request.Request(url, headers=headers))


def _open_and_read(opener, request) -> bytes:
    """Read in chunks, checking the observation deadline between them. A socket timeout bounds ONE
    wait, not the whole read: a server dripping a byte at a time never trips it."""
    chunks: list[bytes] = []
    total = 0
    try:
        with opener.open(request, timeout=_remaining(TIMEOUT_S)) as response:
            while True:
                _remaining(TIMEOUT_S)
                chunk = response.read1(8192) if hasattr(response, "read1") else response.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BYTES:
                    raise ChannelUnreadable("oversized response")
                chunks.append(chunk)
    except (ObservationFailed, ChannelUnreadable):
        raise
    except Exception as exc:  # noqa: BLE001 - the reason code is the whole signal
        raise ChannelUnreadable(type(exc).__name__) from None
    return b"".join(chunks)


def _json(data: bytes) -> dict:
    try:
        value = json.loads(data.decode("utf-8"))
    except Exception:
        raise ValueError("not JSON") from None
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    return value


def _read_token(install_dir: Path) -> str:
    try:
        token = (install_dir / ".git-pat").read_text(encoding="ascii").strip()
    except OSError:
        raise ChannelUnreadable("no channel credential") from None
    if not _PAT.match(token):
        raise ChannelUnreadable("channel credential is malformed")
    return token


def _unique_asset(release: dict, name: str, key: str) -> str:
    hits = [a.get(key, "") for a in release.get("assets", []) if isinstance(a, dict) and a.get("name") == name]
    if len(hits) != 1 or not isinstance(hits[0], str) or not hits[0].startswith("https://"):
        raise ValueError(f"release has no unique {name}")
    return hits[0]


def read_channel(series: str, install_dir: Path, *, get: Callable[..., bytes] = _get) -> tuple[dict, str]:
    """`(channel facts, pointer sha256)` from the configured channel. Raises ChannelUnreadable/ValueError."""
    if CHANNEL_CREDENTIALED:
        token = _read_token(install_dir)
        pointer_bytes = get(f"{API}/repos/{CHANNEL_REPOSITORY}/contents/channel/{series}/latest.json?ref=main",
                            token=token, accept="application/vnd.github.raw+json")
        pointer = _json(pointer_bytes)
        tag = str(pointer.get("release_tag", ""))
        if (pointer.get("schema_version") != 1 or pointer.get("installer_series") != series
                or not _POINTER_MANIFEST.match(str(pointer.get("release_manifest", "")))
                or not _PRIVATE_TAG.match(tag)):
            raise ValueError("latest.json is invalid for this series")
        release_meta = _json(get(f"{API}/repos/{CHANNEL_REPOSITORY}/releases/tags/{tag}", token=token))
        release_bytes = get(_unique_asset(release_meta, "release.json", "url"), token=token,
                            accept="application/octet-stream")
        facts = ic.channel_facts(_json(release_bytes), release_tag=tag)
        if pointer.get("commit") != facts["commit"]:
            raise ValueError("latest.json and release.json disagree on the commit")
        return facts, hashlib.sha256(pointer_bytes).hexdigest()
    release_meta = _json(get(f"{API}/repos/{CHANNEL_REPOSITORY}/releases/latest"))
    tag = str(release_meta.get("tag_name", ""))
    if not _PUBLIC_TAG.match(tag):
        raise ValueError("the Latest release has no valid tag")
    release_bytes = get(_unique_asset(release_meta, "release.json", "browser_download_url"),
                        accept="application/octet-stream")
    facts = ic.channel_facts(_json(release_bytes), release_tag=tag)
    pointer = json.dumps({"release_tag": tag, "release_json_sha256": hashlib.sha256(release_bytes).hexdigest()},
                         sort_keys=True).encode("utf-8")
    return facts, hashlib.sha256(pointer).hexdigest()


def _git(git: str, checkout: Path, *args: str) -> subprocess.CompletedProcess:
    """A git call that cannot outlive the budget. A timeout or a git that will not start is a
    FAILED observation, never a verdict about ancestry."""
    try:
        child = subprocess.Popen([git, "-C", str(checkout), "-c", "safe.directory=*", *args],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        raise ObservationFailed(type(exc).__name__) from None
    _CHILDREN.add(child)
    try:
        out, err = child.communicate(timeout=_remaining(GIT_TIMEOUT_S))
    except (subprocess.TimeoutExpired, ObservationFailed) as exc:
        child.kill()
        child.communicate()
        raise ObservationFailed(type(exc).__name__) from None
    finally:
        _CHILDREN.discard(child)
    return subprocess.CompletedProcess(child.args, child.returncode, out, err)


_CHILDREN: set = set()


def _stop_children() -> None:
    for child in list(_CHILDREN):
        try:
            child.kill()
        except Exception:  # noqa: BLE001 - already gone
            pass


def git_predicates(git: str, checkout: Path):
    def is_ancestor(a: str, b: str) -> Optional[bool]:
        for commit in (a, b):
            if _git(git, checkout, "cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
                return None
        rc = _git(git, checkout, "merge-base", "--is-ancestor", a, b).returncode
        return True if rc == 0 else False if rc == 1 else None

    def residual_requires_installer(p: str, t: str) -> Optional[bool]:
        from .update_boundary import classify

        diff = _git(git, checkout, "diff", "--name-only", f"{p}..{t}")
        if diff.returncode != 0:
            return None
        paths = [line.strip() for line in diff.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
        return classify(paths).requires_installer

    return is_ancestor, residual_requires_installer


def observe(state_dir: Path, checkout: Path, git: str, install_dir: Path, deployed_head: str,
            target_head: str, *, series: Optional[str] = None, get: Callable[..., bytes] = _get,
            predicates=None) -> Optional[dict]:
    """Decide and write. Returns the record written, or None when no record could be bound."""
    import time

    global _DEADLINE
    _DEADLINE = time.monotonic() + BUDGET_S
    if series is None:
        try:
            from .published import read_published_installation

            series = read_published_installation().installer_series
        except Exception:  # noqa: BLE001 - an unreadable installation binds no operands
            series = None
    operands = {"deployed_head": deployed_head, "target_head": target_head,
                "installer_series": series or "", "channel_pointer_sha256": ""}
    try:
        ic.validate_record(ic.unknown_record(ic.R_NOT_OBSERVED, operands=operands))
    except ValueError:
        # No record can be bound to these operands. Remove any earlier one rather than leave a
        # confident answer about an installation this run could not identify.
        ic.record_path(state_dir).unlink(missing_ok=True)
        return None
    deadline = _DEADLINE
    outcome: dict = {}

    def work() -> None:
        # Decides only. It never writes: the record is published by the thread that holds the
        # deadline, so a result reached after expiry can never be published.
        outcome["record"] = _decide_from_channel(series, install_dir, git, checkout, operands, get, predicates)

    import threading

    worker = threading.Thread(target=work, name="installer-channel-observation", daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()))
    record = outcome.get("record")
    if worker.is_alive() or record is None or time.monotonic() > deadline:
        # The deadline is the whole observation's, network and git together. Whatever the worker
        # is still waiting on is abandoned (it is a daemon thread; its git children are killed).
        _stop_children()
        record = ic.unknown_record(ic.R_OBSERVER_FAILED, operands=dict(operands, channel_pointer_sha256=""))
    ic.write_record(state_dir, record)
    return record


def _decide_from_channel(series, install_dir, git, checkout, operands, get, predicates) -> dict:
    operands = dict(operands)
    try:
        facts, pointer_sha = read_channel(series, install_dir, get=get)
    except ChannelUnreadable:
        return ic.unknown_record(ic.R_UNREADABLE, operands=operands)
    except ValueError:
        return ic.unknown_record(ic.R_INVALID, operands=operands)
    except ObservationFailed:
        return ic.unknown_record(ic.R_OBSERVER_FAILED, operands=operands)
    operands["channel_pointer_sha256"] = pointer_sha
    try:
        is_ancestor, residual = predicates or git_predicates(git, checkout)
        return ic.decide(facts, operands=operands, is_ancestor=is_ancestor,
                         residual_requires_installer=residual)
    except Exception:  # noqa: BLE001 - any failure replaces the old answer with `unknown`
        return ic.unknown_record(ic.R_OBSERVER_FAILED, operands=operands, channel=facts)


def _invalidate(state_dir: Path) -> None:
    """Remove the previous answer. Used whenever this run cannot leave a current one."""
    try:
        ic.record_path(state_dir).unlink(missing_ok=True)
    except Exception:  # noqa: BLE001 - the updater's own fallback removes it too
        pass


def loaded_from(library: Path) -> bool:
    """Every loaded `corpusfm` module, and the package path itself, resolves under `library`."""
    root = library.resolve()

    def inside(value) -> bool:
        try:
            Path(value).resolve().relative_to(root)
            return True
        except (TypeError, ValueError, OSError):
            return False

    package = sys.modules.get("corpusfm")
    if package is None or not list(getattr(package, "__path__", [])):
        return False
    if not all(inside(entry) for entry in package.__path__):
        return False
    for name, module in list(sys.modules.items()):
        if name == "corpusfm" or name.startswith("corpusfm."):
            origin = getattr(module, "__file__", None)
            if origin is None or not inside(origin):
                return False
    return True


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        return 2
    state_dir, checkout, git, install_dir, deployed, target = argv
    commit = re.compile(r"^[0-9a-f]{40,64}$")
    if not commit.match(deployed) or not commit.match(target):
        _invalidate(Path(state_dir))
        return 2
    try:
        observe(Path(state_dir), Path(checkout), git, Path(install_dir), deployed, target)
    except Exception:  # noqa: BLE001 - the updater logs a fixed sentence; nothing else is emitted
        _invalidate(Path(state_dir))
        return 1
    return 0


def entry(library: str, argv: list[str]) -> int:
    """The updaters' entry. Refuses (exit 3) unless this code and everything it imported came from
    the installation's own protected library, and removes the previous answer when it refuses."""
    if len(argv) != 6:
        return main(argv)
    expected = Path(argv[3]) / "lib"
    try:
        same_library = Path(library).resolve() == expected.resolve()
    except OSError:
        same_library = False
    if not same_library or not loaded_from(expected):
        _invalidate(Path(argv[0]))
        return 3
    return main(argv)
