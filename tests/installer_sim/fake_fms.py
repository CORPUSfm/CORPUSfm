"""Fake FMS substrate for installer decision-path tests (packet 022).

Two modest fakes — NOT a FileMaker Server emulator:

- `make_fake_fmsadmin(dir, scenario)` writes a fake `fmsadmin` executable that scripts the outcomes the
  installer/uninstaller actually depend on (`list files`, credential accept/reject, `-y close <db>`),
  recording every argv line to `$FAKE_FMSADMIN_LOG` so a test can assert which DBs were touched.
- `FakeFmsHttp` is a requests-level fake for the FMS Admin API / OData. Install it with
  `fake.install(monkeypatch, "corpusfm.server.fms_admin_pki")` (patches that module's `requests`); it
  routes (method, path) to scripted (status, json) so PKI auth/register/deregister and OData-reachability
  decisions run without a live box.

Scenarios are explicit and file/dict-backed; response bodies are minimal but realistic.
"""
from __future__ import annotations

import json as _json
from pathlib import Path

from tests.installer_sim.harness import make_fake_bin


# ── fake fmsadmin ─────────────────────────────────────────────────────────────────

def make_fake_fmsadmin(d: Path, *, hosted=("CORPUSfm_DB.fmp12",), good_pass="admin",
                       close_ok=True, close_out=None, list_rc=0) -> Path:
    """Write a fake `fmsadmin` into `d`. `hosted` = the DB filenames `list files` reports; auth is
    accepted only for `-p <good_pass>` (else exit 9 "Permission denied", like the real tool); every
    invocation appends its args to $FAKE_FMSADMIN_LOG.

    `close_out` overrides what `close` prints — packet 1237 measured a SUCCESSFUL close emitting
    "File Closing: CORPUSfm_DB.fmp12", which matches none of the success patterns the old code
    grepped for, so the text and the exit status must be settable independently to test that the
    verdict comes from the status. `list_rc` makes `list files` fail while credentials are accepted
    (an FMS that went away mid-run), which is otherwise only reachable via a bad password.
    """
    listing = "\\n".join("filewin:/C:/.../Databases/" + h for h in hosted)
    if close_out is not None:
        close_body = "echo '%s'; %s" % (close_out, "exit 0" if close_ok else "exit 1")
    elif close_ok:
        close_body = "echo 'File Closed.'"
    else:
        close_body = "echo 'Error 10502: host unreachable' >&2; exit 1"
    body = f'''
echo "fmsadmin $*" >> "$FAKE_FMSADMIN_LOG"
# parse "-p <pass>" out of the args (auth gate)
pass=""
prev=""
for a in "$@"; do [ "$prev" = "-p" ] && pass="$a"; prev="$a"; done
if [ "$pass" != "{good_pass}" ]; then
  echo "fmsadmin: Permission denied." >&2
  exit 9
fi
case "$*" in
  *"list files"*) printf '{listing}\\n'; exit {list_rc} ;;
  *close*) {close_body} ;;
  *) : ;;
esac
exit 0
'''
    make_fake_bin(d, {"fmsadmin": body})
    return d / "fmsadmin"


# ── fake FMS Admin API / OData (requests-level) ───────────────────────────────────

class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    @property
    def text(self):
        return _json.dumps(self._payload) if not isinstance(self._payload, Exception) else ""


class FakeFmsHttp:
    """Scripted FMS HTTP. `routes` maps a path-substring to (status, json-body). `record` collects the
    (method, url) calls. `verify_seen` records the `verify=` kwarg of each call (to assert loopback
    verify_ssl=False is what reaches the wire)."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.record: list[tuple[str, str]] = []
        self.verify_seen: list = []

    def _handle(self, method, url, **kw):
        self.record.append((method, url))
        self.verify_seen.append(kw.get("verify"))
        for frag, (status, payload) in self.routes.items():
            if frag in url:
                return _Resp(status, payload)
        return _Resp(404, {"messages": [{"code": "404", "text": "no route"}]})

    def install(self, monkeypatch, module_path: str):
        import importlib
        mod = importlib.import_module(module_path)
        # fms_admin_pki does `import requests` inside functions → patch the real requests module
        import requests
        for verb in ("get", "post", "put", "delete", "patch"):
            monkeypatch.setattr(requests, verb,
                                lambda url, _v=verb, **kw: self._handle(_v.upper(), url, **kw))
        return self


def auth_ok_routes(token="sess-tok-123") -> dict:
    """A scenario where Admin-API PKI auth + the key endpoints succeed."""
    return {
        "/fmi/admin/api/v2/user/auth": (200, {"response": {"token": token}, "messages": [{"code": "0"}]}),
        "/fmi/admin/api/v2/server/config/pkipublickey": (200, {"response": {}, "messages": [{"code": "0"}]}),
    }


def auth_rejected_routes() -> dict:
    return {"/fmi/admin/api/v2/user/auth": (401, {"messages": [{"code": "212", "text": "bad credentials"}]})}
