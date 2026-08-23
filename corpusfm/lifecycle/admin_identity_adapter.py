"""The live Admin-API adapter the CLI hands to the identity operations (packet 1246-07).

**It exposes exactly the ADDITIVE primitives and nothing else.** `register_public_key` and
`delete_public_key` — the delete-then-post shapes — are deliberately absent from this surface, so the
component cannot reach them even by accident, and a reader can see that from the class body.

**TWO AUTHORITIES, TWO METHOD PAIRS, NEVER ONE PAIR WITH A BLANK PASSWORD.** An administrator
credential authenticates Basic; the installed identity authenticates by PKI. An earlier version had
one pair and a lease-shaped `_SelfAuthority` whose `password` was `""` — which the adapter did not
recognise, so an EMPTY PASSWORD was offered to FileMaker Server as if it were a credential. The
authority type now selects the method, so there is no value a caller can pass that reaches Basic auth
without a real password.

Separated from `admin_identity_ops` because the operations must remain testable with an injected
double and no network; this is the one place a real HTTPS call is composed.
"""

from __future__ import annotations

from .admin_identity_store import REGISTRATION_NAME


class LiveAdminApi:
    """Four calls, one registration name, no credential ever placed in a child process's argv."""

    def __init__(self, *, verify_ssl: bool = False):
        # Loopback against FMS's own certificate cannot cert-verify (its SAN/CN is the hostname),
        # which `fms_admin_pki` documents at module level. This is the existing, accepted posture.
        self._verify = verify_ssl

    def get_public_keys(self, host, user, password):
        from corpusfm.server import fms_admin_pki as pki

        return pki.get_public_keys(host, user, password, verify_ssl=self._verify)

    def add_public_key(self, host, user, password, name, public_pem):
        from corpusfm.server import fms_admin_pki as pki

        return pki.add_public_key(host, user, password, name, public_pem,
                                  verify_ssl=self._verify)

    def update_public_key(self, host, user, password, name, public_pem):
        from corpusfm.server import fms_admin_pki as pki

        return pki.update_public_key(host, user, password, name, public_pem,
                                     verify_ssl=self._verify)

    def delete_public_key_exact(self, host, user, password, name):
        from corpusfm.server import fms_admin_pki as pki

        return pki.delete_public_key_exact(host, user, password, name, verify_ssl=self._verify)

    # ── the installed identity's own authority: PKI, never Basic ─────────────

    def get_public_keys_as_identity(self, host, registration_name, private_pem):
        from corpusfm.server import fms_admin_pki as pki

        return pki.get_public_keys_pki(host, registration_name, private_pem,
                                       verify_ssl=self._verify)

    def delete_public_key_exact_as_identity(self, host, registration_name, private_pem, name):
        from corpusfm.server import fms_admin_pki as pki

        return pki.delete_public_key_exact_pki(host, registration_name, private_pem, name,
                                               verify_ssl=self._verify)

    def authenticate(self, host, name, private_pem) -> bool | None:
        """``True`` accepted · ``False`` explicitly refused · ``None`` inconclusive.

        The three-way return is the whole point: a timeout and a refusal are different facts, and
        collapsing them would let a network failure be reported as a broken relationship.
        """
        import requests

        from corpusfm.server import fms_admin_pki as pki

        try:
            token = pki.authenticate(host, name or REGISTRATION_NAME, private_pem,
                                     verify_ssl=self._verify)
        except requests.RequestException:
            return None                       # transport: proves nothing about the relationship
        except RuntimeError:
            return False                      # FMS answered and refused the credential
        pki.logout(host, token, verify_ssl=self._verify)
        return True


def reachability_probe(host: str) -> bool:
    """One read-only, UNAUTHENTICATED probe. Carries no credential and opens no Admin-API session.

    It asks only whether the server answered. Any HTTP status is an answer — a 401 from an endpoint
    that requires auth proves the server is up, which is the only question this axis asks.
    """
    import requests

    from corpusfm.server.fms_admin_pki import _clean_host

    try:
        requests.get(f"https://{_clean_host(host)}/fmi/admin/api/v2/user/auth",
                     verify=False, timeout=10)
        return True
    except requests.RequestException:
        return False


__all__ = ["LiveAdminApi", "reachability_probe"]
