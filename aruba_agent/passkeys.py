"""
WebAuthn / passkey support for dashboard login.

Why this module exists
----------------------
TOTP 2FA (T3.3) puts a second factor in front of password auth, but
it's still password-and-something. WebAuthn / passkeys offers a
passwordless second-factor flow: the user enrols an authenticator
(Touch ID, Windows Hello, YubiKey, phone passkey synced through
iCloud / Google), and on subsequent logins they tap-to-authenticate.
No password typing, no phishing surface.

This module is a thin shell around the `webauthn` PyPI package. It
exposes four functions the web layer calls:

    registration_options(username, existing_credential_ids)
        Build the JSON the browser passes to `navigator.credentials.create`.

    verify_registration(response_json, expected_challenge, rp_id, origin)
        Verify the attestation, return a dict we can persist.

    authentication_options(allow_credential_ids)
        Build the JSON for `navigator.credentials.get`. Empty
        allow_credential_ids = passwordless ("any registered key").

    verify_authentication(response_json, expected_challenge,
                          stored_passkey, rp_id, origin)
        Verify the assertion, return the new sign_count.

Storage of the per-user passkey list happens in local_auth.py — this
module never touches users.json. Challenge ephemera (the random bytes
the browser must echo back signed) lives in the Flask session for the
brief window between begin / complete.

Threading
---------
Pure functions; no state. Safe to call from any worker thread.
"""

from __future__ import annotations

import base64
import logging
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


log = logging.getLogger(__name__)


# ─── helpers ────────────────────────────────────────────────────────────────

def _b64u_encode(b: bytes) -> str:
    """base64url without padding — the WebAuthn wire format."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _new_challenge() -> bytes:
    """32 random bytes is what the spec recommends."""
    return secrets.token_bytes(32)


# ─── registration ───────────────────────────────────────────────────────────

def registration_options(
    username:               str,
    existing_credential_ids: List[str],
    rp_id:                  str,
    rp_name:                str = "Aruba Network Agent",
) -> Tuple[Dict[str, Any], bytes]:
    """
    Return (options_for_browser_dict, challenge_bytes).

    The caller stashes the challenge in the Flask session and serves
    the dict as JSON to ``navigator.credentials.create({ publicKey: ... })``.

    ``existing_credential_ids`` blocks re-enrolling a key the user
    already has (the browser refuses to create a duplicate).
    """
    try:
        from webauthn import generate_registration_options
        from webauthn.helpers.cose import COSEAlgorithmIdentifier
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria,
            ResidentKeyRequirement,
            UserVerificationRequirement,
            PublicKeyCredentialDescriptor,
        )
    except ImportError as exc:
        raise RuntimeError(
            f"webauthn library not installed ({exc}). "
            "Run: pip install webauthn"
        ) from exc

    challenge = _new_challenge()
    exclude = [
        PublicKeyCredentialDescriptor(id=_b64u_decode(cid))
        for cid in existing_credential_ids if cid
    ]
    options = generate_registration_options(
        rp_id              = rp_id,
        rp_name            = rp_name,
        user_id            = username.encode("utf-8"),
        user_name          = username,
        user_display_name  = username,
        challenge          = challenge,
        # Both passkey-class (resident, multi-device) and traditional
        # security-key authenticators are accepted. ResidentKey is
        # PREFERRED rather than REQUIRED so a YubiKey 4 without
        # resident-key support can still enrol.
        authenticator_selection = AuthenticatorSelectionCriteria(
            resident_key      = ResidentKeyRequirement.PREFERRED,
            user_verification = UserVerificationRequirement.PREFERRED,
        ),
        # Same algorithms the WebAuthn working group recommends as the
        # baseline. ES256 covers every modern authenticator; RS256
        # covers older Windows Hello on TPM 1.2.
        supported_pub_key_algs = [
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        exclude_credentials = exclude,
    )

    # webauthn>=2 returns a PublicKeyCredentialCreationOptions; we want
    # the JSON-serialisable dict the browser actually consumes. The
    # library provides options_to_json() but it returns a string —
    # rehydrate via json.loads so the Flask jsonify() works cleanly.
    import json
    from webauthn.helpers import options_to_json
    return json.loads(options_to_json(options)), challenge


def verify_registration(
    response_json:    Dict[str, Any],
    expected_challenge: bytes,
    rp_id:            str,
    origin:           str,
) -> Dict[str, Any]:
    """
    Verify the browser's response to ``navigator.credentials.create``.
    Returns a dict suitable for persisting via LocalAuthStore.add_passkey:

        {
          "credential_id": "<b64u>",
          "public_key":    "<b64u COSE>",
          "sign_count":    int,
          "name":          "",          # caller fills this in
          "created":       "ISO ts",
          "last_used":     None,
        }

    Raises ValueError on verification failure with a message safe to
    surface to the operator.
    """
    try:
        from webauthn import verify_registration_response
    except ImportError as exc:
        raise RuntimeError(f"webauthn not installed: {exc}") from exc

    try:
        verification = verify_registration_response(
            credential          = response_json,
            expected_challenge  = expected_challenge,
            expected_rp_id      = rp_id,
            expected_origin     = origin,
            require_user_verification = False,
        )
    except Exception as exc:
        raise ValueError(f"Passkey enrolment failed verification: {exc}") from exc

    return {
        "credential_id": _b64u_encode(verification.credential_id),
        "public_key":    _b64u_encode(verification.credential_public_key),
        "sign_count":    verification.sign_count,
        "name":          "",
        "created":       datetime.now().isoformat(timespec="seconds"),
        "last_used":     None,
    }


# ─── authentication ─────────────────────────────────────────────────────────

def authentication_options(
    allow_credential_ids: Optional[List[str]],
    rp_id:                str,
) -> Tuple[Dict[str, Any], bytes]:
    """
    Build the options the browser passes to
    ``navigator.credentials.get({ publicKey: ... })``.

    When ``allow_credential_ids`` is None (or empty), the browser shows
    every discoverable credential it can find — that's the passwordless
    flow ("just tap"). When the list is populated, the browser is
    constrained to those specific credentials, which is what we use
    when the user typed a username first.
    """
    try:
        from webauthn import generate_authentication_options
        from webauthn.helpers.structs import (
            PublicKeyCredentialDescriptor, UserVerificationRequirement,
        )
    except ImportError as exc:
        raise RuntimeError(f"webauthn not installed: {exc}") from exc

    challenge = _new_challenge()
    allow = []
    if allow_credential_ids:
        allow = [
            PublicKeyCredentialDescriptor(id=_b64u_decode(cid))
            for cid in allow_credential_ids if cid
        ]
    options = generate_authentication_options(
        rp_id                = rp_id,
        challenge            = challenge,
        allow_credentials    = allow,
        user_verification    = UserVerificationRequirement.PREFERRED,
    )

    import json
    from webauthn.helpers import options_to_json
    return json.loads(options_to_json(options)), challenge


def verify_authentication(
    response_json:      Dict[str, Any],
    expected_challenge: bytes,
    stored_passkey:     Dict[str, Any],
    rp_id:              str,
    origin:             str,
) -> int:
    """
    Verify the assertion. Returns the new sign_count the caller must
    persist via ``LocalAuthStore.update_passkey_after_use``.

    Raises ValueError on any verification failure (wrong origin,
    bad signature, cloned authenticator detected).
    """
    try:
        from webauthn import verify_authentication_response
    except ImportError as exc:
        raise RuntimeError(f"webauthn not installed: {exc}") from exc

    try:
        verification = verify_authentication_response(
            credential                  = response_json,
            expected_challenge          = expected_challenge,
            expected_rp_id              = rp_id,
            expected_origin             = origin,
            credential_public_key       = _b64u_decode(stored_passkey["public_key"]),
            credential_current_sign_count = int(stored_passkey.get("sign_count", 0)),
            require_user_verification   = False,
        )
    except Exception as exc:
        raise ValueError(f"Passkey verification failed: {exc}") from exc

    # WebAuthn's sign_count contract: the new value MUST strictly
    # increase over what we stored, unless both are 0 (some
    # authenticators don't implement a counter). If it doesn't, we
    # might be looking at a cloned credential — the spec says reject.
    new_count = verification.new_sign_count
    old_count = int(stored_passkey.get("sign_count", 0))
    if new_count == 0 and old_count == 0:
        # Counter disabled on both sides — accept, can't do better.
        pass
    elif new_count <= old_count:
        raise ValueError(
            "Passkey sign-count did not increase — possible cloned "
            f"authenticator (stored={old_count}, presented={new_count})."
        )
    return new_count


# ─── re-exports ─────────────────────────────────────────────────────────────

__all__ = (
    "registration_options",
    "verify_registration",
    "authentication_options",
    "verify_authentication",
)
