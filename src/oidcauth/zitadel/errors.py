"""Errors of the Zitadel API client and of IDPLogin.finish."""

from __future__ import annotations


class ZitadelError(Exception):
    """Base class of the errors of this package."""


class APIError(ZitadelError):
    """An error response of the API."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        # Zitadel's message, e.g.
        # "Errors.User.ProjectRequired (OIDC-foSyH49RvL)".
        self.message = message
        super().__init__(f"zitadel: {status} {message}")


def has_message(err: BaseException | None, key: str) -> bool:
    """Tells whether err (or its cause) is an API error whose message contains
    key, e.g. "Errors.User.NotAllowedOrg"."""
    while err is not None:
        if isinstance(err, APIError) and key in err.message:
            return True
        err = err.__cause__
    return False


class LoginError(ZitadelError):
    """A refusal of IDPLogin.finish; ``detail`` says why."""

    reason = "zitadel: login refused"

    def __init__(self, detail: str = "") -> None:
        self.detail = detail
        super().__init__(f"{self.reason}: {detail}" if detail else self.reason)


class NotLinkedError(LoginError):
    """The external account is linked to no Zitadel user, and the identity
    provider neither auto-links nor auto-creates one."""

    reason = "zitadel: external account is not linked to a user"


class NotAllowedError(LoginError):
    """The user is outside the organization the app requires, or that
    organization does not allow this identity provider."""

    reason = "zitadel: user is not allowed to log in with this identity provider"


class AccessDeniedError(LoginError):
    """The user has no grant for the application's project."""

    reason = "zitadel: user has no access to the application"


class UserInactiveError(LoginError):
    """The Zitadel user is deactivated or locked."""

    reason = "zitadel: user is not active"


class MFARequiredError(LoginError):
    """The user's organization requires a second factor for external logins,
    which this login cannot ask for."""

    reason = "zitadel: organization requires multi-factor authentication"


class AuthRequestExpiredError(LoginError):
    """The OIDC auth request is unknown, expired or already completed."""

    reason = "zitadel: auth request expired or already handled"


class IntentFailedError(LoginError):
    """The login at the identity provider was cancelled or failed (Zitadel
    returned to the failure URL)."""

    reason = "zitadel: login at the identity provider failed"


def is_user_error(err: BaseException | None) -> bool:
    """Tells whether err is a refusal or a failure on the user's side (a
    LoginError, or a Zitadel API error 4xx such as an expired intent) rather
    than Zitadel being unreachable, misconfigured or failing."""
    if isinstance(err, LoginError):
        return True
    return isinstance(err, APIError) and 400 <= err.status < 500
