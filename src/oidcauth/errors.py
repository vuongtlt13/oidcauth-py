"""Errors of the relying party."""

from __future__ import annotations

import httpx


class OIDCAuthError(Exception):
    """Base class of every error the library raises."""


class InvalidStateError(OIDCAuthError):
    """The login state (flow cookie) is missing, forged, foreign or expired."""

    def __init__(self, detail: str = "") -> None:
        msg = "oidcauth: invalid or expired login state"
        super().__init__(f"{msg}: {detail}" if detail else msg)


class MissingCodeError(OIDCAuthError):
    """The authorization response carries no code."""

    def __init__(self) -> None:
        super().__init__("oidcauth: authorization code missing")


class NotSupportedError(OIDCAuthError):
    """The provider does not advertise the endpoint a call needs."""

    def __init__(self, detail: str = "") -> None:
        msg = "oidcauth: not supported by the provider"
        super().__init__(f"{msg}: {detail}" if detail else msg)


class ProviderError(OIDCAuthError):
    """The provider answered the authorization request with an error, e.g.
    access_denied when the user cancelled."""

    def __init__(self, code: str, description: str = "") -> None:
        self.code = code
        self.description = description
        msg = f"oidcauth: provider error: {code}"
        super().__init__(f"{msg}: {description}" if description else msg)


class TokenError(OIDCAuthError):
    """A token request was refused or a token failed verification (bad
    signature, audience, nonce, expired, replayed code, ...)."""

    def __init__(self, op: str, cause: object) -> None:
        self.op = op
        self.cause = cause
        super().__init__(f"oidcauth: {op} failed: {cause}")


class ProviderUnreachableError(OIDCAuthError):
    """The provider could not be reached (network error, timeout)."""

    def __init__(self, op: str, cause: object) -> None:
        self.op = op
        self.cause = cause
        super().__init__(f"oidcauth: {op}: provider unreachable: {cause}")


class DiscoveryError(OIDCAuthError):
    """The discovery document or the JWKS could not be loaded."""

    def __init__(self, cause: object) -> None:
        self.cause = cause
        super().__init__(f"oidcauth: provider discovery failed: {cause}")


class UserInfoError(OIDCAuthError):
    """The userinfo request of a login failed."""

    def __init__(self, cause: object) -> None:
        self.cause = cause
        super().__init__(f"oidcauth: userinfo failed: {cause}")


class InvalidLogoutTokenError(OIDCAuthError):
    """A back-channel logout token failed verification."""

    def __init__(self, reason: str = "") -> None:
        self.reason = reason
        msg = "oidcauth: invalid logout token"
        super().__init__(f"{msg}: {reason}" if reason else msg)


class TicketNotFoundError(OIDCAuthError):
    """The ticket is unknown, expired or already taken."""

    def __init__(self) -> None:
        super().__init__("oidcauth: ticket not found or expired")


class ConfigError(OIDCAuthError, ValueError):
    """The configuration is invalid; ``errors`` lists every problem."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("oidcauth: " + "; ".join(errors))


def classify(op: str, err: BaseException) -> OIDCAuthError:
    """Wraps an error of a request to the provider: a transport error means the
    provider is unreachable, anything else is a refused or invalid token."""
    if isinstance(err, OIDCAuthError):
        return err
    if isinstance(err, httpx.TransportError):
        return ProviderUnreachableError(op, err)
    return TokenError(op, err)


def is_user_error(err: BaseException | None) -> bool:
    """Tells whether err is a failure on the user's side (an invalid or replayed
    login, a cancelled login, a refused token) rather than the provider being
    unreachable or misconfigured. Handlers answer the former with 401 and the
    latter with 502."""
    return isinstance(
        err, (InvalidStateError, MissingCodeError, ProviderError, TokenError)
    )
