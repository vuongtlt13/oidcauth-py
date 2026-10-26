"""Configuration of one relying party."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx

from .errors import ConfigError
from .scopes import SCOPE_EMAIL, SCOPE_OPENID, SCOPE_PROFILE

DEFAULT_COOKIE_NAME = "oidc_flow"
DEFAULT_COOKIE_PATH = "/"
DEFAULT_FLOW_TTL = timedelta(minutes=10)
MIN_COOKIE_SECRET = 32

# Token endpoint client authentication methods (OpenID Connect Core 1.0,
# section 9). Config.token_endpoint_auth_method selects one.
#
# AUTH_METHOD_AUTO picks client_secret_basic, falling back to
# client_secret_post, for a client with a secret; private_key_jwt for a client
# with client_key; none for a public client.
AUTH_METHOD_AUTO = ""
AUTH_METHOD_CLIENT_SECRET_BASIC = "client_secret_basic"
AUTH_METHOD_CLIENT_SECRET_POST = "client_secret_post"
AUTH_METHOD_PRIVATE_KEY_JWT = "private_key_jwt"
AUTH_METHOD_NONE = "none"

DEFAULT_SCOPES = (SCOPE_OPENID, SCOPE_PROFILE, SCOPE_EMAIL)

RoleExtractor = Callable[[dict[str, Any]], list[str]]


@dataclass
class Config:
    """One OpenID Connect relying party (your app) registered at one OpenID
    Provider (Zitadel, Keycloak, Google, ...)."""

    # Provider issuer URL, e.g. https://id.example.com. It must match the
    # `issuer` of the discovery document exactly.
    issuer: str = ""
    # Overrides <issuer>/.well-known/openid-configuration.
    discovery_url: str = ""
    client_id: str = ""
    # For client_secret_basic / client_secret_post. Leave it and client_key
    # empty for a public client (PKCE only).
    client_secret: str = ""
    # PEM private key (RSA or EC) for private_key_jwt client authentication,
    # with client_key_id as its `kid`. For Zitadel, take `key` and `keyId` from
    # the application key JSON. Mutually exclusive with client_secret.
    client_key: bytes | str = b""
    client_key_id: str = ""
    # Forces one client authentication method. Defaults to AUTH_METHOD_AUTO.
    token_endpoint_auth_method: str = AUTH_METHOD_AUTO
    # Absolute callback URL registered at the provider.
    redirect_url: str = ""
    # Scopes requested at the authorization endpoint. Defaults to
    # DEFAULT_SCOPES. Must include "openid".
    scopes: list[str] = field(default_factory=list)

    # Sent as `acr_values` on every login. Per-request acr_values override it.
    acr_values: list[str] = field(default_factory=list)
    # Rejects a login whose ID token `acr` is not one of the requested
    # acr_values. Without it acr_values is only a hint.
    require_acr: bool = False
    # Sent as `max_age` on every login when positive: the provider must
    # re-authenticate a user whose last authentication is older, and the ID
    # token `auth_time` is then checked.
    max_age: timedelta | None = None

    # Encrypts the short-lived login flow cookie that carries state, nonce and
    # the PKCE verifier. At least 32 characters.
    cookie_secret: str = ""
    # Flow cookie prefix. Defaults to "oidc_flow".
    cookie_name: str = ""
    # Scopes the flow cookie; it must cover the callback path. Defaults to "/".
    cookie_path: str = ""
    # Drops the Secure attribute. Only for plain-HTTP local development on
    # hosts browsers do not treat as secure.
    cookie_insecure: bool = False
    # Bounds how long a user may stay at the provider login page.
    flow_ttl: timedelta | None = None

    # Disables the userinfo request after the code exchange. By default
    # userinfo claims are merged over the ID token claims, because providers
    # such as Zitadel only put profile/role claims into the ID token when
    # explicitly configured to.
    skip_userinfo: bool = False
    # Reads roles from the merged claims. Defaults to
    # identity.default_role_extractor (Zitadel project roles, then
    # `roles`/`groups`).
    role_extractor: RoleExtractor | None = None

    # Default target after RP-initiated logout.
    post_logout_redirect_url: str = ""
    # Used for discovery, JWKS, token, userinfo and revocation requests.
    # Defaults to a client with a 15 s timeout.
    http_client: httpx.AsyncClient | None = None

    def with_defaults(self) -> Config:
        from .identity import default_role_extractor

        c = dataclasses.replace(self)
        c.issuer = c.issuer.strip()
        c.client_id = c.client_id.strip()
        c.redirect_url = c.redirect_url.strip()
        c.scopes = list(c.scopes) if c.scopes else list(DEFAULT_SCOPES)
        c.acr_values = list(c.acr_values)
        c.cookie_name = c.cookie_name or DEFAULT_COOKIE_NAME
        c.cookie_path = c.cookie_path or DEFAULT_COOKIE_PATH
        if c.flow_ttl is None or c.flow_ttl <= timedelta(0):
            c.flow_ttl = DEFAULT_FLOW_TTL
        if c.role_extractor is None:
            c.role_extractor = default_role_extractor
        if isinstance(c.client_key, str):
            c.client_key = c.client_key.encode()
        return c

    def validate(self) -> None:
        """Raises ConfigError listing every configuration error, without
        contacting the provider."""
        errs: list[str] = []
        _check_url(errs, "issuer", self.issuer)
        if self.discovery_url:
            _check_url(errs, "discovery url", self.discovery_url)
        if not self.client_id:
            errs.append("client id is required")
        _check_url(errs, "redirect url", self.redirect_url)
        if len(self.cookie_secret) < MIN_COOKIE_SECRET:
            errs.append(
                f"cookie secret must be at least {MIN_COOKIE_SECRET} characters"
            )
        if self.scopes and SCOPE_OPENID not in self.scopes:
            errs.append('scopes must include "openid"')
        has_key = len(self.client_key) > 0
        if self.client_secret and has_key:
            errs.append("set either client secret or client key, not both")
        if has_key and not self.client_key_id:
            errs.append("client key id is required with client key")
        m = self.token_endpoint_auth_method
        if m == AUTH_METHOD_AUTO:
            pass
        elif m in (AUTH_METHOD_CLIENT_SECRET_BASIC, AUTH_METHOD_CLIENT_SECRET_POST):
            if not self.client_secret:
                errs.append(f"{m} requires a client secret")
        elif m == AUTH_METHOD_PRIVATE_KEY_JWT:
            if not has_key:
                errs.append("private_key_jwt requires a client key")
        elif m == AUTH_METHOD_NONE:
            if self.client_secret or has_key:
                errs.append("auth method none must not have client credentials")
        else:
            errs.append(f'unsupported token endpoint auth method "{m}"')
        if self.max_age is not None and self.max_age < timedelta(0):
            errs.append("max age must not be negative")
        if self.require_acr and not self.acr_values:
            errs.append("require acr needs acr values")
        if errs:
            raise ConfigError(errs)


def _check_url(errs: list[str], name: str, raw: str) -> None:
    if not raw:
        errs.append(f"{name} is required")
        return
    try:
        u = urlsplit(raw)
    except ValueError:
        errs.append(f"{name} must be an absolute URL")
        return
    if not u.scheme or not u.netloc:
        errs.append(f"{name} must be an absolute URL")
    elif u.scheme not in ("http", "https"):
        errs.append(f"{name} must use http or https")
