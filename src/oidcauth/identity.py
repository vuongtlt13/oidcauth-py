"""The signed-in user as the provider asserted it."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Tokens:
    """The raw tokens from the token endpoint."""

    id_token: str = ""
    access_token: str = ""
    refresh_token: str = ""
    token_type: str = ""
    expiry: datetime | None = None
    # Scopes actually granted: the token response `scope` when present, else
    # the scopes requested (RFC 6749, section 5.1). Providers may grant fewer
    # scopes than requested.
    scopes: list[str] = field(default_factory=list)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


@dataclass
class Address:
    """The `address` claim (OpenID Connect Core 1.0, section 5.1.1)."""

    formatted: str = ""
    street_address: str = ""
    locality: str = ""
    region: str = ""
    postal_code: str = ""
    country: str = ""


@dataclass
class Identity:
    """What the provider asserted about the signed-in user. The library never
    creates or links local accounts: the application decides what to do with
    an Identity (link by subject, match by verified email, auto-provision,
    reject, ...).

    Fields map the standard claims of OpenID Connect Core 1.0, section 5.1;
    which ones are filled depends on the granted scopes and on the provider.
    """

    # issuer and subject together are the stable, unique key of the user at
    # the provider. Store both; never key local accounts on email alone.
    issuer: str = ""
    subject: str = ""

    # email scope.
    email: str = ""
    email_verified: bool = False

    # profile scope.
    name: str = ""
    given_name: str = ""
    family_name: str = ""
    middle_name: str = ""
    nickname: str = ""
    preferred_username: str = ""
    profile: str = ""
    picture: str = ""
    website: str = ""
    gender: str = ""
    # YYYY-MM-DD, or YYYY / 0000-MM-DD when partially disclosed.
    birthdate: str = ""
    zoneinfo: str = ""
    locale: str = ""
    updated_at: datetime | None = None

    # phone scope.
    phone_number: str = ""
    phone_number_verified: bool = False

    # address scope. None when the provider sent no address.
    address: Address | None = None

    # Authentication context from the ID token: when the user last
    # authenticated (auth_time), the context class (acr) and the methods
    # (amr, e.g. "pwd", "otp", "mfa").
    auth_time: datetime | None = None
    acr: str = ""
    amr: list[str] = field(default_factory=list)
    # The provider session (sid). Store it with the app session to honour
    # back-channel logout by session.
    session_id: str = ""

    # Roles extracted by Config.role_extractor.
    roles: list[str] = field(default_factory=list)
    # Every claim of the ID token merged with userinfo, for provider-specific
    # fields. Protected ID token claims (iss, sub, aud, exp, nonce, auth_time,
    # sid, ...) are never overridden by userinfo.
    claims: dict[str, Any] = field(default_factory=dict)

    # Tokens returned by the provider. id_token is needed as id_token_hint for
    # RP-initiated logout; access/refresh tokens are only useful if the app
    # calls provider APIs on behalf of the user or refreshes the login.
    tokens: Tokens = field(default_factory=Tokens)

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def display_name(self) -> str:
        """The best human-readable name available."""
        for v in (
            self.name,
            f"{self.given_name} {self.family_name}".strip(),
            self.preferred_username,
            self.nickname,
            self.email,
        ):
            if v:
                return v
        return self.subject


def identity_from_claims(claims: dict[str, Any], role_extractor: Any) -> Identity:
    return Identity(
        issuer=_str(claims, "iss"),
        subject=_str(claims, "sub"),
        email=_str(claims, "email").strip(),
        email_verified=_bool(claims, "email_verified"),
        name=_str(claims, "name"),
        given_name=_str(claims, "given_name"),
        family_name=_str(claims, "family_name"),
        middle_name=_str(claims, "middle_name"),
        nickname=_str(claims, "nickname"),
        preferred_username=_str(claims, "preferred_username"),
        profile=_str(claims, "profile"),
        picture=_str(claims, "picture"),
        website=_str(claims, "website"),
        gender=_str(claims, "gender"),
        birthdate=_str(claims, "birthdate"),
        zoneinfo=_str(claims, "zoneinfo"),
        locale=_str(claims, "locale"),
        updated_at=_time(claims, "updated_at"),
        phone_number=_str(claims, "phone_number").strip(),
        phone_number_verified=_bool(claims, "phone_number_verified"),
        address=_address(claims),
        auth_time=_time(claims, "auth_time"),
        acr=_str(claims, "acr"),
        amr=_strings(claims, "amr"),
        session_id=_str(claims, "sid"),
        roles=list(role_extractor(claims)),
        claims=claims,
    )


ZITADEL_ROLES_CLAIM = "urn:zitadel:iam:org:project:roles"


def default_role_extractor(claims: dict[str, Any]) -> list[str]:
    """Reads roles, in order of preference, from:

    - Zitadel ``urn:zitadel:iam:org:project:roles`` and
      ``urn:zitadel:iam:org:project:<id>:roles`` (object keyed by role name);
    - a plain ``roles`` claim (array of strings, or object keyed by role);
    - a ``groups`` claim (array of strings).

    The result is de-duplicated and sorted.
    """
    found: set[str] = set()
    for key, value in claims.items():
        if key == ZITADEL_ROLES_CLAIM or (
            key.startswith("urn:zitadel:iam:org:project:") and key.endswith(":roles")
        ):
            _add_roles(found, value)
    if not found:
        _add_roles(found, claims.get("roles"))
        _add_roles(found, claims.get("groups"))
    return sorted(found)


def _add_roles(found: set[str], value: Any) -> None:
    if isinstance(value, dict):
        found.update(k for k in value if isinstance(k, str) and k)
    elif isinstance(value, (list, tuple)):
        found.update(s for s in value if isinstance(s, str) and s)


def _str(claims: dict[str, Any], key: str) -> str:
    v = claims.get(key)
    return v if isinstance(v, str) else ""


def _bool(claims: dict[str, Any], key: str) -> bool:
    # JSON booleans, and the "true"/"false" strings some providers send for
    # email_verified.
    v = claims.get(key)
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() == "true"
    return False


def _time(claims: dict[str, Any], key: str) -> datetime | None:
    # NumericDate: seconds since the epoch (section 2).
    v = claims.get(key)
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if v <= 0 or math.isinf(v) or math.isnan(v):
        return None
    return datetime.fromtimestamp(int(v), tz=timezone.utc)


def _strings(claims: dict[str, Any], key: str) -> list[str]:
    v = claims.get(key)
    if isinstance(v, (list, tuple)):
        return [s for s in v if isinstance(s, str) and s]
    if isinstance(v, str) and v:
        return [v]
    return []


def _address(claims: dict[str, Any]) -> Address | None:
    v = claims.get("address")
    if isinstance(v, dict):
        a = Address(
            **{
                k: v[k]
                for k in Address.__dataclass_fields__
                if isinstance(v.get(k), str)
            }
        )
        return None if a == Address() else a
    if isinstance(v, str) and v:
        # Some providers send a plain formatted string.
        return Address(formatted=v)
    return None
