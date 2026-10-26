"""Standard scopes, request parameter values and the claims request."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Scopes of OpenID Connect Core 1.0, section 5.4 and 11.
SCOPE_OPENID = "openid"
SCOPE_PROFILE = "profile"
SCOPE_EMAIL = "email"
SCOPE_ADDRESS = "address"
SCOPE_PHONE = "phone"
SCOPE_OFFLINE_ACCESS = "offline_access"

# Values of the prompt parameter.
PROMPT_NONE = "none"
PROMPT_LOGIN = "login"
PROMPT_CONSENT = "consent"
PROMPT_SELECT_ACCOUNT = "select_account"
PROMPT_CREATE = "create"

# Values of the display parameter.
DISPLAY_PAGE = "page"
DISPLAY_POPUP = "popup"
DISPLAY_TOUCH = "touch"
DISPLAY_WAP = "wap"

# Values of the response_mode parameter.
RESPONSE_MODE_QUERY = "query"
RESPONSE_MODE_FORM_POST = "form_post"

# Token type hints of revocation.
TOKEN_TYPE_HINT_ACCESS = "access_token"
TOKEN_TYPE_HINT_REFRESH = "refresh_token"


@dataclass
class ClaimRequest:
    """Request of one claim (OpenID Connect Core 1.0, section 5.5.1)."""

    essential: bool = False
    value: Any = None
    values: list[Any] | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.essential:
            out["essential"] = True
        if self.value is not None:
            out["value"] = self.value
        if self.values:
            out["values"] = list(self.values)
        return out


@dataclass
class ClaimsRequest:
    """The claims request parameter: claims to return from the userinfo
    endpoint and in the ID token. A claim mapped to None is requested in the
    default manner (JSON null)."""

    userinfo: dict[str, ClaimRequest | None] = field(default_factory=dict)
    id_token: dict[str, ClaimRequest | None] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, claims in (("userinfo", self.userinfo), ("id_token", self.id_token)):
            if claims:
                out[name] = {
                    k: (None if v is None else v.to_json()) for k, v in claims.items()
                }
        return out
