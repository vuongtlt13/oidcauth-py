"""OpenID Connect relying party for browser login: authorization code flow with
PKCE, state and nonce, an encrypted flow cookie, ID token verification,
refresh, revocation, RP-initiated and back-channel logout.

The library verifies the provider response and returns an Identity. It does not
touch the user table and does not issue session tokens: what to do with the
identity (link, provision, reject) and how to keep the user signed in is the
application's decision.

See ``oidcauth.fastapi`` for the FastAPI/Starlette adapter,
``oidcauth.testing`` for a fake provider and ``oidcauth.zitadel`` for
Zitadel's headless identity provider login.
"""

from .client import (
    BACKCHANNEL_LOGOUT_EVENT,
    Client,
    LoginOptions,
    LogoutToken,
    RefreshResult,
    Result,
)
from .config import (
    AUTH_METHOD_AUTO,
    AUTH_METHOD_CLIENT_SECRET_BASIC,
    AUTH_METHOD_CLIENT_SECRET_POST,
    AUTH_METHOD_NONE,
    AUTH_METHOD_PRIVATE_KEY_JWT,
    DEFAULT_SCOPES,
    Config,
)
from .errors import (
    ConfigError,
    DiscoveryError,
    InvalidLogoutTokenError,
    InvalidStateError,
    MissingCodeError,
    NotSupportedError,
    OIDCAuthError,
    ProviderError,
    ProviderUnreachableError,
    TicketNotFoundError,
    TokenError,
    UserInfoError,
    is_user_error,
)
from .flow import Cookie
from .helpers import MemoryTicketStore, RedisTicketStore, TicketStore, safe_return_to
from .identity import Address, Identity, Tokens, default_role_extractor
from .scopes import (
    DISPLAY_PAGE,
    DISPLAY_POPUP,
    DISPLAY_TOUCH,
    DISPLAY_WAP,
    PROMPT_CONSENT,
    PROMPT_CREATE,
    PROMPT_LOGIN,
    PROMPT_NONE,
    PROMPT_SELECT_ACCOUNT,
    RESPONSE_MODE_FORM_POST,
    RESPONSE_MODE_QUERY,
    SCOPE_ADDRESS,
    SCOPE_EMAIL,
    SCOPE_OFFLINE_ACCESS,
    SCOPE_OPENID,
    SCOPE_PHONE,
    SCOPE_PROFILE,
    TOKEN_TYPE_HINT_ACCESS,
    TOKEN_TYPE_HINT_REFRESH,
    ClaimRequest,
    ClaimsRequest,
)

__version__ = "0.1.0"

__all__ = [
    "AUTH_METHOD_AUTO",
    "AUTH_METHOD_CLIENT_SECRET_BASIC",
    "AUTH_METHOD_CLIENT_SECRET_POST",
    "AUTH_METHOD_NONE",
    "AUTH_METHOD_PRIVATE_KEY_JWT",
    "BACKCHANNEL_LOGOUT_EVENT",
    "DEFAULT_SCOPES",
    "DISPLAY_PAGE",
    "DISPLAY_POPUP",
    "DISPLAY_TOUCH",
    "DISPLAY_WAP",
    "PROMPT_CONSENT",
    "PROMPT_CREATE",
    "PROMPT_LOGIN",
    "PROMPT_NONE",
    "PROMPT_SELECT_ACCOUNT",
    "RESPONSE_MODE_FORM_POST",
    "RESPONSE_MODE_QUERY",
    "SCOPE_ADDRESS",
    "SCOPE_EMAIL",
    "SCOPE_OFFLINE_ACCESS",
    "SCOPE_OPENID",
    "SCOPE_PHONE",
    "SCOPE_PROFILE",
    "TOKEN_TYPE_HINT_ACCESS",
    "TOKEN_TYPE_HINT_REFRESH",
    "Address",
    "ClaimRequest",
    "ClaimsRequest",
    "Client",
    "Config",
    "ConfigError",
    "Cookie",
    "DiscoveryError",
    "Identity",
    "InvalidLogoutTokenError",
    "InvalidStateError",
    "LoginOptions",
    "LogoutToken",
    "MemoryTicketStore",
    "MissingCodeError",
    "NotSupportedError",
    "OIDCAuthError",
    "ProviderError",
    "ProviderUnreachableError",
    "RedisTicketStore",
    "RefreshResult",
    "Result",
    "TicketNotFoundError",
    "TicketStore",
    "TokenError",
    "Tokens",
    "UserInfoError",
    "default_role_extractor",
    "is_user_error",
    "safe_return_to",
]
