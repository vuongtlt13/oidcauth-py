"""Zitadel's identity provider login without its login UI.

The app calls the Zitadel v2 API with a service user (instance role
IAM_LOGIN_CLIENT) to act as the login UI for one external identity provider:
the browser only sees that provider's page (e.g. Google), and the login ends
as a regular Zitadel OIDC login (Zitadel user, roles, back-channel logout).

See ``oidcauth.zitadel.fastapi`` for the FastAPI/Starlette handlers and
``oidcauth.zitadel.testing`` for a fake Zitadel API.
"""

from .client import (
    AUTO_LINKING_EMAIL,
    AUTO_LINKING_USERNAME,
    ORG_SCOPE,
    USER_STATE_INACTIVE,
    USER_STATE_LOCKED,
    AuthRequest,
    Client,
    IDPLink,
    IDPOptions,
    Intent,
    LoginSettings,
    NewUser,
    Session,
    User,
    UserAgent,
)
from .errors import (
    AccessDeniedError,
    APIError,
    AuthRequestExpiredError,
    IntentFailedError,
    LoginError,
    MFARequiredError,
    NotAllowedError,
    NotLinkedError,
    UserInactiveError,
    ZitadelError,
    has_message,
    is_user_error,
)
from .login import IDPLogin

__all__ = [
    "AUTO_LINKING_EMAIL",
    "AUTO_LINKING_USERNAME",
    "ORG_SCOPE",
    "USER_STATE_INACTIVE",
    "USER_STATE_LOCKED",
    "APIError",
    "AccessDeniedError",
    "AuthRequest",
    "AuthRequestExpiredError",
    "Client",
    "IDPLink",
    "IDPLogin",
    "IDPOptions",
    "Intent",
    "IntentFailedError",
    "LoginError",
    "LoginSettings",
    "MFARequiredError",
    "NewUser",
    "NotAllowedError",
    "NotLinkedError",
    "Session",
    "User",
    "UserAgent",
    "UserInactiveError",
    "ZitadelError",
    "has_message",
    "is_user_error",
]
