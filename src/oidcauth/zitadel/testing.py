"""A fake Zitadel v2 API for the identity provider login (IDPLogin), on top of
an ``oidcauth.testing.Provider`` that issues the tokens: the authorization
request gets a V2 auth request, and completing it returns the provider's code
callback::

    op = Provider("c1", "s1")
    fake = FakeZitadel(op)
    fake.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID)
    fake.external = External(id="g-1", linked_to="u1")
    login = IDPLogin(Client(op.issuer, TOKEN, fake.http_client()), IDP_ID)

The fake serves the API on the provider's host, through an
``httpx.MockTransport``; other requests go to the provider.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx

from ..testing import Provider
from ..testing import User as OIDCUser

# Fixed values of the fake.
TOKEN = "service-pat"
IDP_ID = "idp-google"
AUTH_REQUEST_ID = "V2_auth-1"
INTENT_ID = "intent-1"
INTENT_TOKEN = "intent-token"
DEFAULT_ORG_ID = "org-default"
NEW_USER_ID = "user-new"
# Where start_intent sends the browser (the fake Google).
IDP_AUTH_URL = "https://accounts.google.test/o/oauth2/auth"


@dataclass
class User:
    """A Zitadel user of the fake."""

    id: str
    org_id: str = ""
    email: str = ""
    state: str = ""  # defaults to USER_STATE_ACTIVE
    # What the provider puts in the tokens of this user; subject defaults to
    # id, email to email (verified).
    oidc: OIDCUser | None = None


@dataclass
class Org:
    """The login policy of an organization."""

    allow_external_idp: bool = False
    force_mfa: bool = False
    # Identity providers active at login, with linking allowed.
    idps: list[str] = field(default_factory=list)


@dataclass
class External:
    """The account the user logs in with at the identity provider."""

    id: str = ""
    email: str = ""
    verified: bool = False
    given_name: str = ""
    family_name: str = ""
    # The Zitadel user the account is already linked to.
    linked_to: str = ""


class FakeZitadel:
    """The fake Zitadel API. Configure the fields before the login."""

    def __init__(self, op: Provider) -> None:
        self.op = op
        # Options of the identity provider IDP_ID.
        self.auto_linking = ""
        self.is_auto_creation = False
        self.users: dict[str, User] = {}
        self.orgs: dict[str, Org] = {
            DEFAULT_ORG_ID: Org(allow_external_idp=True, idps=[IDP_ID])
        }
        self.external = External()
        # The scope of the auth request (an org scope restricts the users).
        self.auth_request_scope: list[str] = []
        # Makes create_callback fail with this message.
        self.callback_error = ""
        # External accounts linked by add_idp_link: user -> idp user.
        self.links: dict[str, str] = {}
        # The create_user requests.
        self.created: list[dict[str, Any]] = []
        # The user of the last session.
        self.session_user = ""

        self._auth_url = ""
        self._success_url = ""
        self._failure_url = ""
        self._handled = False
        self._consumed = False
        self.transport = httpx.MockTransport(self.handle)

    def http_client(self, **kwargs: Any) -> httpx.AsyncClient:
        """An AsyncClient for the zitadel Client: it answers the provider's
        authorization endpoint like Zitadel with Login V2 (a redirect to the
        login UI with the auth request ID), serves the API and sends every
        other request to the provider."""
        return httpx.AsyncClient(transport=self.transport, **kwargs)

    # -- browser side --------------------------------------------------------

    def success_redirect(self) -> str:
        """Where Zitadel sends the browser after a succeeded login at the
        identity provider: the success URL with the intent."""
        q = {"id": INTENT_ID, "token": INTENT_TOKEN}
        if self.external.linked_to:
            q["user"] = self.external.linked_to
        return _append_query(self._success_url, q)

    def failure_redirect(self, code: str) -> str:
        """Where Zitadel sends the browser after a failed login at the
        identity provider."""
        return _append_query(
            self._failure_url, {"error": code, "error_description": "failed"}
        )

    # -- transport -----------------------------------------------------------

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/oauth/v2/authorize":
            self._auth_url = str(request.url)
            self._handled = False
            base = f"{request.url.scheme}://{request.url.netloc.decode()}"
            return httpx.Response(
                302,
                headers={
                    "Location": f"{base}/ui/v2/login/login?authRequest={AUTH_REQUEST_ID}"
                },
            )
        if not path.startswith("/v2/"):
            return self.op.handle(request)
        if request.headers.get("authorization") != "Bearer " + TOKEN:
            return _api_error(401, "Errors.Token.Invalid")
        body: dict[str, Any] = {}
        if request.content:
            try:
                data = json.loads(request.content)
            except ValueError as e:
                return _api_error(400, f"invalid body: {e}")
            body = data if isinstance(data, dict) else {}
        query = dict(request.url.params)
        parts = path.strip("/").split("/")[1:]  # without "v2"
        method = request.method

        if method == "POST" and parts == ["idp_intents"]:
            return self._start_intent(body)
        if method == "POST" and len(parts) == 2 and parts[0] == "idp_intents":
            return self._retrieve_intent(parts[1], body)
        if method == "GET" and len(parts) == 2 and parts[0] == "idps":
            return self._idp(parts[1])
        if method == "POST" and parts == ["users"]:
            return self._list_users(body)
        if method == "POST" and parts == ["users", "new"]:
            return self._create_user(body)
        if method == "GET" and len(parts) == 2 and parts[0] == "users":
            return self._get_user(parts[1])
        if (
            method == "POST"
            and len(parts) == 3
            and parts[0] == "users"
            and parts[2] == "links"
        ):
            return self._add_link(parts[1], body)
        if method == "POST" and parts == ["organizations", "_search"]:
            return _json({"result": [{"id": DEFAULT_ORG_ID}]})
        if method == "GET" and parts == ["settings", "login"]:
            return self._login_settings(query)
        if method == "GET" and parts == ["settings", "login", "idps"]:
            return self._active_idps(query)
        if method == "POST" and parts == ["sessions"]:
            return self._create_session(body)
        if len(parts) == 3 and parts[:2] == ["oidc", "auth_requests"]:
            if method == "GET":
                return self._auth_request(parts[2])
            if method == "POST":
                return self._create_callback(parts[2], body)
        return _api_error(404, "not found")

    # -- endpoints -----------------------------------------------------------

    def _start_intent(self, body: dict[str, Any]) -> httpx.Response:
        if body.get("idpId") != IDP_ID:
            return _api_error(404, "Errors.IDPConfig.NotExisting")
        urls = body.get("urls") or {}
        self._success_url = urls.get("successUrl", "")
        self._failure_url = urls.get("failureUrl", "")
        self._consumed = False
        return _json({"authUrl": IDP_AUTH_URL + "?state=zitadel-state"})

    def _retrieve_intent(self, intent_id: str, body: dict[str, Any]) -> httpx.Response:
        if intent_id != INTENT_ID or body.get("idpIntentToken") != INTENT_TOKEN:
            return _api_error(412, "Errors.Intent.InvalidToken")
        ext = self.external
        out: dict[str, Any] = {
            "idpInformation": {"idpId": IDP_ID, "userId": ext.id, "userName": ext.email}
        }
        if ext.linked_to:
            out["userId"] = ext.linked_to
        else:
            email: dict[str, Any] = {"email": ext.email}
            if ext.verified:
                email["isVerified"] = True
            else:
                email["sendCode"] = {}
            out["createUser"] = {
                "username": ext.email,
                "human": {
                    "profile": {
                        "givenName": ext.given_name,
                        "familyName": ext.family_name,
                    },
                    "email": email,
                    "idpLinks": [
                        {"idpId": IDP_ID, "userId": ext.id, "userName": ext.email}
                    ],
                },
            }
        return _json(out)

    def _idp(self, idp_id: str) -> httpx.Response:
        return _json(
            {
                "idp": {
                    "id": idp_id,
                    "config": {
                        "options": {
                            "isLinkingAllowed": True,
                            "isAutoCreation": self.is_auto_creation,
                            "autoLinking": self.auto_linking,
                        }
                    },
                }
            }
        )

    @staticmethod
    def _user_json(u: User) -> dict[str, Any]:
        return {
            "userId": u.id,
            "state": u.state or "USER_STATE_ACTIVE",
            "details": {"resourceOwner": u.org_id},
        }

    def _list_users(self, body: dict[str, Any]) -> httpx.Response:
        email = org = ""
        for q in body.get("queries") or []:
            if "emailQuery" in q:
                email = q["emailQuery"].get("emailAddress", "")
            if "organizationIdQuery" in q:
                org = q["organizationIdQuery"].get("organizationId", "")
        result = [
            self._user_json(u)
            for u in self.users.values()
            if u.email.lower() == email.lower() and (not org or u.org_id == org)
        ]
        return _json({"result": result})

    def _get_user(self, user_id: str) -> httpx.Response:
        u = self.users.get(user_id)
        if u is None:
            return _api_error(404, "Errors.User.NotFound")
        return _json({"user": self._user_json(u)})

    def _add_link(self, user_id: str, body: dict[str, Any]) -> httpx.Response:
        self.links[user_id] = (body.get("idpLink") or {}).get("userId", "")
        return _json({})

    def _create_user(self, body: dict[str, Any]) -> httpx.Response:
        self.created.append(body)
        self.users[NEW_USER_ID] = User(
            id=NEW_USER_ID,
            org_id=body.get("organizationId", ""),
            email=self.external.email,
        )
        self.links[NEW_USER_ID] = self.external.id  # from human.idpLinks
        return _json({"id": NEW_USER_ID})

    def _org(self, query: dict[str, str]) -> Org:
        return self.orgs.get(query.get("ctx.orgId", ""), Org())

    def _login_settings(self, query: dict[str, str]) -> httpx.Response:
        o = self._org(query)
        return _json(
            {
                "settings": {
                    "allowExternalIdp": o.allow_external_idp,
                    "forceMfa": o.force_mfa,
                }
            }
        )

    def _active_idps(self, query: dict[str, str]) -> httpx.Response:
        return _json({"identityProviders": [{"id": i} for i in self._org(query).idps]})

    def _create_session(self, body: dict[str, Any]) -> httpx.Response:
        checks = body.get("checks") or {}
        user_id = (checks.get("user") or {}).get("userId", "")
        intent = checks.get("idpIntent") or {}
        if (
            intent.get("idpIntentId") != INTENT_ID
            or intent.get("idpIntentToken") != INTENT_TOKEN
            or self._consumed
        ):
            return _api_error(412, "Errors.Intent.NotSucceeded")
        # CheckIntent: the external account must belong to the session user.
        if (
            self.external.linked_to != user_id
            and self.links.get(user_id) != self.external.id
        ):
            return _api_error(412, "Errors.Intent.OtherUser")
        self._consumed = True
        self.session_user = user_id
        return _json({"sessionId": "session-1", "sessionToken": "session-token"})

    def _auth_request(self, auth_request_id: str) -> httpx.Response:
        if auth_request_id != AUTH_REQUEST_ID or not self._auth_url:
            return _api_error(404, "Errors.AuthRequest.NotFound")
        return _json(
            {
                "authRequest": {
                    "id": AUTH_REQUEST_ID,
                    "clientId": self.op.client_id,
                    "scope": self.auth_request_scope,
                }
            }
        )

    def _create_callback(
        self, auth_request_id: str, body: dict[str, Any]
    ) -> httpx.Response:
        session = body.get("session") or {}
        if auth_request_id != AUTH_REQUEST_ID or not self._auth_url:
            return _api_error(404, "Errors.AuthRequest.NotFound")
        if self._handled:
            return _api_error(412, "Errors.AuthRequest.AlreadyHandled")
        if (
            session.get("sessionId") != "session-1"
            or session.get("sessionToken") != "session-token"
        ):
            return _api_error(412, "Errors.Session.Token.Invalid")
        if self.callback_error:
            return _api_error(403, self.callback_error)
        u = self.users.get(self.session_user)
        if u is None:
            return _api_error(404, "Errors.User.NotFound")
        self._handled = True
        oidc_user = dataclasses.replace(u.oidc) if u.oidc else OIDCUser(subject=u.id)
        if not oidc_user.subject:
            oidc_user.subject = u.id
        if not oidc_user.email:
            oidc_user.email, oidc_user.email_verified = u.email, True
        params = self.op.authorize(self._auth_url, oidc_user)
        redirect_uri = dict(parse_qsl(urlsplit(self._auth_url).query)).get(
            "redirect_uri", ""
        )
        return _json({"callbackUrl": _append_query(redirect_uri, params)})


def _append_query(raw: str, q: dict[str, str]) -> str:
    return raw + ("&" if "?" in raw else "?") + urlencode(q)


def _json(v: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=v)


def _api_error(status: int, message: str) -> httpx.Response:
    return _json({"code": status, "message": message}, status)


__all__ = [
    "AUTH_REQUEST_ID",
    "DEFAULT_ORG_ID",
    "IDP_AUTH_URL",
    "IDP_ID",
    "INTENT_ID",
    "INTENT_TOKEN",
    "NEW_USER_ID",
    "TOKEN",
    "External",
    "FakeZitadel",
    "Org",
    "User",
]
