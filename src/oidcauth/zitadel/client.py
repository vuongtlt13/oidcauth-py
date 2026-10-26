"""A client of the Zitadel v2 API (REST): the calls the app needs to act as
Zitadel's login UI for one external identity provider. The browser only sees
that provider's page (e.g. Google), the app does the rest with a service
user."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit

import httpx

from .errors import APIError, ZitadelError

# Auto-linking options of an identity provider.
AUTO_LINKING_EMAIL = "AUTO_LINKING_OPTION_EMAIL"
AUTO_LINKING_USERNAME = "AUTO_LINKING_OPTION_USERNAME"

# User states that refuse a login.
USER_STATE_INACTIVE = "USER_STATE_INACTIVE"
USER_STATE_LOCKED = "USER_STATE_LOCKED"

# Restricts an auth request to the users of one organization.
ORG_SCOPE = "urn:zitadel:iam:org:id:"

_MAX_BODY = 1 << 20


@dataclass
class IDPLink:
    """An external account linked to a Zitadel user."""

    idp_id: str = ""
    user_id: str = ""
    user_name: str = ""

    def to_json(self) -> dict[str, str]:
        return {
            "idpId": self.idp_id,
            "userId": self.user_id,
            "userName": self.user_name,
        }


@dataclass
class NewUser:
    """What the app reads from Intent.create_user."""

    username: str = ""
    given_name: str = ""
    family_name: str = ""
    email: str = ""
    email_verified: bool = False


@dataclass
class Intent:
    """A succeeded identity provider login."""

    idp_information: IDPLink
    # The Zitadel user the external account is linked to, if any.
    user_id: str = ""
    # The CreateUser request Zitadel prepared from the external account, when
    # it is not linked.
    create_user: dict[str, Any] | None = None

    def new_user(self) -> NewUser | None:
        """Decodes create_user; None when absent."""
        if not isinstance(self.create_user, dict):
            return None
        human = _dict(self.create_user.get("human"))
        profile = _dict(human.get("profile"))
        email = _dict(human.get("email"))
        return NewUser(
            username=_str(self.create_user.get("username")),
            given_name=_str(profile.get("givenName")),
            family_name=_str(profile.get("familyName")),
            email=_str(email.get("email")),
            email_verified=email.get("isVerified") is True,
        )


@dataclass
class IDPOptions:
    """The account options of an identity provider."""

    is_linking_allowed: bool = False
    is_creation_allowed: bool = False
    is_auto_creation: bool = False
    is_auto_update: bool = False
    auto_linking: str = ""


@dataclass
class User:
    """A Zitadel user."""

    user_id: str
    state: str = ""
    # The organization of the user.
    resource_owner: str = ""


@dataclass
class LoginSettings:
    """The login policy of an organization."""

    allow_external_idp: bool = False
    force_mfa: bool = False
    force_mfa_local_only: bool = False


@dataclass
class UserAgent:
    """The browser of a session, for the session list and audit."""

    ip: str = ""
    description: str = ""


@dataclass
class Session:
    """A Zitadel session."""

    id: str
    token: str


@dataclass
class AuthRequest:
    """A pending OIDC auth request."""

    id: str
    client_id: str = ""
    scope: list[str] = field(default_factory=list)

    def org_id(self) -> str:
        """The organization the auth request is restricted to
        (urn:zitadel:iam:org:id:<id> scope), or ""."""
        for s in self.scope:
            if s.startswith(ORG_SCOPE):
                return s[len(ORG_SCOPE) :]
        return ""


class Client:
    """Calls the v2 API of one Zitadel instance as a service user.

    base_url is the instance (its issuer, e.g. https://id.viset.vn), token the
    personal access token of a service user. http_client defaults to a client
    with a 15 s timeout.
    """

    def __init__(
        self, base_url: str, token: str, http_client: httpx.AsyncClient | None = None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._own_http = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=15.0)

    async def aclose(self) -> None:
        """Closes the HTTP client when the library created it."""
        if self._own_http:
            await self._http.aclose()

    async def _do(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        body: Any = None,
    ) -> dict[str, Any]:
        headers = {
            "Authorization": "Bearer " + self._token,
            "Accept": "application/json",
        }
        content: bytes | None = None
        if body is not None:
            content = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        url = self.base_url + path
        if query:
            url += "?" + urlencode(query)
        try:
            resp = await self._http.request(
                method, url, headers=headers, content=content, follow_redirects=False
            )
        except httpx.HTTPError as e:
            raise ZitadelError(f"zitadel: {method} {path}: {e}") from e
        raw = resp.content[:_MAX_BODY]
        if resp.status_code >= 300:
            message = ""
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    message = _str(data.get("message"))
            except ValueError:
                pass
            raise APIError(
                resp.status_code, message or raw.decode(errors="replace").strip()
            )
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except ValueError as e:
            raise ZitadelError(f"zitadel: {method} {path}: decode response: {e}") from e
        return data if isinstance(data, dict) else {}

    async def authorize(self, auth_url: str) -> tuple[str, str]:
        """Sends the authorization request auth_url (built by the relying
        party) to Zitadel from the server and returns (auth_request_id, "")
        with the ID of the auth request Zitadel created, read from the login
        UI redirect. When Zitadel answers without a login UI redirect (e.g. an
        error redirect to the client's redirect URI), it returns ("",
        location) instead, for the browser to follow.

        This is how the app becomes the login UI of its own logins: with the
        instance feature "Login V2 required", Zitadel sends every auth request
        to the instance login UI, whatever base URI the application sets.
        """
        try:
            resp = await self._http.get(auth_url, follow_redirects=False)
        except httpx.HTTPError as e:
            raise ZitadelError(f"zitadel: authorize: {e}") from e
        if not 300 <= resp.status_code < 400:
            raise APIError(resp.status_code, "authorize: no redirect")
        location = resp.headers.get("location", "")
        if not location:
            raise ZitadelError("zitadel: authorize: redirect without location")
        location = urljoin(str(resp.request.url), location)
        auth_request = parse_qs(urlsplit(location).query).get("authRequest", [""])[0]
        if auth_request:
            return auth_request, ""
        return "", location

    async def start_intent(
        self, idp_id: str, success_url: str, failure_url: str
    ) -> str:
        """Starts the login at identity provider idp_id and returns the
        provider URL to send the browser to. The provider returns to Zitadel,
        which redirects to success_url with id, token (and user when the
        external account is linked), or to failure_url with error and
        error_description."""
        out = await self._do(
            "POST",
            "/v2/idp_intents",
            body={
                "idpId": idp_id,
                "urls": {"successUrl": success_url, "failureUrl": failure_url},
            },
        )
        auth_url = _str(out.get("authUrl"))
        if not auth_url:
            # Form POST (SAML) and LDAP intents need a page of their own.
            raise ZitadelError(
                "zitadel: identity provider does not use a redirect login"
            )
        return auth_url

    async def retrieve_intent(self, intent_id: str, intent_token: str) -> Intent:
        """Reads a succeeded intent, with the token from the success redirect."""
        out = await self._do(
            "POST",
            "/v2/idp_intents/" + _path(intent_id),
            body={"idpIntentToken": intent_token},
        )
        info = _dict(out.get("idpInformation"))
        create_user = out.get("createUser")
        return Intent(
            idp_information=IDPLink(
                idp_id=_str(info.get("idpId")),
                user_id=_str(info.get("userId")),
                user_name=_str(info.get("userName")),
            ),
            user_id=_str(out.get("userId")),
            create_user=create_user if isinstance(create_user, dict) else None,
        )

    async def idp_options(self, idp_id: str) -> IDPOptions:
        """Reads the account options of identity provider idp_id."""
        out = await self._do("GET", "/v2/idps/" + _path(idp_id))
        o = _dict(_dict(_dict(out.get("idp")).get("config")).get("options"))
        return IDPOptions(
            is_linking_allowed=o.get("isLinkingAllowed") is True,
            is_creation_allowed=o.get("isCreationAllowed") is True,
            is_auto_creation=o.get("isAutoCreation") is True,
            is_auto_update=o.get("isAutoUpdate") is True,
            auto_linking=_str(o.get("autoLinking")),
        )

    async def list_users(
        self, *, email: str = "", username: str = "", org_id: str = ""
    ) -> list[User]:
        """Returns the users matching email or username, within organization
        org_id when set. Text matches ignore case."""
        ignore_case = "TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE"
        queries: list[dict[str, Any]] = []
        if email:
            queries.append(
                {"emailQuery": {"emailAddress": email, "method": ignore_case}}
            )
        if username:
            queries.append(
                {"userNameQuery": {"userName": username, "method": ignore_case}}
            )
        if org_id:
            queries.append({"organizationIdQuery": {"organizationId": org_id}})
        out = await self._do("POST", "/v2/users", body={"queries": queries})
        result = out.get("result")
        return (
            [_user(u) for u in result if isinstance(u, dict)]
            if isinstance(result, list)
            else []
        )

    async def get_user(self, user_id: str) -> User:
        """Reads user user_id."""
        out = await self._do("GET", "/v2/users/" + _path(user_id))
        return _user(_dict(out.get("user")))

    async def add_idp_link(self, user_id: str, link: IDPLink) -> None:
        """Links an external account to user user_id."""
        await self._do(
            "POST",
            "/v2/users/" + _path(user_id) + "/links",
            body={"idpLink": link.to_json()},
        )

    async def create_user(self, org_id: str, request: dict[str, Any]) -> str:
        """Creates a user in organization org_id from a CreateUser request
        prepared by Zitadel (Intent.create_user) and returns its ID."""
        body = dict(request)
        body["organizationId"] = org_id
        out = await self._do("POST", "/v2/users/new", body=body)
        return _str(out.get("id"))

    async def default_org_id(self) -> str:
        """The default organization of the instance."""
        out = await self._do(
            "POST",
            "/v2/organizations/_search",
            body={"queries": [{"defaultQuery": {}}]},
        )
        result = out.get("result")
        if not isinstance(result, list) or not result:
            raise ZitadelError("zitadel: no default organization")
        return _str(_dict(result[0]).get("id"))

    async def login_settings(self, org_id: str) -> LoginSettings:
        """Reads the login policy of organization org_id."""
        out = await self._do("GET", "/v2/settings/login", query={"ctx.orgId": org_id})
        s = _dict(out.get("settings"))
        return LoginSettings(
            allow_external_idp=s.get("allowExternalIdp") is True,
            force_mfa=s.get("forceMfa") is True,
            force_mfa_local_only=s.get("forceMfaLocalOnly") is True,
        )

    async def active_idps(self, org_id: str, linking: bool = False) -> list[str]:
        """The IDs of the identity providers organization org_id offers at
        login (its own or the instance's); with linking, only those that allow
        linking existing users."""
        query = {"ctx.orgId": org_id}
        if linking:
            query["linkingAllowed"] = "true"
        out = await self._do("GET", "/v2/settings/login/idps", query=query)
        idps = out.get("identityProviders")
        if not isinstance(idps, list):
            return []
        return [_str(_dict(p).get("id")) for p in idps]

    async def create_session(
        self,
        user_id: str,
        intent_id: str,
        intent_token: str,
        user_agent: UserAgent | None = None,
    ) -> Session:
        """Creates a session of user user_id checked by a succeeded intent
        (which it consumes)."""
        body: dict[str, Any] = {
            "checks": {
                "user": {"userId": user_id},
                "idpIntent": {"idpIntentId": intent_id, "idpIntentToken": intent_token},
            }
        }
        if user_agent is not None:
            ua = {"ip": user_agent.ip, "description": user_agent.description}
            body["userAgent"] = {k: v for k, v in ua.items() if v}
        out = await self._do("POST", "/v2/sessions", body=body)
        return Session(
            id=_str(out.get("sessionId")), token=_str(out.get("sessionToken"))
        )

    async def auth_request(self, auth_request_id: str) -> AuthRequest:
        """Reads auth request auth_request_id."""
        out = await self._do("GET", "/v2/oidc/auth_requests/" + _path(auth_request_id))
        a = _dict(out.get("authRequest"))
        scope = a.get("scope")
        return AuthRequest(
            id=_str(a.get("id")),
            client_id=_str(a.get("clientId")),
            scope=[_str(s) for s in scope] if isinstance(scope, list) else [],
        )

    async def create_callback(self, auth_request_id: str, session: Session) -> str:
        """Completes auth request auth_request_id with session and returns the
        client's redirect URI with the authorization code."""
        out = await self._do(
            "POST",
            "/v2/oidc/auth_requests/" + _path(auth_request_id),
            body={"session": {"sessionId": session.id, "sessionToken": session.token}},
        )
        return _str(out.get("callbackUrl"))


def _user(u: dict[str, Any]) -> User:
    return User(
        user_id=_str(u.get("userId")),
        state=_str(u.get("state")),
        resource_owner=_str(_dict(u.get("details")).get("resourceOwner")),
    )


def _path(segment: str) -> str:
    return quote(segment, safe="")


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _str(v: Any) -> str:
    return v if isinstance(v, str) else ""
