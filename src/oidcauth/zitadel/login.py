"""Zitadel's identity provider login without its login UI."""

from __future__ import annotations

import copy
from typing import Any, NoReturn

from .client import (
    AUTO_LINKING_EMAIL,
    AUTO_LINKING_USERNAME,
    USER_STATE_INACTIVE,
    USER_STATE_LOCKED,
    Client,
    Intent,
    User,
    UserAgent,
)
from .errors import (
    AccessDeniedError,
    APIError,
    AuthRequestExpiredError,
    MFARequiredError,
    NotAllowedError,
    NotLinkedError,
    UserInactiveError,
    ZitadelError,
    has_message,
)


class IDPLogin:
    """Logs users in to Zitadel with one external identity provider (e.g.
    Google) without Zitadel's login UI, the way the login UI itself does it:
    start an intent at the provider, then turn the succeeded intent into a
    session and complete the OIDC auth request with it. The app then exchanges
    the code as for any other login, so the result is a regular Zitadel login
    (Zitadel user, roles, back-channel logout).

    The service user behind the client needs the instance role
    IAM_LOGIN_CLIENT.
    """

    def __init__(self, api: Client, idp_id: str) -> None:
        self.api = api
        self._idp_id = idp_id

    @property
    def idp_id(self) -> str:
        """The identity provider of the login."""
        return self._idp_id

    async def authorize(self, auth_url: str) -> tuple[str, str]:
        """Sends the authorization request auth_url to Zitadel. Returns
        (auth_request_id, "") to pass to finish or, when Zitadel rejected the
        request, ("", error_redirect): the client's redirect URI with the
        error, for the browser."""
        return await self.api.authorize(auth_url)

    async def start_intent(self, success_url: str, failure_url: str) -> str:
        """Starts the login at the identity provider and returns the URL to
        send the browser to. Zitadel returns to success_url with the intent
        (id, token) or to failure_url with error and error_description."""
        return await self.api.start_intent(self._idp_id, success_url, failure_url)

    async def finish(
        self,
        auth_request_id: str,
        intent_id: str,
        intent_token: str,
        user_agent: UserAgent | None = None,
    ) -> str:
        """Completes auth request auth_request_id with the intent of the
        success redirect (query id and token) and returns the client's
        redirect URI with the authorization code.

        The Zitadel user is the one the external account is linked to.
        Otherwise, following the identity provider options: auto-linking by
        verified email (or username) links the single matching user, if their
        organization allows the provider; auto-creation creates a user in the
        organization the auth request is restricted to
        (urn:zitadel:iam:org:id scope), or in the default organization.
        """
        try:
            auth_req = await self.api.auth_request(auth_request_id)
        except ZitadelError as e:
            _raise_auth_request_error(e)
        intent = await self.api.retrieve_intent(intent_id, intent_token)
        if intent.idp_information.idp_id != self._idp_id:
            raise ZitadelError(
                f'zitadel: intent of identity provider "{intent.idp_information.idp_id}", '
                f'want "{self._idp_id}"'
            )
        org_id = auth_req.org_id()

        user = await self._resolve_user(intent, org_id)
        if user.state in (USER_STATE_INACTIVE, USER_STATE_LOCKED):
            raise UserInactiveError(f"user {user.user_id} is {user.state}")
        if org_id and user.resource_owner != org_id:
            raise NotAllowedError(
                f"user {user.user_id} belongs to org {user.resource_owner}, "
                f"the auth request requires org {org_id}"
            )
        settings = await self.api.login_settings(user.resource_owner)
        if settings.force_mfa and not settings.force_mfa_local_only:
            raise MFARequiredError(f"org {user.resource_owner} of user {user.user_id}")

        session = await self.api.create_session(
            user.user_id, intent_id, intent_token, user_agent
        )
        try:
            return await self.api.create_callback(auth_request_id, session)
        except ZitadelError as e:
            if has_message(e, "Errors.User.ProjectRequired") or has_message(
                e, "Errors.User.GrantRequired"
            ):
                raise AccessDeniedError(f"user {user.user_id}: {e}") from e
            if has_message(e, "Errors.User.NotAllowedOrg"):
                raise NotAllowedError(f"user {user.user_id}: {e}") from e
            _raise_auth_request_error(e)

    async def _resolve_user(self, intent: Intent, org_id: str) -> User:
        """The Zitadel user of the external account, linking or creating it
        as the identity provider options allow."""
        if intent.user_id:
            return await self.api.get_user(intent.user_id)
        opts = await self.api.idp_options(self._idp_id)
        new_user = intent.new_user()
        reason = "the identity provider neither auto-links nor auto-creates users"

        users: list[User] | None = None
        if (
            opts.auto_linking == AUTO_LINKING_EMAIL
            and new_user is not None
            and new_user.email_verified
            and new_user.email
        ):
            users = await self.api.list_users(email=new_user.email, org_id=org_id)
        elif (
            opts.auto_linking == AUTO_LINKING_USERNAME
            and intent.idp_information.user_name
        ):
            users = await self.api.list_users(
                username=intent.idp_information.user_name, org_id=org_id
            )
        if users is not None:
            # Several matches (the same email in two organizations): linking
            # would be a guess, so the user links from an existing session.
            if not users:
                reason = f"auto-linking by {opts.auto_linking} found no user"
            elif len(users) == 1:
                user = users[0]
                await self._check_linking_allowed(user.resource_owner)
                await self.api.add_idp_link(user.user_id, intent.idp_information)
                return user
            else:
                ids = [f"{u.user_id}@org:{u.resource_owner}" for u in users]
                reason = f"auto-linking by {opts.auto_linking} matches {len(users)} users {ids}"

        if opts.is_auto_creation and new_user is not None and intent.create_user:
            request = _with_names(intent.create_user)
            if request is None:
                raise NotLinkedError(f"{reason}, auto-creation needs a name")
            if not org_id:
                org_id = await self.api.default_org_id()
            user_id = await self.api.create_user(org_id, request)
            return User(user_id=user_id, resource_owner=org_id)
        raise NotLinkedError(f"idp {self._idp_id}: {reason}")

    async def _check_linking_allowed(self, org_id: str) -> None:
        """Raises NotAllowedError unless organization org_id offers the
        identity provider for linking existing users."""
        settings = await self.api.login_settings(org_id)
        if not settings.allow_external_idp:
            raise NotAllowedError(
                f"org {org_id} does not allow external identity providers"
            )
        ids = await self.api.active_idps(org_id, linking=True)
        if self._idp_id not in ids:
            raise NotAllowedError(
                f"org {org_id} does not offer identity provider {self._idp_id} "
                f"for linking (it offers {ids})"
            )


def _with_names(create_user: dict[str, Any]) -> dict[str, Any] | None:
    """create_user with both names, which CreateUser requires (the login UI
    asks for missing ones). Many accounts lack one, e.g. Google accounts with
    a single name: a missing name takes the other, else the display name,
    else the email's local part, else the username. None when there is
    nothing to use."""
    request = copy.deepcopy(create_user)
    human = request.get("human")
    if not isinstance(human, dict):
        return None
    profile = human.get("profile")
    if not isinstance(profile, dict):
        profile = human["profile"] = {}
    email = human.get("email")
    email = email.get("email") if isinstance(email, dict) else None
    fallbacks = (
        profile.get("givenName"),
        profile.get("familyName"),
        profile.get("displayName"),
        email.partition("@")[0] if isinstance(email, str) else None,
        request.get("username"),
    )
    name = next((v.strip() for v in fallbacks if isinstance(v, str) and v.strip()), "")
    if not name:
        return None
    for key in ("givenName", "familyName"):
        value = profile.get(key)
        if not isinstance(value, str) or not value.strip():
            profile[key] = name
    return request


def _raise_auth_request_error(err: ZitadelError) -> NoReturn:
    """Raises AuthRequestExpiredError for an unknown or completed auth
    request, err otherwise."""
    if (isinstance(err, APIError) and err.status == 404) or has_message(
        err, "Errors.AuthRequest.AlreadyHandled"
    ):
        raise AuthRequestExpiredError(str(err)) from err
    raise err
