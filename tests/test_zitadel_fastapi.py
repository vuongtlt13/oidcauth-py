"""The Zitadel identity provider login end to end: login route -> identity
provider (the browser only sees its page) -> Zitadel -> idp callback -> the
client's callback."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response

from oidcauth import (
    Client,
    Config,
    InvalidStateError,
    MemoryTicketStore,
    Result,
    safe_return_to,
)
from oidcauth.fastapi import OIDCHandler
from oidcauth.testing import Provider
from oidcauth.zitadel import (
    AUTO_LINKING_EMAIL,
    USER_STATE_INACTIVE,
    AccessDeniedError,
)
from oidcauth.zitadel import Client as ZitadelClient
from oidcauth.zitadel import (
    IDPLogin,
    IntentFailedError,
    MFARequiredError,
    NotAllowedError,
    NotLinkedError,
    UserInactiveError,
    is_user_error,
)
from oidcauth.zitadel.fastapi import ZitadelIDPHandler
from oidcauth.zitadel.testing import (
    DEFAULT_ORG_ID,
    IDP_AUTH_URL,
    IDP_ID,
    NEW_USER_ID,
    TOKEN,
    External,
    FakeZitadel,
    Org,
    User,
)

API = "http://api.test"


@dataclass
class Env:
    http: httpx.AsyncClient
    fake: FakeZitadel
    # The result of the last successful login, the last failure.
    results: list[Result] = field(default_factory=list)
    errors: list[Exception] = field(default_factory=list)

    @property
    def err(self) -> Exception | None:
        return self.errors[-1] if self.errors else None

    async def start(self, return_to: str) -> tuple[str, dict[str, str]]:
        """Runs the login route; returns its redirect and the cookies the
        browser keeps."""
        resp = await self.http.get("/auth/google/login", params={"redirect": return_to})
        assert resp.status_code == 302, resp.text
        assert resp.headers["cache-control"] == "no-store"
        cookies = {k: v for k, v in resp.cookies.items() if v}
        return resp.headers["location"], cookies

    async def follow(self, raw: str, cookies: dict[str, str] | None) -> str:
        """Sends the browser to an API URL with cookies; returns the
        redirect."""
        u = urlsplit(raw)
        assert u.netloc in ("", "api.test"), f"leaves the API: {raw}"
        target = u.path + ("?" + u.query if u.query else "")
        header = "; ".join(f"{k}={v}" for k, v in (cookies or {}).items())
        resp = await self.http.get(target, headers={"cookie": header} if header else {})
        assert resp.status_code == 302, f"{u.path}: {resp.status_code} {resp.text}"
        return resp.headers["location"]

    async def login(self, return_to: str) -> str:
        loc, cookies = await self.start(return_to)
        assert loc.startswith(IDP_AUTH_URL), "the browser must go straight to the IdP"
        loc = await self.follow(self.fake.success_redirect(), cookies)
        if urlsplit(loc).path != "/auth/callback":
            return loc  # error
        return await self.follow(loc, cookies)


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    op = Provider("c1", "s1")
    fake = FakeZitadel(op)
    client = Client(
        Config(
            issuer=op.issuer,
            client_id="c1",
            client_secret="s1",
            redirect_url=API + "/auth/callback",
            cookie_secret="k" * 32,
            cookie_path="/auth/",
            http_client=op.http_client(),
        )
    )
    app = FastAPI()
    e = Env(
        http=httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API),
        fake=fake,
    )

    def on_error(request: Request, err: Exception) -> Response:
        e.errors.append(err)
        return RedirectResponse("/login?error=1", 302)

    def on_success(request: Request, res: Result) -> Response:
        e.results.append(res)
        return RedirectResponse(safe_return_to(res.return_to, "/"), 302)

    web = OIDCHandler(client, on_success=on_success, on_error=on_error)
    login = IDPLogin(ZitadelClient(op.issuer, TOKEN, fake.http_client()), IDP_ID)
    idp = ZitadelIDPHandler(
        client,
        login,
        tickets=MemoryTicketStore(),
        callback_url=API + "/auth/google/idp/callback",
        on_error=on_error,
    )
    app.add_api_route("/auth/callback", web.callback, methods=["GET"])
    app.add_api_route("/auth/google/login", idp.login, methods=["GET"])
    app.add_api_route("/auth/google/idp/callback", idp.callback, methods=["GET"])
    async with e.http:
        yield e


async def test_linked_account_logs_in(env: Env) -> None:
    env.fake.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID, email="a@example.com")
    env.fake.external = External(
        id="g-1", email="a@gmail.com", verified=True, linked_to="u1"
    )

    assert await env.login("/jobs") == "/jobs", env.err
    assert env.fake.session_user == "u1"
    # The identity is the Zitadel user.
    assert env.results and env.results[0].identity.subject == "u1"


async def test_auto_links_by_verified_email(env: Env) -> None:
    env.fake.auto_linking = AUTO_LINKING_EMAIL
    env.fake.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID, email="A@Gmail.com")
    env.fake.external = External(id="g-1", email="a@gmail.com", verified=True)

    assert await env.login("/") == "/", env.err
    assert env.fake.links["u1"] == "g-1"
    assert env.fake.session_user == "u1"


@pytest.mark.parametrize(
    "scope, org",
    [
        (["openid", "urn:zitadel:iam:org:id:org-customer"], "org-customer"),
        ([], DEFAULT_ORG_ID),
    ],
    ids=["in the requested org", "in the default org"],
)
async def test_auto_creates(env: Env, scope: list[str], org: str) -> None:
    env.fake.is_auto_creation = True
    env.fake.auth_request_scope = scope
    env.fake.external = External(
        id="g-1",
        email="new@gmail.com",
        verified=True,
        given_name="An",
        family_name="Nguyen",
    )

    assert await env.login("/") == "/", env.err
    assert len(env.fake.created) == 1
    assert env.fake.created[0]["organizationId"] == org
    assert env.fake.session_user == NEW_USER_ID


@pytest.mark.parametrize(
    "given, family, want",
    [
        ("An", "", ("An", "An")),
        ("", "Nguyen", ("Nguyen", "Nguyen")),
        ("", " ", ("new", "new")),
    ],
    ids=["no family name", "no given name", "no names"],
)
async def test_auto_creates_with_missing_names(
    env: Env, given: str, family: str, want: tuple[str, str]
) -> None:
    env.fake.is_auto_creation = True
    env.fake.external = External(
        id="g-1",
        email="new@gmail.com",
        verified=True,
        given_name=given,
        family_name=family,
    )

    assert await env.login("/") == "/", env.err
    assert len(env.fake.created) == 1
    profile = env.fake.created[0]["human"]["profile"]
    assert (profile["givenName"], profile["familyName"]) == want
    assert env.fake.session_user == NEW_USER_ID


def _not_linked(f: FakeZitadel) -> None:
    f.external = External(id="g-1", email="a@gmail.com", verified=True)


def _unverified(f: FakeZitadel) -> None:
    f.auto_linking = AUTO_LINKING_EMAIL
    f.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID, email="a@gmail.com")
    f.external = External(id="g-1", email="a@gmail.com")


def _several_matches(f: FakeZitadel) -> None:
    f.auto_linking = AUTO_LINKING_EMAIL
    f.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID, email="a@gmail.com")
    f.users["u2"] = User(id="u2", org_id="org-other", email="a@gmail.com")
    f.external = External(id="g-1", email="a@gmail.com", verified=True)


def _org_without_idp(f: FakeZitadel) -> None:
    f.auto_linking = AUTO_LINKING_EMAIL
    f.orgs["org-closed"] = Org(allow_external_idp=True)
    f.users["u1"] = User(id="u1", org_id="org-closed", email="a@gmail.com")
    f.external = External(id="g-1", email="a@gmail.com", verified=True)


def _outside_org(f: FakeZitadel) -> None:
    f.auth_request_scope = ["urn:zitadel:iam:org:id:org-customer"]
    f.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID)
    f.external = External(id="g-1", linked_to="u1")


def _inactive(f: FakeZitadel) -> None:
    f.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID, state=USER_STATE_INACTIVE)
    f.external = External(id="g-1", linked_to="u1")


def _force_mfa(f: FakeZitadel) -> None:
    f.orgs[DEFAULT_ORG_ID].force_mfa = True
    f.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID)
    f.external = External(id="g-1", linked_to="u1")


def _no_grant(f: FakeZitadel) -> None:
    f.callback_error = "Errors.User.GrantRequired (OIDC-foSyH49RvL)"
    f.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID)
    f.external = External(id="g-1", linked_to="u1")


@pytest.mark.parametrize(
    "setup, want, session",
    [
        (_not_linked, NotLinkedError, False),
        (_unverified, NotLinkedError, False),
        (_several_matches, NotLinkedError, False),
        (_org_without_idp, NotAllowedError, False),
        (_outside_org, NotAllowedError, False),
        (_inactive, UserInactiveError, False),
        (_force_mfa, MFARequiredError, False),
        # Zitadel checks the project grant when completing the auth request,
        # after the session exists.
        (_no_grant, AccessDeniedError, True),
    ],
    ids=[
        "not linked, no auto options",
        "auto-link needs a verified email",
        "auto-link with several matches",
        "auto-link into an org without the idp",
        "user outside the requested org",
        "inactive user",
        "org forces MFA",
        "no project grant",
    ],
)
async def test_refusals(
    env: Env, setup: Callable[[FakeZitadel], None], want: type[Exception], session: bool
) -> None:
    setup(env.fake)
    assert await env.login("/") == "/login?error=1"
    assert isinstance(env.err, want), env.err
    assert is_user_error(env.err), env.err
    if not session:
        assert env.fake.session_user == ""


async def test_cancelled_at_the_identity_provider(env: Env) -> None:
    _, cookies = await env.start("/")
    await env.follow(env.fake.failure_redirect("access_denied"), cookies)
    assert isinstance(env.err, IntentFailedError)


async def test_ticket_is_single_use(env: Env) -> None:
    env.fake.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID)
    env.fake.external = External(id="g-1", linked_to="u1")
    _, cookies = await env.start("/")
    success = env.fake.success_redirect()
    loc = await env.follow(success, cookies)
    assert urlsplit(loc).path == "/auth/callback", env.err
    await env.follow(success, cookies)
    assert isinstance(env.err, InvalidStateError)


async def test_forged_callback_is_rejected(env: Env) -> None:
    await env.follow(API + "/auth/google/idp/callback?rq=forged&id=x&token=y", None)
    assert isinstance(env.err, InvalidStateError)


async def test_code_needs_the_flow_cookie(env: Env) -> None:
    # The client's callback still checks state, nonce and PKCE against the
    # flow cookie of the browser that started the login.
    env.fake.users["u1"] = User(id="u1", org_id=DEFAULT_ORG_ID)
    env.fake.external = External(id="g-1", linked_to="u1")
    _, cookies = await env.start("/")
    loc = await env.follow(env.fake.success_redirect(), cookies)
    assert urlsplit(loc).path == "/auth/callback", env.err
    await env.follow(loc, None)
    assert isinstance(env.err, InvalidStateError)
    assert not env.results
