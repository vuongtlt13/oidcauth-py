from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest

from oidcauth import Client, Config, Identity, Result
from oidcauth.testing import Provider, User

CLIENT_ID = "client-1"
CLIENT_SECRET = "secret-1"
COOKIE_SECRET = "0123456789abcdef0123456789abcdef"
REDIRECT_URL = "https://app.example.com/api/v1/auth/oidc/callback"

ALICE = User(
    subject="user-alice",
    email="Alice@Example.com",
    email_verified=True,
    name="Alice",
    roles=["admin"],
    userinfo_only={"preferred_username": "alice"},
)

BOB = User(
    subject="user-bob",
    email="bob@example.com",
    email_verified=True,
    name="Bob",
    phone_number="+84901234567",
    phone_verified=True,
    address={"locality": "Ha Noi", "country": "VN"},
    amr=["pwd", "otp"],
    extra={"given_name": "Bob", "tenant": "t1"},
)


def new_client(op: Provider, **overrides: Any) -> Client:
    cfg = Config(
        issuer=op.issuer,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_url=REDIRECT_URL,
        cookie_secret=COOKIE_SECRET,
        http_client=op.http_client(),
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return Client(cfg)


async def login(c: Client, op: Provider, user: User, **options: Any) -> Result:
    auth_url, cookie = await c.start(**options)
    return await c.finish(op.authorize(auth_url, user), cookie.value)


async def must_login(c: Client, op: Provider, user: User, **options: Any) -> Identity:
    return (await login(c, op, user, **options)).identity


def query(url: str) -> dict[str, str]:
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


@pytest.fixture
def op() -> Provider:
    return Provider(CLIENT_ID, CLIENT_SECRET)


@pytest.fixture
def client(op: Provider) -> Client:
    return new_client(op)
