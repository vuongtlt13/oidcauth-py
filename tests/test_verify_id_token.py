from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

import pytest
from conftest import ALICE, BOB, CLIENT_ID, must_login

from oidcauth import Client, TokenError, UserInfoError, is_user_error
from oidcauth.testing import Provider

APP_ID = "native-app-1"


def id_token(op: Provider, **overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": op.issuer,
        "sub": "user-alice",
        "aud": [APP_ID],
        "azp": APP_ID,
        "iat": now,
        "exp": now + 3600,
        "email": "alice@example.com",
        "email_verified": True,
        "name": "Alice",
        "sid": "sid-1",
    }
    claims.update(overrides)
    return op.sign(claims)


async def test_verify_id_token_of_another_client(op: Provider, client: Client) -> None:
    raw = id_token(op, nonce="n-1")
    identity = await client.verify_id_token(raw, audience=APP_ID, nonce="n-1")
    assert (identity.issuer, identity.subject) == (op.issuer, "user-alice")
    assert identity.email == "alice@example.com" and identity.email_verified
    assert identity.session_id == "sid-1"
    assert identity.tokens.id_token == raw


async def test_verify_id_token_of_own_login_merges_userinfo(
    op: Provider, client: Client
) -> None:
    tokens = (await must_login(client, op, ALICE)).tokens
    identity = await client.verify_id_token(
        tokens.id_token, access_token=tokens.access_token
    )
    assert identity.subject == "user-alice"
    assert identity.preferred_username == "alice"  # userinfo-only claim
    # Without the access token, only the ID token claims
    identity = await client.verify_id_token(tokens.id_token)
    assert identity.preferred_username == ""


@pytest.mark.parametrize(
    "overrides, options",
    [
        ({"aud": [CLIENT_ID], "azp": CLIENT_ID}, {}),
        ({"aud": ["other"], "azp": "other"}, {}),
        ({"aud": [APP_ID, "other"], "azp": "other"}, {}),
        ({"iss": "https://evil.example.com"}, {}),
        ({"exp": int(time.time()) - 3600}, {}),
        ({"iat": int(time.time()) + 3600}, {}),
        ({"nonce": "other"}, {"nonce": "n-1"}),
        ({}, {"nonce": "n-1"}),
        ({"iat": int(time.time()) - 600}, {"max_age": timedelta(minutes=5)}),
    ],
    ids=[
        "audience-default-client",
        "audience",
        "azp",
        "issuer",
        "expired",
        "iat-future",
        "nonce",
        "nonce-missing",
        "max-age",
    ],
)
async def test_verify_id_token_rejects(
    op: Provider, client: Client, overrides: dict[str, Any], options: dict[str, Any]
) -> None:
    with pytest.raises(TokenError) as e:
        await client.verify_id_token(
            id_token(op, **overrides), audience=APP_ID, **options
        )
    assert is_user_error(e.value)


async def test_verify_id_token_rejects_foreign_signature(client: Client) -> None:
    other = Provider(APP_ID)  # same issuer, another key
    with pytest.raises(TokenError):
        await client.verify_id_token(id_token(other), audience=APP_ID)


async def test_verify_id_token_rejects_access_token_mismatch(
    op: Provider, client: Client
) -> None:
    tokens = (await must_login(client, op, ALICE)).tokens
    # The fake provider issues no at_hash: userinfo refuses the token
    with pytest.raises(UserInfoError):
        await client.verify_id_token(tokens.id_token, access_token="not-the-one")
    # Another user's access token: userinfo answers for the wrong subject
    bob = (await must_login(client, op, BOB)).tokens
    with pytest.raises(UserInfoError):
        await client.verify_id_token(tokens.id_token, access_token=bob.access_token)


async def test_verify_id_token_empty(client: Client) -> None:
    with pytest.raises(TokenError):
        await client.verify_id_token("")
