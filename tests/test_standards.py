from __future__ import annotations

import dataclasses
import json
import time
from datetime import timedelta
from typing import Any

import pytest
from conftest import (
    ALICE,
    BOB,
    CLIENT_ID,
    CLIENT_SECRET,
    COOKIE_SECRET,
    login,
    must_login,
    new_client,
    query,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from oidcauth import (
    AUTH_METHOD_CLIENT_SECRET_BASIC,
    AUTH_METHOD_CLIENT_SECRET_POST,
    AUTH_METHOD_NONE,
    AUTH_METHOD_PRIVATE_KEY_JWT,
    BACKCHANNEL_LOGOUT_EVENT,
    DISPLAY_POPUP,
    PROMPT_CONSENT,
    PROMPT_LOGIN,
    RESPONSE_MODE_FORM_POST,
    RESPONSE_MODE_QUERY,
    SCOPE_ADDRESS,
    SCOPE_EMAIL,
    SCOPE_OFFLINE_ACCESS,
    SCOPE_PHONE,
    SCOPE_PROFILE,
    TOKEN_TYPE_HINT_REFRESH,
    ClaimRequest,
    ClaimsRequest,
    Client,
    Config,
    ConfigError,
    InvalidLogoutTokenError,
    is_user_error,
)
from oidcauth.testing import Provider


async def test_scopes_control_claims(op: Provider, client: Client) -> None:
    id = await must_login(client, op, BOB)
    assert op.last_auth_request["scope"] == "openid profile email"
    assert id.tokens.scopes == ["openid", "profile", "email"]
    assert id.tokens.has_scope("email")
    assert id.email == "bob@example.com" and id.given_name == "Bob"
    assert id.claims["tenant"] == "t1"
    assert id.phone_number == "" and id.address is None

    id = await must_login(client, op, BOB, extra_scopes=[SCOPE_PHONE, SCOPE_ADDRESS])
    assert id.phone_number == "+84901234567" and id.phone_number_verified
    assert id.address is not None
    assert (id.address.locality, id.address.country) == ("Ha Noi", "VN")
    assert id.tokens.has_scope(SCOPE_PHONE) and id.tokens.has_scope(SCOPE_ADDRESS)


async def test_granted_scopes_may_be_fewer(op: Provider, client: Client) -> None:
    op.grant_scopes = lambda req: [s for s in req if s != SCOPE_EMAIL]
    id = await must_login(client, op, BOB)
    assert not id.tokens.has_scope(SCOPE_EMAIL) and id.email == ""
    assert id.tokens.has_scope(SCOPE_PROFILE)

    # Without `scope` in the token response the requested scopes are assumed.
    op.omit_scope_in_response = True
    op.grant_scopes = None
    id = await must_login(client, op, BOB, scopes=[SCOPE_EMAIL])
    assert id.tokens.scopes == ["openid", "email"]
    assert id.name == ""


async def test_authorization_request_parameters(client: Client) -> None:
    auth_url, _ = await client.start(
        scopes=[SCOPE_EMAIL, SCOPE_OFFLINE_ACCESS, SCOPE_EMAIL],
        prompt=[PROMPT_LOGIN, PROMPT_CONSENT],
        login_hint="bob@example.com",
        id_token_hint="old-id-token",
        max_age=timedelta(seconds=90),
        acr_values=["urn:mfa", "urn:pwd"],
        ui_locales=["vi", "en"],
        claims_locales=["vi"],
        display=DISPLAY_POPUP,
        response_mode=RESPONSE_MODE_QUERY,
        claims=ClaimsRequest(
            id_token={"email": ClaimRequest(essential=True), "auth_time": None}
        ),
        params={"organization": "acme"},
    )
    q = query(auth_url)
    want = {
        "scope": "openid email offline_access",
        "prompt": "login consent",
        "login_hint": "bob@example.com",
        "id_token_hint": "old-id-token",
        "max_age": "90",
        "acr_values": "urn:mfa urn:pwd",
        "ui_locales": "vi en",
        "claims_locales": "vi",
        "display": "popup",
        "response_mode": "query",
        "organization": "acme",
        "response_type": "code",
        "code_challenge_method": "S256",
        "client_id": CLIENT_ID,
    }
    for k, v in want.items():
        assert q.get(k) == v, k
    claims = json.loads(q["claims"])
    assert "auth_time" in claims["id_token"]
    assert claims["id_token"]["auth_time"] is None
    assert claims["id_token"]["email"]["essential"] is True


@pytest.mark.parametrize(
    "options",
    [
        {"params": {"state": "x"}},
        {"params": {"nonce": "x"}},
        {"params": {"scope": "x"}},
        {"params": {"redirect_uri": "https://evil"}},
        {"response_mode": "fragment"},
        {"max_age": timedelta(seconds=-1)},
    ],
)
async def test_start_rejects_invalid_options(
    client: Client, options: dict[str, Any]
) -> None:
    with pytest.raises(ValueError):
        await client.start(**options)


async def test_max_age_checks_auth_time(op: Provider, client: Client) -> None:
    recent = dataclasses.replace(BOB, auth_time=int(time.time()) - 60)
    id = await must_login(client, op, recent, max_age=timedelta(minutes=5))
    assert id.auth_time is not None
    assert int(id.auth_time.timestamp()) == recent.auth_time

    stale = dataclasses.replace(BOB, auth_time=int(time.time()) - 3600)
    with pytest.raises(Exception) as e:
        await login(client, op, stale, max_age=timedelta(minutes=5))
    assert is_user_error(e.value)
    # Without max_age the same login is fine.
    await login(client, op, stale)

    # max_age from Config, and auth_time is then required.
    c = new_client(op, max_age=timedelta(minutes=10))
    op.mutate_id_token = lambda claims: claims.pop("auth_time", None)  # type: ignore[func-returns-value]
    with pytest.raises(Exception) as e:
        await login(c, op, BOB)
    assert is_user_error(e.value)
    assert op.last_auth_request["max_age"] == "600"


async def test_require_acr(op: Provider) -> None:
    c = new_client(op, acr_values=["urn:mfa"], require_acr=True)
    id = await must_login(c, op, BOB)  # the provider echoes the first acr_values
    assert id.acr == "urn:mfa" and id.amr == ["pwd", "otp"] and id.session_id

    weak = dataclasses.replace(BOB, acr="urn:pwd")
    with pytest.raises(Exception) as e:
        await login(c, op, weak)
    assert is_user_error(e.value)
    # A per-request override is enforced too.
    await login(c, op, weak, acr_values=["urn:pwd"])
    # Without require_acr acr_values is only a hint.
    c = new_client(op, acr_values=["urn:mfa"])
    await login(c, op, weak)


async def test_finish_rejects_issuer_mix_up(op: Provider, client: Client) -> None:
    auth_url, cookie = await client.start()
    params = op.authorize(auth_url, BOB)
    params["iss"] = "https://evil.example.com"
    with pytest.raises(Exception) as e:
        await client.finish(params, cookie.value)
    assert is_user_error(e.value)
    # iss is optional (RFC 9207 only when the provider supports it).
    auth_url, cookie = await client.start()
    params = op.authorize(auth_url, BOB)
    del params["iss"]
    await client.finish(params, cookie.value)


async def test_form_post_flow_cookie(client: Client) -> None:
    _, cookie = await client.start(response_mode=RESPONSE_MODE_FORM_POST)
    assert cookie.same_site == "none" and cookie.secure and cookie.http_only


async def test_refresh(op: Provider, client: Client) -> None:
    # No offline_access, no refresh token.
    assert (await must_login(client, op, BOB)).tokens.refresh_token == ""

    id = await must_login(client, op, BOB, extra_scopes=[SCOPE_OFFLINE_ACCESS])
    first = id.tokens.refresh_token
    assert first
    res = await client.refresh(first)
    assert res.tokens.access_token and res.tokens.access_token != id.tokens.access_token
    assert res.tokens.refresh_token and res.tokens.refresh_token != first
    assert res.tokens.has_scope(SCOPE_OFFLINE_ACCESS)
    assert res.tokens.has_scope(SCOPE_EMAIL)
    assert res.identity is not None
    assert (res.identity.subject, res.identity.email) == (BOB.subject, BOB.email)
    assert res.identity.tokens.id_token

    # A rotated refresh token is single use.
    with pytest.raises(Exception) as e:
        await client.refresh(first)
    assert is_user_error(e.value)
    with pytest.raises(Exception) as e:
        await client.refresh("")
    assert is_user_error(e.value)

    # Providers may omit the ID token on refresh.
    op.refresh_without_id_token = True
    res = await client.refresh(res.tokens.refresh_token)
    assert res.identity is None and res.tokens.id_token == ""
    assert res.tokens.access_token


async def test_refresh_rejects_forged_id_token(op: Provider, client: Client) -> None:
    id = await must_login(client, op, BOB, extra_scopes=[SCOPE_OFFLINE_ACCESS])
    op.mutate_id_token = lambda c: c.update(aud=["other"], azp="other")
    with pytest.raises(Exception) as e:
        await client.refresh(id.tokens.refresh_token)
    assert is_user_error(e.value)


async def test_revoke(op: Provider, client: Client) -> None:
    id = await must_login(client, op, BOB, extra_scopes=[SCOPE_OFFLINE_ACCESS])
    await client.revoke(id.tokens.refresh_token, TOKEN_TYPE_HINT_REFRESH)
    assert id.tokens.refresh_token in op.revoked
    with pytest.raises(Exception):
        await client.refresh(id.tokens.refresh_token)


async def test_userinfo(op: Provider, client: Client) -> None:
    id = await must_login(client, op, ALICE)
    claims = await client.userinfo(id.tokens.access_token, ALICE.subject)
    assert claims["sub"] == ALICE.subject and claims["email"] == ALICE.email
    assert claims["preferred_username"] == "alice"
    with pytest.raises(Exception):
        await client.userinfo(id.tokens.access_token, "someone-else")
    with pytest.raises(Exception):
        await client.userinfo("bogus", ALICE.subject)


async def test_skip_userinfo(op: Provider) -> None:
    c = new_client(op, skip_userinfo=True)
    id = await must_login(c, op, ALICE)
    assert id.preferred_username == "" and id.email == ALICE.email


async def test_logout_url_options(op: Provider) -> None:
    c = new_client(op, post_logout_redirect_url="https://app.example.com/bye")
    u = await c.logout_url(logout_hint="bob@example.com", ui_locales=["vi", "en"])
    q = query(u)
    assert q["logout_hint"] == "bob@example.com" and q["ui_locales"] == "vi en"
    assert q["post_logout_redirect_uri"] == "https://app.example.com/bye"
    assert "id_token_hint" not in q and "state" not in q


async def test_verify_logout_token(op: Provider, client: Client) -> None:
    lt = await client.verify_logout_token(op.logout_token("user-bob", "sid-1"))
    assert (lt.issuer, lt.subject, lt.session_id) == (op.issuer, "user-bob", "sid-1")
    assert lt.jwt_id and lt.expiry.timestamp() > time.time()
    await client.verify_logout_token(op.logout_token("", "sid-only"))
    await client.verify_logout_token(op.logout_token("sub-only", ""))

    other = Provider(CLIENT_ID, CLIENT_SECRET)
    past, future = int(time.time()) - 3600, int(time.time()) + 3600
    cases = {
        "no event": op.logout_token("u", mutate=lambda c: c.pop("events")),
        "event not obj": op.logout_token(
            "u", mutate=lambda c: c.update(events={BACKCHANNEL_LOGOUT_EVENT: "x"})
        ),
        "nonce": op.logout_token("u", mutate=lambda c: c.update(nonce="n")),
        "audience": op.logout_token("u", mutate=lambda c: c.update(aud=["other"])),
        "issuer": op.logout_token(
            "u", mutate=lambda c: c.update(iss="https://evil.example.com")
        ),
        "expired": op.logout_token("u", mutate=lambda c: c.update(exp=past)),
        "future iat": op.logout_token("u", mutate=lambda c: c.update(iat=future)),
        "no jti": op.logout_token("u", mutate=lambda c: c.pop("jti")),
        "no sub nor sid": op.logout_token(),
        "foreign key": other.logout_token(
            "u", mutate=lambda c: c.update(iss=op.issuer)
        ),
        "garbage": "a.b.c",
    }
    for name, raw in cases.items():
        with pytest.raises(InvalidLogoutTokenError):
            await client.verify_logout_token(raw)
            pytest.fail(name)


async def test_client_secret_basic(op: Provider, client: Client) -> None:
    await must_login(client, op, BOB)
    assert op.last_client_auth == AUTH_METHOD_CLIENT_SECRET_BASIC


async def test_client_secret_post(op: Provider) -> None:
    c = new_client(op, token_endpoint_auth_method=AUTH_METHOD_CLIENT_SECRET_POST)
    id = await must_login(c, op, BOB, extra_scopes=[SCOPE_OFFLINE_ACCESS])
    assert op.last_client_auth == AUTH_METHOD_CLIENT_SECRET_POST
    await c.refresh(id.tokens.refresh_token)
    assert op.last_client_auth == AUTH_METHOD_CLIENT_SECRET_POST


async def test_client_auth_none() -> None:
    op = Provider(CLIENT_ID, "")
    c = new_client(op, client_secret="")
    await must_login(c, op, BOB)
    assert op.last_client_auth == AUTH_METHOD_NONE


def _pem(key: Any) -> bytes:
    return key.private_bytes(  # type: ignore[no-any-return]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


@pytest.mark.parametrize("kind", ["rsa", "ec"])
async def test_private_key_jwt(kind: str) -> None:
    key: Any = (
        rsa.generate_private_key(65537, 2048)
        if kind == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    op = Provider(CLIENT_ID, "", client_public_key=key.public_key())
    c = new_client(op, client_secret="", client_key=_pem(key), client_key_id="key-1")
    id = await must_login(c, op, BOB, extra_scopes=[SCOPE_OFFLINE_ACCESS])
    assert op.last_client_auth == AUTH_METHOD_PRIVATE_KEY_JWT
    res = await c.refresh(id.tokens.refresh_token)
    await c.revoke(res.tokens.refresh_token, TOKEN_TYPE_HINT_REFRESH)
    assert op.last_client_auth == AUTH_METHOD_PRIVATE_KEY_JWT

    # A key the provider does not know is rejected.
    op.client_public_key = rsa.generate_private_key(65537, 2048).public_key()
    with pytest.raises(Exception) as e:
        await login(c, op, BOB)
    assert is_user_error(e.value)


async def test_private_key_jwt_pem_string() -> None:
    key = rsa.generate_private_key(65537, 2048)
    op = Provider(CLIENT_ID, "", client_public_key=key.public_key())
    c = new_client(
        op, client_secret="", client_key=_pem(key).decode(), client_key_id="k"
    )
    await must_login(c, op, BOB)
    assert op.last_client_auth == AUTH_METHOD_PRIVATE_KEY_JWT


async def test_wrong_secret(op: Provider) -> None:
    c = new_client(op, client_secret="wrong")
    with pytest.raises(Exception) as e:
        await login(c, op, BOB)
    assert is_user_error(e.value)


async def test_discovery(op: Provider) -> None:
    c = new_client(op, discovery_url=op.issuer + "/.well-known/openid-configuration")
    d = await c.discovery()
    assert d["issuer"] == op.issuer
    assert SCOPE_OFFLINE_ACCESS in d["scopes_supported"]
    assert d["backchannel_logout_supported"] and d["revocation_endpoint"]


@pytest.mark.parametrize(
    "overrides,want",
    [
        ({"client_secret": "s", "client_key": b"k", "client_key_id": "1"}, "not both"),
        ({"client_key": b"k"}, "key id"),
        (
            {"token_endpoint_auth_method": AUTH_METHOD_CLIENT_SECRET_BASIC},
            "client secret",
        ),
        (
            {"token_endpoint_auth_method": AUTH_METHOD_CLIENT_SECRET_POST},
            "client secret",
        ),
        ({"token_endpoint_auth_method": AUTH_METHOD_PRIVATE_KEY_JWT}, "client key"),
        (
            {"token_endpoint_auth_method": AUTH_METHOD_NONE, "client_secret": "s"},
            "none",
        ),
        ({"token_endpoint_auth_method": "tls_client_auth"}, "unsupported"),
        ({"max_age": timedelta(seconds=-1)}, "max age"),
        ({"require_acr": True}, "acr"),
        ({"discovery_url": "/.well-known"}, "discovery url"),
        ({"client_key": b"not a pem", "client_key_id": "1"}, "PEM"),
    ],
)
def test_config_validate_client_auth(overrides: dict[str, Any], want: str) -> None:
    cfg = Config(
        issuer="https://id.example.com",
        client_id="c",
        redirect_url="https://a/cb",
        cookie_secret=COOKIE_SECRET,
        **overrides,
    )
    with pytest.raises(ConfigError, match=want):
        Client(cfg)


def test_public_client_config() -> None:
    Client(
        Config(
            issuer="https://id.example.com",
            client_id="c",
            redirect_url="https://a/cb",
            cookie_secret=COOKIE_SECRET,
        )
    )
