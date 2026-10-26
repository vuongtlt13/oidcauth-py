from __future__ import annotations

import time

import pytest
from conftest import ALICE, CLIENT_ID, COOKIE_SECRET, new_client, query

from oidcauth import (
    Client,
    Config,
    ConfigError,
    InvalidStateError,
    ProviderError,
    is_user_error,
)
from oidcauth.testing import Provider


async def test_login_round_trip(op: Provider, client: Client) -> None:
    auth_url, cookie = await client.start(return_to="/jobs?page=2")
    assert cookie.http_only and cookie.secure and cookie.max_age > 0
    params = op.authorize(auth_url, ALICE)
    assert client.cookie_name_for(params["state"]) == cookie.name

    res = await client.finish(params, cookie.value)
    id = res.identity
    assert (id.issuer, id.subject) == (op.issuer, "user-alice")
    assert id.email == "Alice@Example.com" and id.email_verified
    assert id.name == "Alice"
    assert id.preferred_username == "alice"  # userinfo-only claim merged
    assert id.has_role("admin") and id.roles == ["admin"]
    assert id.tokens.id_token and id.tokens.access_token
    assert res.return_to == "/jobs?page=2"


async def test_finish_rejects_state_mismatch_and_replay(
    op: Provider, client: Client
) -> None:
    auth_url, cookie = await client.start()
    params = op.authorize(auth_url, ALICE)

    # Cookie from another login flow.
    _, other = await client.start()
    with pytest.raises(InvalidStateError):
        await client.finish(params, other.value)
    # Tampered state.
    with pytest.raises(InvalidStateError):
        await client.finish(
            {"code": params["code"], "state": "x" + params["state"]}, cookie.value
        )
    # Missing cookie.
    with pytest.raises(InvalidStateError):
        await client.finish(params, "")
    # Valid once, the code cannot be replayed.
    await client.finish(params, cookie.value)
    with pytest.raises(Exception) as e:
        await client.finish(params, cookie.value)
    assert is_user_error(e.value)


async def test_finish_rejects_cookie_from_other_secret(op: Provider) -> None:
    a = new_client(op)
    b = new_client(op, cookie_secret="z" * 32)
    auth_url, cookie = await a.start()
    with pytest.raises(InvalidStateError):
        await b.finish(op.authorize(auth_url, ALICE), cookie.value)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(nonce="other"),
        lambda c: c.update(aud=["someone-else"], azp="someone-else"),
        lambda c: c.update(iss="https://evil.example.com"),
        lambda c: c.update(exp=int(time.time()) - 3600),
    ],
    ids=["nonce", "audience", "issuer", "expired"],
)
async def test_finish_verifies_id_token(op: Provider, mutate) -> None:  # type: ignore[no-untyped-def]
    op.mutate_id_token = mutate
    c = new_client(op)
    auth_url, cookie = await c.start()
    with pytest.raises(Exception) as e:
        await c.finish(op.authorize(auth_url, ALICE), cookie.value)
    assert is_user_error(e.value), e.value


async def test_finish_provider_error(op: Provider, client: Client) -> None:
    auth_url, cookie = await client.start()
    state = op.authorize(auth_url, ALICE)["state"]
    params = {"state": state, "error": "access_denied", "error_description": "no"}
    with pytest.raises(ProviderError) as e:
        await client.finish(params, cookie.value)
    assert e.value.code == "access_denied" and is_user_error(e.value)


async def test_start_with_extra_scopes_and_prompt(client: Client) -> None:
    auth_url, _ = await client.start(
        extra_scopes=["urn:zitadel:iam:org:id:42"], prompt=["login"]
    )
    q = query(auth_url)
    assert q["scope"] == "openid profile email urn:zitadel:iam:org:id:42"
    assert q["prompt"] == "login" and q["nonce"] and q["state"]


async def test_provider_unreachable_is_not_user_error() -> None:
    c = Client(
        Config(
            issuer="http://127.0.0.1:1",
            client_id=CLIENT_ID,
            redirect_url="https://app.example.com/cb",
            cookie_secret=COOKIE_SECRET,
        )
    )
    with pytest.raises(Exception) as e:
        await c.start()
    assert not is_user_error(e.value)
    await c.aclose()


async def test_unreachable_after_discovery_is_not_user_error(
    op: Provider, client: Client
) -> None:
    auth_url, cookie = await client.start()
    params = op.authorize(auth_url, ALICE)
    op.down = True
    with pytest.raises(Exception) as e:
        await client.finish(params, cookie.value)
    assert not is_user_error(e.value)


async def test_logout_url(op: Provider, client: Client) -> None:
    u = await client.logout_url("idt", "https://app.example.com/", "s1")
    assert u.startswith(op.issuer + "/oidc/v1/end_session?")
    assert query(u) == {
        "client_id": CLIENT_ID,
        "id_token_hint": "idt",
        "post_logout_redirect_uri": "https://app.example.com/",
        "state": "s1",
    }


def test_config_validate() -> None:
    with pytest.raises(ConfigError) as e:
        Client(Config(issuer="id.example.com", cookie_secret="short"))
    for want in ("issuer", "client id", "redirect url", "cookie secret"):
        assert want in str(e.value)
    assert isinstance(e.value, ValueError)
    with pytest.raises(ConfigError, match="openid"):
        Client(
            Config(
                issuer="https://id.example.com",
                client_id="c",
                redirect_url="https://a/cb",
                cookie_secret=COOKIE_SECRET,
                scopes=["profile"],
            )
        )
