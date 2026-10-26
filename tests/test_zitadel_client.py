from __future__ import annotations

import httpx
import pytest

from oidcauth.zitadel import (
    APIError,
    AuthRequest,
    AuthRequestExpiredError,
    Client,
    ZitadelError,
    is_user_error,
)
from oidcauth.zitadel.login import _raise_auth_request_error

BASE = "https://id.test"


def authorize_server(request: httpx.Request) -> httpx.Response:
    case = request.url.params.get("case")
    if case == "login":
        return httpx.Response(
            302, headers={"Location": "/ui/v2/login/login?authRequest=V2_1"}
        )
    if case == "error":
        return httpx.Response(
            302, headers={"Location": "http://api.test/cb?error=invalid_scope&state=s"}
        )
    return httpx.Response(200, text="<html>login</html>")


async def test_authorize() -> None:
    c = Client(
        BASE, "pat", httpx.AsyncClient(transport=httpx.MockTransport(authorize_server))
    )

    assert await c.authorize(BASE + "/oauth/v2/authorize?case=login") == ("V2_1", "")

    # The client's error redirect, for the browser.
    assert await c.authorize(BASE + "/oauth/v2/authorize?case=error") == (
        "",
        "http://api.test/cb?error=invalid_scope&state=s",
    )

    # Login V1 or a misconfigured instance renders a page instead.
    with pytest.raises(APIError):
        await c.authorize(BASE + "/oauth/v2/authorize?case=page")


@pytest.mark.parametrize(
    "err, expired",
    [
        (APIError(404, "Errors.AuthRequest.NotFound"), True),
        (APIError(412, "Errors.AuthRequest.AlreadyHandled (OIDC-1)"), True),
        (APIError(403, "Errors.Token.Invalid"), False),
    ],
)
def test_auth_request_error(err: APIError, expired: bool) -> None:
    with pytest.raises(ZitadelError) as info:
        _raise_auth_request_error(err)
    assert isinstance(info.value, AuthRequestExpiredError) == expired
    if expired:
        assert info.value.__cause__ is err


def test_auth_request_org_id() -> None:
    assert (
        AuthRequest(id="1", scope=["openid", "urn:zitadel:iam:org:id:42"]).org_id()
        == "42"
    )
    assert AuthRequest(id="1", scope=["openid"]).org_id() == ""


async def test_api_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer pat"
        if request.url.path == "/v2/users/json":
            return httpx.Response(
                404, json={"code": 5, "message": "Errors.User.NotFound"}
            )
        if request.url.path == "/v2/users/text":
            return httpx.Response(500, text=" boom \n")
        raise httpx.ConnectError("refused", request=request)

    c = Client(
        BASE + "/", "pat", httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(APIError) as info:
        await c.get_user("json")
    assert (info.value.status, info.value.message) == (404, "Errors.User.NotFound")
    assert str(info.value) == "zitadel: 404 Errors.User.NotFound"
    assert is_user_error(info.value)

    with pytest.raises(APIError) as info:
        await c.get_user("text")
    assert info.value.message == "boom"
    assert not is_user_error(info.value)

    with pytest.raises(ZitadelError, match="zitadel: GET /v2/users/down: refused"):
        await c.get_user("down")
