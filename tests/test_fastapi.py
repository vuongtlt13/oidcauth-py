from __future__ import annotations

from http.cookies import SimpleCookie
from urllib.parse import urlencode

import httpx
from conftest import new_client, query
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response

from oidcauth import (
    InvalidStateError,
    LoginOptions,
    LogoutToken,
    ProviderUnreachableError,
    Result,
    safe_return_to,
)
from oidcauth.fastapi import OIDCHandler, default_error_handler
from oidcauth.testing import Provider, User

APP_URL = "https://app.example.com"


def asgi(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=APP_URL)


def cookies_of(resp: httpx.Response) -> dict[str, dict[str, str]]:
    """The Set-Cookie headers of resp: name -> attributes (lower-case keys,
    plus "value")."""
    out: dict[str, dict[str, str]] = {}
    for header in resp.headers.get_list("set-cookie"):
        jar: SimpleCookie = SimpleCookie()
        jar.load(header)
        for name, morsel in jar.items():
            attrs = {k: v for k, v in morsel.items() if v}
            attrs["value"] = morsel.value
            # SimpleCookie keeps flags as True; normalise.
            for flag in ("secure", "httponly"):
                if morsel[flag]:
                    attrs[flag] = "true"
            out[name] = attrs
    return out


def flow_cookie(resp: httpx.Response) -> tuple[str, dict[str, str]]:
    for name, attrs in cookies_of(resp).items():
        if name.startswith("oidc_flow_"):
            return name, attrs
    raise AssertionError(f"no flow cookie in {resp.headers.get_list('set-cookie')}")


async def test_login_callback(op: Provider) -> None:
    client = new_client(op)
    got: list[Result] = []

    def on_success(request: Request, res: Result) -> Response:
        got.append(res)
        return RedirectResponse(safe_return_to(res.return_to, "/"), 302)

    def on_error(request: Request, err: Exception) -> Response:
        return PlainTextResponse(str(err), status_code=401)

    h = OIDCHandler(client, on_success=on_success, on_error=on_error)
    app = FastAPI()
    app.add_api_route("/auth/login", h.login, methods=["GET"])
    app.add_api_route("/auth/callback", h.callback, methods=["GET"])

    async with asgi(app) as http:
        resp = await http.get("/auth/login", params={"redirect": "/jobs"})
        assert resp.status_code == 302
        assert resp.headers["cache-control"] == "no-store"
        name, attrs = flow_cookie(resp)
        assert attrs.get("httponly") and attrs.get("secure")
        assert attrs["samesite"].lower() == "lax"

        params = op.authorize(
            resp.headers["location"],
            User(subject="u1", email="u1@example.com", email_verified=True),
        )
        resp = await http.get(
            "/auth/callback?" + urlencode(params),
            headers={"cookie": f"{name}={attrs['value']}"},
        )
        assert resp.status_code == 302, resp.text
        assert resp.headers["location"] == "/jobs"
        assert resp.headers["cache-control"] == "no-store"
        assert got and got[0].identity.subject == "u1"
        assert got[0].identity.email == "u1@example.com"
        cleared = cookies_of(resp)[name]
        assert cleared["value"] == "" and cleared.get("max-age") == "0"

        # Replaying the same callback without a fresh flow fails, and still
        # clears the cookie.
        resp = await http.get("/auth/callback?" + urlencode(params))
        assert resp.status_code == 401
        assert name in cookies_of(resp)
        assert resp.headers["cache-control"] == "no-store"


async def test_form_post_callback(op: Provider) -> None:
    client = new_client(op)
    got: list[Result] = []

    async def on_success(request: Request, res: Result) -> Response:
        got.append(res)
        return Response(status_code=204)

    async def login_options(request: Request) -> LoginOptions:
        return LoginOptions(response_mode="form_post", return_to="link:7")

    h = OIDCHandler(client, on_success=on_success, login_options=login_options)
    app = FastAPI()
    app.add_api_route("/auth/login", h.login, methods=["GET"])
    app.add_api_route("/auth/callback", h.callback, methods=["POST"])

    async with asgi(app) as http:
        resp = await http.get("/auth/login", params={"redirect": "/jobs"})
        name, attrs = flow_cookie(resp)
        assert attrs["samesite"].lower() == "none" and attrs.get("secure")
        location = resp.headers["location"]
        assert query(location)["response_mode"] == "form_post"
        params = op.authorize(location, User(subject="u1"))

        resp = await http.post(
            "/auth/callback",
            data=params,
            headers={"cookie": f"{name}={attrs['value']}"},
        )
        assert resp.status_code == 204, resp.text
        assert got and got[0].identity.subject == "u1"
        # A return_to set by login_options wins over the query parameter.
        assert got[0].return_to == "link:7"


async def test_login_error_goes_to_on_error(op: Provider) -> None:
    op.down = True
    h = OIDCHandler(new_client(op), on_success=lambda r, res: Response())
    app = FastAPI()
    app.add_api_route("/auth/login", h.login, methods=["GET"])
    async with asgi(app) as http:
        resp = await http.get("/auth/login")
    assert resp.status_code == 502
    assert resp.text == "identity provider unavailable"


async def test_backchannel_logout(op: Provider) -> None:
    ended: list[LogoutToken] = []

    async def end(request: Request, token: LogoutToken) -> None:
        ended.append(token)

    h = OIDCHandler(new_client(op), on_success=lambda r, res: Response())
    app = FastAPI()
    app.add_api_route(
        "/auth/backchannel-logout", h.backchannel_logout(end), methods=["POST"]
    )

    async with asgi(app) as http:

        async def post(token: str) -> httpx.Response:
            data = {"logout_token": token} if token else {}
            return await http.post("/auth/backchannel-logout", data=data)

        resp = await post(op.logout_token("u1", "sid-1"))
        assert resp.status_code == 200
        assert resp.headers["cache-control"] == "no-store"
        assert len(ended) == 1
        assert ended[0].subject == "u1" and ended[0].session_id == "sid-1"

        def no_events(c: dict[str, object]) -> None:
            del c["events"]

        for token in ("", "not-a-jwt", op.logout_token("u1", mutate=no_events)):
            resp = await post(token)
            assert resp.status_code == 400, token
            assert resp.json() == {"error": "invalid_request"}
        assert len(ended) == 1, "invalid tokens must not end sessions"


async def test_backchannel_logout_failures(op: Provider) -> None:
    def fail(request: Request, token: LogoutToken) -> None:
        raise RuntimeError("db down")

    h = OIDCHandler(new_client(op), on_success=lambda r, res: Response())
    # A client that has not loaded the provider keys yet.
    cold = OIDCHandler(new_client(op), on_success=lambda r, res: Response())
    app = FastAPI()
    app.add_api_route("/logout", h.backchannel_logout(fail), methods=["POST"])
    app.add_api_route("/cold", cold.backchannel_logout(fail), methods=["POST"])
    token = op.logout_token("u1")
    async with asgi(app) as http:
        resp = await http.post("/logout", data={"logout_token": token})
        assert resp.status_code == 501
        assert resp.json() == {"error": "logout_failed"}

        op.down = True
        resp = await http.post("/cold", data={"logout_token": token})
        assert resp.status_code == 502
        assert resp.json() == {"error": "temporarily_unavailable"}


def test_default_error_handler() -> None:
    request = Request({"type": "http", "method": "GET", "headers": []})
    assert default_error_handler(request, InvalidStateError()).status_code == 401
    unreachable = ProviderUnreachableError("token", ConnectionError())
    assert default_error_handler(request, unreachable).status_code == 502
    assert default_error_handler(request, RuntimeError()).status_code == 502
