"""FastAPI / Starlette adapter (needs the ``fastapi`` extra, or Starlette).

::

    async def on_success(request: Request, res: Result) -> Response:
        user = await users.from_identity(res.identity)  # the app decides
        token = sessions.issue(user)
        ticket = await tickets.put(token, 60)
        return RedirectResponse(
            "/auth/callback?" + urlencode({"ticket": ticket,
                "redirect": safe_return_to(res.return_to)}), 302)

    h = OIDCHandler(client, on_success=on_success)
    router.add_api_route("/api/v1/auth/oidc/login", h.login, methods=["GET"])
    router.add_api_route("/api/v1/auth/oidc/callback", h.callback,
                         methods=["GET", "POST"])  # POST only with form_post
    router.add_api_route("/api/v1/auth/oidc/backchannel-logout",
                         h.backchannel_logout(end_sessions), methods=["POST"])

Form bodies (form_post callbacks, back-channel logout) are parsed without
python-multipart.
"""

from __future__ import annotations

import dataclasses
import inspect
from typing import Any, Awaitable, Callable, TypeVar, Union
from urllib.parse import parse_qsl

from starlette.requests import Request
from starlette.responses import (
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)

from .client import Client, LoginOptions, LogoutToken, Result
from .errors import InvalidLogoutTokenError, is_user_error
from .flow import Cookie

T = TypeVar("T")
MaybeAwaitable = Union[T, Awaitable[T]]

SuccessHandler = Callable[[Request, Result], MaybeAwaitable[Response]]
ErrorHandler = Callable[[Request, Exception], MaybeAwaitable[Response]]
LoginOptionsFunc = Callable[[Request], MaybeAwaitable[LoginOptions]]
LogoutHandler = Callable[[Request, LogoutToken], MaybeAwaitable[None]]

NO_STORE = {"Cache-Control": "no-store"}


async def _resolve(value: MaybeAwaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return value


class OIDCHandler:
    """Login, callback and back-channel logout endpoints for one Client.

    on_success receives the verified login (required); it typically maps the
    identity to a local user, issues the app session and redirects.
    on_error handles any failure (start or callback); it defaults to
    default_error_handler's 401/502 plain text, SPAs usually redirect to their
    login page with an error code instead. login_options adds per-request
    authorization options; when it leaves return_to empty, return_to is the
    return_to_param query parameter.
    """

    def __init__(
        self,
        client: Client,
        *,
        on_success: SuccessHandler,
        on_error: ErrorHandler | None = None,
        login_options: LoginOptionsFunc | None = None,
        return_to_param: str = "redirect",
    ) -> None:
        if on_success is None:
            raise ValueError("oidcauth.fastapi: on_success is required")
        self.client = client
        self.on_success = on_success
        self.on_error: ErrorHandler = on_error or default_error_handler
        self.login_options = login_options
        self.return_to_param = return_to_param or "redirect"

    async def start_options(self, request: Request) -> LoginOptions:
        """The LoginOptions of a login request."""
        return await start_options(request, self.login_options, self.return_to_param)

    async def login(self, request: Request) -> Response:
        """Starts the authorization request and redirects to the provider."""
        try:
            auth_url, cookie = await self.client.start(
                await self.start_options(request)
            )
        except Exception as e:
            return await _resolve(self.on_error(request, e))
        resp = RedirectResponse(auth_url, status_code=302, headers=NO_STORE)
        set_cookie(resp, cookie)
        return resp

    async def callback(self, request: Request) -> Response:
        """Completes the login and calls on_success or on_error. Mount it on GET
        (response_mode=query) and, when form_post is used, on POST too."""
        params = await callback_values(request)
        state = params.get("state", "")
        cookie_value = (
            request.cookies.get(self.client.cookie_name_for(state)) if state else None
        )
        try:
            res = await self.client.finish(params, cookie_value)
        except Exception as e:
            resp = await _resolve(self.on_error(request, e))
        else:
            resp = await _resolve(self.on_success(request, res))
        resp.headers["Cache-Control"] = "no-store"
        if state:
            set_cookie(resp, self.client.clear_cookie(state))
        return resp

    def backchannel_logout(
        self, on_logout: LogoutHandler
    ) -> Callable[[Request], Awaitable[Response]]:
        """An endpoint for the back-channel logout URI registered at the
        provider (OpenID Connect Back-Channel Logout 1.0). It verifies the
        POSTed `logout_token` and calls on_logout, which ends the app sessions
        of LogoutToken.subject and/or LogoutToken.session_id. It answers 200 on
        success, 400 for an invalid token, 502 when the provider keys cannot
        be fetched and 501 when on_logout fails (the spec's error status),
        always with Cache-Control: no-store."""
        if on_logout is None:
            raise ValueError("oidcauth.fastapi: backchannel_logout needs on_logout")

        async def endpoint(request: Request) -> Response:
            raw = (await form_values(request)).get("logout_token", "")
            if not raw:
                return _json_error(400, "invalid_request")
            try:
                token = await self.client.verify_logout_token(raw)
            except InvalidLogoutTokenError:
                return _json_error(400, "invalid_request")
            except Exception:
                return _json_error(502, "temporarily_unavailable")
            try:
                await _resolve(on_logout(request, token))
            except Exception:
                return _json_error(501, "logout_failed")
            return Response(status_code=200, headers=NO_STORE)

        return endpoint


async def start_options(
    request: Request, login_options: LoginOptionsFunc | None, return_to_param: str
) -> LoginOptions:
    """The LoginOptions of a login request: those of login_options, with
    return_to defaulting to the return_to_param query parameter. A return_to
    set by login_options wins, so the app can sanitize the client value or
    replace it with a server-side marker (e.g. an account linking flow)."""
    o = LoginOptions()
    if login_options is not None:
        o = await _resolve(login_options(request))
    if o.return_to:
        return o
    return dataclasses.replace(
        o, return_to=request.query_params.get(return_to_param, "")
    )


def default_error_handler(request: Request, err: Exception) -> Response:
    """401 for login failures and 502 when the provider cannot be reached,
    without leaking internal details."""
    if is_user_error(err):
        return PlainTextResponse("login failed", status_code=401)
    return PlainTextResponse("identity provider unavailable", status_code=502)


async def form_values(request: Request) -> dict[str, str]:
    """The fields of an application/x-www-form-urlencoded body."""
    ctype = request.headers.get("content-type", "")
    if not ctype.startswith("application/x-www-form-urlencoded"):
        return {}
    body = (await request.body()).decode("utf-8", errors="replace")
    return dict(parse_qsl(body, keep_blank_values=True))


async def callback_values(request: Request) -> dict[str, str]:
    """The authorization response parameters: the query string, or the form
    body of a POST (response_mode=form_post)."""
    if request.method != "POST":
        return dict(request.query_params)
    return await form_values(request)


def set_cookie(response: Response, ck: Cookie) -> None:
    """Writes an oidcauth Cookie on a Starlette response."""
    kwargs: dict[str, Any] = {
        "path": ck.path,
        "secure": ck.secure,
        "httponly": ck.http_only,
        "samesite": ck.same_site,
    }
    if ck.max_age < 0:
        # Deletion: Max-Age=0 and an Expires in the past.
        kwargs.update(max_age=0, expires=0)
    else:
        kwargs["max_age"] = ck.max_age
    response.set_cookie(ck.name, ck.value, **kwargs)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _json_error(status: int, code: str) -> Response:
    return JSONResponse({"error": code}, status_code=status, headers=NO_STORE)


__all__ = [
    "OIDCHandler",
    "callback_values",
    "client_ip",
    "default_error_handler",
    "form_values",
    "set_cookie",
    "start_options",
]
