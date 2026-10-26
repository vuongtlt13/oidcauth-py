"""Serves the Zitadel identity provider login (IDPLogin) with FastAPI /
Starlette: the browser goes straight to the identity provider (e.g. Google),
the app plays Zitadel's login UI with a service user, and the login ends at
the client's usual callback (oidcauth.fastapi.OIDCHandler.callback), which
exchanges the code and verifies state, nonce and PKCE as for any login.

    browser -> login -> identity provider -> Zitadel -> callback
    -> client redirect URI (OIDCHandler.callback) -> on_success

Wiring, next to the OIDCHandler of the same client::

    api = zitadel.Client(client.config.issuer, service_pat)
    h = ZitadelIDPHandler(client, zitadel.IDPLogin(api, google_idp_id),
        tickets=tickets,
        callback_url="https://api.example.com/auth/google/idp/callback",
        on_error=on_error)  # see oidcauth.zitadel errors
    router.add_api_route("/auth/google/login", h.login, methods=["GET"])
    router.add_api_route("/auth/google/idp/callback", h.callback, methods=["GET"])
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response

from .. import errors as oidc_errors
from ..client import Client
from ..fastapi import (
    NO_STORE,
    ErrorHandler,
    LoginOptionsFunc,
    _resolve,
    client_ip,
    set_cookie,
    start_options,
)
from ..helpers import TicketStore
from .client import UserAgent
from .errors import IntentFailedError
from .errors import is_user_error as zitadel_is_user_error
from .login import IDPLogin

# Marks the tickets of this handler in a TicketStore shared with other uses.
TICKET_PREFIX = "zitadel-idp:"


class ZitadelIDPHandler:
    """Serves the identity provider login of one oidcauth Client.

    tickets carries the Zitadel auth request ID from login to callback; a
    ticket lives as long as the login flow (Config.flow_ttl). callback_url is
    the absolute URL of the callback route; login adds the ticket as query
    parameter ticket_param. on_error handles any failure before the client's
    callback: oidcauth errors of the login start, InvalidStateError for an
    unknown or used ticket, zitadel errors (NotLinkedError,
    IntentFailedError, ..., APIError) and network errors;
    oidcauth.zitadel.is_user_error tells refusals from Zitadel being
    unavailable. It defaults to default_error_handler's 401/502.
    """

    def __init__(
        self,
        client: Client,
        login: IDPLogin,
        *,
        tickets: TicketStore,
        callback_url: str,
        ticket_param: str = "rq",
        return_to_param: str = "redirect",
        login_options: LoginOptionsFunc | None = None,
        on_error: ErrorHandler | None = None,
    ) -> None:
        if tickets is None:
            raise ValueError("oidcauth.zitadel.fastapi: tickets is required")
        if not callback_url:
            raise ValueError("oidcauth.zitadel.fastapi: callback_url is required")
        self.client = client
        self.idp_login = login
        self.tickets = tickets
        self.callback_url = callback_url
        self.ticket_param = ticket_param or "rq"
        self.return_to_param = return_to_param or "redirect"
        self.login_options = login_options
        self.on_error: ErrorHandler = on_error or default_error_handler

    async def _error(self, request: Request, err: Exception) -> Response:
        resp = await _resolve(self.on_error(request, err))
        resp.headers["Cache-Control"] = "no-store"
        return resp

    async def login(self, request: Request) -> Response:
        """Starts the client's login, completes Zitadel's authorization
        request server side and redirects the browser to the identity
        provider. The flow cookie is set as by OIDCHandler.login, so the
        client's callback verifies the login as usual."""
        try:
            o = await start_options(request, self.login_options, self.return_to_param)
            auth_url, cookie = await self.client.start(o)
            auth_request_id, error_redirect = await self.idp_login.authorize(auth_url)
        except Exception as e:
            return await self._error(request, e)
        if not auth_request_id:
            # Zitadel rejected the authorization request: error_redirect is
            # the client's callback with the error, handled there.
            resp: Response = RedirectResponse(error_redirect, 302, headers=NO_STORE)
            set_cookie(resp, cookie)
            return resp
        try:
            # Lives as long as the login flow: the user is at the identity
            # provider meanwhile.
            ttl = self.client.config.flow_ttl
            assert ttl is not None
            ticket = await self.tickets.put(TICKET_PREFIX + auth_request_id, ttl)
            callback = self._callback_url(ticket)
            redirect = await self.idp_login.start_intent(callback, callback)
        except Exception as e:
            return await self._error(request, e)
        resp = RedirectResponse(redirect, 302, headers=NO_STORE)
        set_cookie(resp, cookie)
        return resp

    async def callback(self, request: Request) -> Response:
        """Where Zitadel returns after the identity provider login: query id
        and token on success, error and error_description on failure, plus the
        ticket. On success it completes the Zitadel auth request and redirects
        the browser to the client's redirect URI with the code."""
        q = request.query_params
        try:
            value = await self.tickets.take(q.get(self.ticket_param, ""))
        except oidc_errors.TicketNotFoundError as e:
            err = oidc_errors.InvalidStateError(str(e))
            err.__cause__ = e
            return await self._error(request, err)
        except Exception as e:
            return await self._error(request, e)
        if not value.startswith(TICKET_PREFIX):
            return await self._error(
                request, oidc_errors.InvalidStateError("not a zitadel login ticket")
            )
        auth_request_id = value[len(TICKET_PREFIX) :]
        code = q.get("error", "")
        if code or not q.get("id"):
            return await self._error(
                request, IntentFailedError(f"{code}: {q.get('error_description', '')}")
            )
        ua = UserAgent(
            ip=client_ip(request), description=request.headers.get("user-agent", "")
        )
        try:
            callback = await self.idp_login.finish(
                auth_request_id, q.get("id", ""), q.get("token", ""), ua
            )
        except Exception as e:
            return await self._error(request, e)
        return RedirectResponse(callback, 302, headers=NO_STORE)

    def _callback_url(self, ticket: str) -> str:
        u = urlsplit(self.callback_url)
        query = [
            (k, v)
            for k, v in parse_qsl(u.query, keep_blank_values=True)
            if k != self.ticket_param
        ]
        query.append((self.ticket_param, ticket))
        return urlunsplit(u._replace(query=urlencode(query)))


def default_error_handler(request: Request, err: Exception) -> Response:
    """401 for refusals and 502 when the provider or Zitadel is unavailable,
    without leaking internal details."""
    if (
        oidc_errors.is_user_error(err)
        or zitadel_is_user_error(err)
        or isinstance(err, oidc_errors.TicketNotFoundError)
    ):
        return PlainTextResponse("login failed", status_code=401)
    return PlainTextResponse("identity provider unavailable", status_code=502)


__all__ = ["TICKET_PREFIX", "ZitadelIDPHandler", "default_error_handler"]
