"""The relying party: login, tokens and logout."""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import json
import math
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote_plus, urlencode, urlsplit, urlunsplit

import httpx
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from joserfc import jwk, jws, jwt
from joserfc.errors import InvalidKeyIdError, JoseError

from .config import (
    AUTH_METHOD_AUTO,
    AUTH_METHOD_CLIENT_SECRET_BASIC,
    AUTH_METHOD_CLIENT_SECRET_POST,
    AUTH_METHOD_NONE,
    AUTH_METHOD_PRIVATE_KEY_JWT,
    Config,
)
from .errors import (
    ConfigError,
    DiscoveryError,
    InvalidLogoutTokenError,
    InvalidStateError,
    MissingCodeError,
    NotSupportedError,
    OIDCAuthError,
    ProviderError,
    ProviderUnreachableError,
    TokenError,
    UserInfoError,
    classify,
)
from .flow import Cookie, Flow, FlowCodec, random_token
from .identity import Identity, Tokens, identity_from_claims
from .scopes import RESPONSE_MODE_FORM_POST, RESPONSE_MODE_QUERY, SCOPE_OPENID

# Tolerated clock difference between the provider and the app on exp/iat.
CLOCK_SKEW = 30
# Tolerated clock difference when checking auth_time against max_age.
AUTH_TIME_SKEW = 30
# Tolerated clock difference on the iat/exp of a logout token.
LOGOUT_TOKEN_SKEW = 60

# Event member of a back-channel logout token.
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

# Asymmetric signature algorithms an ID token may use; "none" and HMAC never.
_SIGNING_ALGS = {
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
}

# Parameters with a dedicated option, or that the caller must not set.
RESERVED_PARAMS = frozenset(
    {
        "client_id",
        "redirect_uri",
        "response_type",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
        "scope",
        "prompt",
        "max_age",
        "acr_values",
        "id_token_hint",
        "login_hint",
        "ui_locales",
        "claims_locales",
        "display",
        "response_mode",
        "claims",
        "request",
        "request_uri",
    }
)

# Claims of the verified ID token that userinfo never overrides.
PROTECTED_CLAIMS = frozenset(
    {
        "iss",
        "sub",
        "aud",
        "azp",
        "exp",
        "iat",
        "nbf",
        "nonce",
        "auth_time",
        "acr",
        "amr",
        "at_hash",
        "c_hash",
        "sid",
        "jti",
    }
)


@dataclass
class LoginOptions:
    """Customises one authorization request (OpenID Connect Core 1.0, section
    3.1.2.1). Every field is optional."""

    # Application value (usually a relative path to go back to) stored in the
    # flow cookie and handed back by finish. Sanitize it with safe_return_to
    # before redirecting.
    return_to: str = ""
    # Replaces Config.scopes for this request; "openid" is added when missing.
    scopes: list[str] | None = None
    # Appended for this request only, e.g. "phone", or the Zitadel
    # `urn:zitadel:iam:org:id:<org>` scope to pin the login to one org.
    extra_scopes: list[str] = field(default_factory=list)
    # `prompt`: none, login, consent, select_account, create.
    prompt: list[str] = field(default_factory=list)
    # Pre-fills the provider login form.
    login_hint: str = ""
    # A previously issued ID token, typically with prompt none for a silent
    # re-authentication.
    id_token_hint: str = ""
    # `max_age`: the provider must re-authenticate the user when the last
    # authentication is older. finish then requires and checks `auth_time`.
    # timedelta(0) forces re-authentication, like prompt login, but verifiably.
    max_age: timedelta | None = None
    # Requested authentication context classes, in order of preference.
    # Defaults to Config.acr_values.
    acr_values: list[str] | None = None
    ui_locales: list[str] = field(default_factory=list)
    claims_locales: list[str] = field(default_factory=list)
    # page, popup, touch or wap.
    display: str = ""
    # "query" (default for the code flow) or "form_post". form_post makes the
    # provider POST the callback; the flow cookie of that login is then
    # SameSite=None (a Lax cookie is not sent on a cross-site POST), which
    # needs HTTPS.
    response_mode: str = ""
    # The `claims` request parameter (section 5.5).
    claims: Any = None
    # Custom authorization request parameters. RESERVED_PARAMS cannot be set
    # this way; start raises ValueError.
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class Result:
    """A verified login."""

    identity: Identity
    # The value of LoginOptions.return_to, unsanitized.
    return_to: str = ""


@dataclass
class RefreshResult:
    """The outcome of a refresh_token grant."""

    # The new tokens. refresh_token keeps the old value when the provider did
    # not rotate it.
    tokens: Tokens
    # Rebuilt from the refreshed ID token (merged with userinfo) when the
    # provider returned one. The caller checks its subject against the
    # previous one.
    identity: Identity | None = None


@dataclass
class LogoutToken:
    """A verified back-channel logout request (OpenID Connect Back-Channel
    Logout 1.0). The app ends the sessions it holds for subject (all of them)
    or for session_id (that provider session only), whichever is set; both may
    be."""

    issuer: str
    subject: str
    session_id: str
    # Identifies the token. Reject a jwt_id seen before the token's expiry to
    # stop replays.
    jwt_id: str
    issued_at: datetime
    expiry: datetime
    claims: dict[str, Any]


class _InvalidToken(ValueError):
    """A token failed verification."""


class Client:
    """An OpenID Connect relying party for browser login (authorization code
    flow + PKCE + state + nonce).

    The client verifies the provider response and returns an Identity. It does
    not touch the user table and does not issue session tokens: what to do with
    the identity (link, provision, reject) and how to keep the user signed in
    is the application's decision.

    Provider discovery happens lazily on first use (and is retried until it
    succeeds), so an unreachable provider never prevents the application from
    starting. Safe for concurrent use within one event loop.
    """

    def __init__(self, cfg: Config, *, now: Callable[[], float] = time.time) -> None:
        cfg = cfg.with_defaults()
        cfg.validate()
        self._cfg = cfg
        self._now = now
        self._flows = FlowCodec(cfg, now)
        self._own_http = cfg.http_client is None
        self._http = cfg.http_client or httpx.AsyncClient(timeout=15.0)
        self._signing_key: Any = None
        self._signing_alg = ""
        if cfg.client_key:
            key = cfg.client_key
            self._signing_key, self._signing_alg = _load_client_key(
                key.encode() if isinstance(key, str) else key
            )
        self._lock = asyncio.Lock()
        self._discovery: dict[str, Any] | None = None
        self._keys: jwk.KeySet | None = None

    @property
    def config(self) -> Config:
        """The effective configuration (with defaults applied)."""
        return self._cfg

    async def aclose(self) -> None:
        """Closes the HTTP client when the library created it."""
        if self._own_http:
            await self._http.aclose()

    async def init(self) -> None:
        """Eagerly runs provider discovery. Optional: useful as a readiness
        check."""
        await self._meta()

    async def discovery(self) -> dict[str, Any]:
        """The provider metadata (OpenID Connect Discovery 1.0), e.g. to check
        scopes_supported or backchannel_logout_supported."""
        return dict(await self._meta())

    # -- login ---------------------------------------------------------------

    def requested_scopes(self, o: LoginOptions) -> list[str]:
        """Config.scopes, or the per-request override, plus extra scopes,
        de-duplicated with openid first."""
        base = self._cfg.scopes if o.scopes is None else o.scopes
        out = [SCOPE_OPENID]
        for s in [*base, *o.extra_scopes]:
            s = s.strip()
            if s and s not in out:
                out.append(s)
        return out

    async def start(
        self, options: LoginOptions | None = None, /, **kwargs: Any
    ) -> tuple[str, Cookie]:
        """Begins a login. The caller sets the returned cookie on the response
        and redirects the browser to the returned authorization URL. Options
        come as a LoginOptions, keyword arguments of LoginOptions, or both."""
        o = dataclasses.replace(options or LoginOptions(), **kwargs)
        for k in o.params:
            if k in RESERVED_PARAMS:
                raise ValueError(
                    f'oidcauth: parameter "{k}" cannot be set with LoginOptions.params'
                )
        if o.response_mode not in ("", RESPONSE_MODE_QUERY, RESPONSE_MODE_FORM_POST):
            raise ValueError(f'oidcauth: unsupported response_mode "{o.response_mode}"')
        max_age = o.max_age
        if max_age is None and self._cfg.max_age and self._cfg.max_age > timedelta(0):
            max_age = self._cfg.max_age
        if max_age is not None and max_age < timedelta(0):
            raise ValueError("oidcauth: max_age must not be negative")
        acr_values = self._cfg.acr_values if o.acr_values is None else o.acr_values

        meta = await self._meta()

        scopes = self.requested_scopes(o)
        f = Flow(
            state=random_token(),
            nonce=random_token(),
            verifier=random_token(),
            return_to=o.return_to,
            scope=" ".join(scopes),
            issued_at=int(self._now()),
        )
        if max_age is not None:
            f.max_age = int(math.floor(max_age.total_seconds() + 0.5))
        if self._cfg.require_acr:
            f.acr = list(acr_values)
        cookie = self._flows.encode(f, o.response_mode == RESPONSE_MODE_FORM_POST)

        params: list[tuple[str, str]] = [
            ("response_type", "code"),
            ("client_id", self._cfg.client_id),
            ("redirect_uri", self._cfg.redirect_url),
            ("state", f.state),
            ("nonce", f.nonce),
            ("scope", f.scope),
            ("code_challenge", _s256(f.verifier)),
            ("code_challenge_method", "S256"),
        ]

        def put(key: str, value: str) -> None:
            if value:
                params.append((key, value))

        put("prompt", " ".join(o.prompt))
        put("login_hint", o.login_hint)
        put("id_token_hint", o.id_token_hint)
        if f.max_age is not None:
            put("max_age", str(f.max_age))
        put("acr_values", " ".join(acr_values))
        put("ui_locales", " ".join(o.ui_locales))
        put("claims_locales", " ".join(o.claims_locales))
        put("display", o.display)
        put("response_mode", o.response_mode)
        if o.claims is not None:
            claims = o.claims.to_json() if hasattr(o.claims, "to_json") else o.claims
            put("claims", json.dumps(claims, separators=(",", ":")))
        for k, v in o.params.items():
            put(k, v)
        return _add_query(meta["authorization_endpoint"], params), cookie

    async def finish(
        self, params: Mapping[str, str], cookie_value: str | None
    ) -> Result:
        """Completes a login from the callback parameters (the query, or the
        form body with form_post) and the flow cookie value (looked up with
        cookie_name_for(params["state"])). The caller always sets
        clear_cookie(state) on the response, whatever the outcome.

        It verifies state, exchanges the code with the PKCE verifier, validates
        the ID token (signature via JWKS, iss, aud, azp, exp, iat, nonce,
        at_hash), checks auth_time when max_age was requested and acr when
        Config.require_acr is set, and, unless skip_userinfo is set, merges
        userinfo claims.
        """
        state = params.get("state") or ""
        if not state or not cookie_value:
            raise InvalidStateError()
        f = self._flows.decode(state, cookie_value)
        iss = params.get("iss") or ""
        if iss and iss != self._cfg.issuer:
            # RFC 9207 authorization server issuer identification: a response
            # from another issuer is a mix-up attack.
            raise TokenError(
                "authorization response", f'iss "{iss}" does not match issuer'
            )
        error = params.get("error") or ""
        if error:
            raise ProviderError(error, params.get("error_description") or "")
        code = params.get("code") or ""
        if not code:
            raise MissingCodeError()

        body = await self._token_request(
            "code exchange",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._cfg.redirect_url,
                "code_verifier": f.verifier,
            },
        )
        id_token = body.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise TokenError("code exchange", "id_token missing from token response")
        try:
            claims = await self._verify_id_token(
                id_token, nonce=f.nonce, access_token=str(body["access_token"])
            )
            self._check_auth_context(f, claims)
        except _InvalidToken as e:
            raise TokenError("code exchange", e) from None

        identity = await self._identity(claims, str(body["access_token"]))
        identity.tokens = self._tokens(body, id_token, f.scope)
        return Result(identity=identity, return_to=f.return_to)

    def _check_auth_context(self, f: Flow, claims: dict[str, Any]) -> None:
        # max_age makes auth_time REQUIRED (section 3.1.2.1).
        if f.max_age is not None:
            auth_time = _num(claims, "auth_time")
            if auth_time is None:
                raise _InvalidToken("auth_time missing")
            # Measured from when the login started, so max_age=0 means "the
            # user authenticated during this login".
            oldest = f.issued_at - f.max_age - AUTH_TIME_SKEW
            if auth_time < oldest:
                when = datetime.fromtimestamp(auth_time, tz=timezone.utc)
                raise _InvalidToken(
                    f"auth_time {when.isoformat()} is older than max_age {f.max_age}s"
                )
        if f.acr:
            acr = claims.get("acr")
            if acr not in f.acr:
                raise _InvalidToken(f'acr "{acr}" is not one of {f.acr}')

    def cookie_name_for(self, state: str) -> str:
        """The flow cookie name of a callback state."""
        return self._flows.name(state)

    def clear_cookie(self, state: str) -> Cookie:
        """A cookie that deletes the flow cookie of state."""
        return self._flows.clear(state)

    # -- tokens --------------------------------------------------------------

    async def refresh(self, refresh_token: str) -> RefreshResult:
        """Exchanges a refresh token for new tokens (OpenID Connect Core 1.0,
        section 12). A refresh token is only issued when offline_access was
        granted (or by provider policy). The refreshed grant keeps the
        originally granted scopes. A returned ID token is fully verified
        (signature, iss, aud, azp, exp, iat); it carries no fresh nonce, so
        nonce is not checked."""
        if not refresh_token:
            raise TokenError("refresh", "refresh token is empty")
        body = await self._token_request(
            "refresh",
            {"grant_type": "refresh_token", "refresh_token": refresh_token},
        )
        id_token = body.get("id_token") if isinstance(body.get("id_token"), str) else ""
        tokens = self._tokens(body, id_token or "", "")
        if not tokens.refresh_token:
            tokens.refresh_token = refresh_token
        res = RefreshResult(tokens=tokens)
        if id_token:
            try:
                claims = await self._verify_id_token(
                    id_token, nonce=None, access_token=tokens.access_token
                )
            except _InvalidToken as e:
                raise TokenError("refresh", e) from None
            identity = await self._identity(claims, tokens.access_token)
            identity.tokens = tokens
            res.identity = identity
        return res

    async def revoke(self, token: str, hint: str = "") -> None:
        """Revokes a refresh or access token at the provider (RFC 7009). hint is
        "refresh_token", "access_token" or "". Revoking a refresh token usually
        also ends the grant's access tokens. Raises NotSupportedError when the
        provider has no revocation_endpoint."""
        meta = await self._meta()
        endpoint = meta.get("revocation_endpoint")
        if not endpoint:
            raise NotSupportedError("revocation_endpoint")
        form = {"token": token}
        if hint:
            form["token_type_hint"] = hint
        headers = self._authenticate(meta, form)
        try:
            resp = await self._http.post(endpoint, data=form, headers=headers)
        except httpx.TransportError as e:
            raise classify("revoke", e) from None
        if resp.status_code >= 300:
            raise TokenError("revoke", _oauth_error(resp))

    async def userinfo(self, access_token: str, subject: str) -> dict[str, Any]:
        """Calls the userinfo endpoint with an access token and returns its
        claims. subject must be the ID token `sub`; a response for another
        subject is rejected (section 5.3.4)."""
        meta = await self._meta()
        if not meta.get("userinfo_endpoint"):
            raise NotSupportedError("userinfo_endpoint")
        try:
            return await self._fetch_userinfo(meta, access_token, subject)
        except (httpx.HTTPError, ValueError) as e:
            raise classify("userinfo", e) from None

    async def _fetch_userinfo(
        self, meta: dict[str, Any], access_token: str, subject: str
    ) -> dict[str, Any]:
        resp = await self._http.get(
            meta["userinfo_endpoint"],
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
        if resp.status_code >= 300:
            raise ValueError(f"userinfo status {resp.status_code}")
        if resp.headers.get("content-type", "").startswith("application/jwt"):
            _, info = await self._verify_signature(resp.text.strip())
        else:
            info = resp.json()
        if not isinstance(info, dict):
            raise ValueError("userinfo is not a JSON object")
        if info.get("sub") != subject:
            raise ValueError("userinfo sub does not match the ID token sub")
        return dict(info)

    async def _identity(self, claims: dict[str, Any], access_token: str) -> Identity:
        """The Identity of a verified ID token merged with userinfo."""
        claims = dict(claims)
        meta = await self._meta()
        if not self._cfg.skip_userinfo and meta.get("userinfo_endpoint"):
            try:
                info = await self._fetch_userinfo(
                    meta, access_token, str(claims.get("sub", ""))
                )
            except (httpx.HTTPError, ValueError) as e:
                raise UserInfoError(e) from None
            for k, v in info.items():
                if k not in PROTECTED_CLAIMS:
                    claims[k] = v
        return identity_from_claims(claims, self._cfg.role_extractor)

    def _tokens(self, body: dict[str, Any], id_token: str, requested: str) -> Tokens:
        scope = body.get("scope")
        if not isinstance(scope, str) or not scope:
            scope = requested
        token_type = str(body.get("token_type") or "Bearer")
        if token_type.lower() == "bearer":
            token_type = "Bearer"
        expiry = None
        expires_in = body.get("expires_in")
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            expiry = datetime.fromtimestamp(
                int(self._now() + expires_in), tz=timezone.utc
            )
        return Tokens(
            id_token=id_token,
            access_token=str(body.get("access_token") or ""),
            refresh_token=str(body.get("refresh_token") or ""),
            token_type=token_type,
            expiry=expiry,
            scopes=scope.split(),
        )

    # -- logout --------------------------------------------------------------

    async def logout_url(
        self,
        id_token_hint: str = "",
        post_logout_redirect: str = "",
        state: str = "",
        *,
        logout_hint: str = "",
        ui_locales: list[str] | None = None,
    ) -> str:
        """The RP-initiated logout URL (OpenID Connect RP-Initiated Logout 1.0)
        at the end_session_endpoint. Raises NotSupportedError when the provider
        advertises none. post_logout_redirect must be registered at the
        provider; empty uses Config.post_logout_redirect_url. Pass the ID token
        of the login (identity.tokens.id_token) as id_token_hint whenever
        available; otherwise logout_hint (e.g. the login name) tells the
        provider which session to end."""
        meta = await self._meta()
        endpoint = meta.get("end_session_endpoint")
        if not endpoint:
            raise NotSupportedError("end_session_endpoint")
        params = [("client_id", self._cfg.client_id)]
        if id_token_hint:
            params.append(("id_token_hint", id_token_hint))
        post_logout_redirect = (
            post_logout_redirect or self._cfg.post_logout_redirect_url
        )
        if post_logout_redirect:
            params.append(("post_logout_redirect_uri", post_logout_redirect))
        if state:
            params.append(("state", state))
        if logout_hint:
            params.append(("logout_hint", logout_hint))
        if ui_locales:
            params.append(("ui_locales", " ".join(ui_locales)))
        return _add_query(endpoint, params)

    async def verify_logout_token(self, raw: str) -> LogoutToken:
        """Validates the `logout_token` POSTed to the back-channel logout URI
        (section 2.6): signature against the provider JWKS, iss, aud, iat, exp,
        the backchannel-logout event, sub and/or sid, and the absence of nonce
        (which tells it apart from an ID token). Raises
        InvalidLogoutTokenError, or a discovery error when the provider is
        unreachable."""
        await self._meta()
        try:
            headers = jws.extract_compact(raw.encode()).headers()
        except (JoseError, ValueError) as e:
            raise InvalidLogoutTokenError(str(e) or type(e).__name__) from None
        typ = headers.get("typ") or ""
        if typ and typ.lower() not in ("logout+jwt", "jwt"):
            raise InvalidLogoutTokenError(f'typ "{typ}"')
        try:
            _, claims = await self._verify_signature(raw)
        except _InvalidToken as e:
            raise InvalidLogoutTokenError(str(e)) from None

        def invalid(reason: str) -> InvalidLogoutTokenError:
            return InvalidLogoutTokenError(reason)

        if claims.get("iss") != self._cfg.issuer:
            raise invalid(f'iss "{claims.get("iss")}"')
        if self._cfg.client_id not in _audience(claims):
            raise invalid("aud does not contain client id")
        now = self._now()
        iat, exp = _num(claims, "iat"), _num(claims, "exp")
        if not iat or iat > now + LOGOUT_TOKEN_SKEW:
            raise invalid("iat missing or in the future")
        if not exp or not now - LOGOUT_TOKEN_SKEW < exp:
            raise invalid("exp missing or passed")
        jti, sub, sid = (str(claims.get(k) or "") for k in ("jti", "sub", "sid"))
        if not jti:
            raise invalid("jti missing")
        if not sub and not sid:
            raise invalid("sub and sid both missing")
        events = claims.get("events")
        if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
            raise invalid("backchannel-logout event missing")
        if not isinstance(events[BACKCHANNEL_LOGOUT_EVENT], dict):
            raise invalid("backchannel-logout event must be a JSON object")
        if "nonce" in claims:
            raise invalid("nonce must not be present")
        return LogoutToken(
            issuer=str(claims["iss"]),
            subject=sub,
            session_id=sid,
            jwt_id=jti,
            issued_at=datetime.fromtimestamp(int(iat), tz=timezone.utc),
            expiry=datetime.fromtimestamp(int(exp), tz=timezone.utc),
            claims=claims,
        )

    # -- provider ------------------------------------------------------------

    async def _meta(self) -> dict[str, Any]:
        if self._discovery is not None:
            return self._discovery
        async with self._lock:
            if self._discovery is None:
                url = self._cfg.discovery_url or (
                    self._cfg.issuer.rstrip("/") + "/.well-known/openid-configuration"
                )
                doc = await self._get_json(url)
                if doc.get("issuer") != self._cfg.issuer:
                    raise DiscoveryError(
                        f'issuer "{doc.get("issuer")}" does not match '
                        f'"{self._cfg.issuer}"'
                    )
                for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                    if not isinstance(doc.get(key), str) or not doc[key]:
                        raise DiscoveryError(f"{key} missing")
                self._discovery = doc
        return self._discovery

    async def _get_json(self, url: str) -> dict[str, Any]:
        try:
            resp = await self._http.get(url, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                raise DiscoveryError(f"GET {url}: status {resp.status_code}")
            doc = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            raise DiscoveryError(e) from None
        if not isinstance(doc, dict):
            raise DiscoveryError(f"GET {url}: not a JSON object")
        return doc

    async def _keyset(self, refresh: bool = False) -> jwk.KeySet:
        if self._keys is not None and not refresh:
            return self._keys
        meta = await self._meta()
        doc = await self._get_json(meta["jwks_uri"])
        try:
            keys = jwk.KeySet.import_key_set(doc)  # type: ignore[arg-type]
        except (JoseError, ValueError, TypeError, KeyError) as e:
            raise DiscoveryError(f"jwks: {e}") from None
        self._keys = keys
        return keys

    def _algorithms(self, meta: dict[str, Any]) -> list[str]:
        algs = meta.get("id_token_signing_alg_values_supported") or ["RS256"]
        return [a for a in algs if a in _SIGNING_ALGS] or ["RS256"]

    async def _verify_signature(
        self, raw: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Verifies the signature of a JWT with the provider keys (refetched
        once on an unknown kid) and returns its header and claims."""
        algs = self._algorithms(await self._meta())
        keys = await self._keyset()
        for attempt in (0, 1):
            try:
                token = jwt.decode(raw, keys, algorithms=algs)
                break
            except InvalidKeyIdError as e:
                if attempt:
                    raise _InvalidToken(f"signature: {e}") from None
                keys = await self._keyset(refresh=True)
            except (JoseError, ValueError, TypeError) as e:
                raise _InvalidToken(f"signature: {e or type(e).__name__}") from None
        if not isinstance(token.claims, dict):
            raise _InvalidToken("claims are not a JSON object")
        return dict(token.header), dict(token.claims)

    async def _verify_id_token(
        self, raw: str, *, nonce: str | None, access_token: str
    ) -> dict[str, Any]:
        header, claims = await self._verify_signature(raw)
        if claims.get("iss") != self._cfg.issuer:
            raise _InvalidToken(f'iss "{claims.get("iss")}" does not match issuer')
        aud = _audience(claims)
        if self._cfg.client_id not in aud:
            raise _InvalidToken("aud does not contain client id")
        azp = claims.get("azp")
        if len(aud) > 1 and not azp:
            raise _InvalidToken("azp is required with several audiences")
        if azp and azp != self._cfg.client_id:
            raise _InvalidToken(f'azp "{azp}" is not the client id')
        now = self._now()
        exp = _num(claims, "exp")
        if exp is None or now > exp + CLOCK_SKEW:
            raise _InvalidToken("token expired")
        iat = _num(claims, "iat")
        if iat is None or iat > now + CLOCK_SKEW:
            raise _InvalidToken("iat missing or in the future")
        if nonce is not None and claims.get("nonce") != nonce:
            raise _InvalidToken("nonce does not match")
        at_hash = claims.get("at_hash")
        if at_hash and access_token:
            if at_hash != _left_hash(str(header.get("alg", "")), access_token):
                raise _InvalidToken("at_hash does not match the access token")
        return claims

    def _auth_method(self, meta: dict[str, Any]) -> str:
        m = self._cfg.token_endpoint_auth_method
        if m != AUTH_METHOD_AUTO:
            return m
        if self._signing_key is not None:
            return AUTH_METHOD_PRIVATE_KEY_JWT
        if not self._cfg.client_secret:
            return AUTH_METHOD_NONE
        supported = meta.get("token_endpoint_auth_methods_supported") or []
        if (
            AUTH_METHOD_CLIENT_SECRET_BASIC not in supported
            and AUTH_METHOD_CLIENT_SECRET_POST in supported
        ):
            return AUTH_METHOD_CLIENT_SECRET_POST
        return AUTH_METHOD_CLIENT_SECRET_BASIC

    def _authenticate(
        self, meta: dict[str, Any], form: dict[str, str]
    ) -> dict[str, str]:
        """Adds client authentication to a token endpoint request and returns
        its headers."""
        headers = {"Accept": "application/json"}
        cfg = self._cfg
        m = self._auth_method(meta)
        if m == AUTH_METHOD_CLIENT_SECRET_BASIC:
            # RFC 6749, section 2.3.1: form-encoded, then Basic.
            raw = f"{quote_plus(cfg.client_id)}:{quote_plus(cfg.client_secret)}"
            headers["Authorization"] = (
                "Basic " + base64.b64encode(raw.encode()).decode()
            )
        elif m == AUTH_METHOD_CLIENT_SECRET_POST:
            form["client_id"] = cfg.client_id
            form["client_secret"] = cfg.client_secret
        elif m == AUTH_METHOD_PRIVATE_KEY_JWT:
            now = int(self._now())
            assertion = jwt.encode(
                {"alg": self._signing_alg, "kid": cfg.client_key_id, "typ": "JWT"},
                {
                    "iss": cfg.client_id,
                    "sub": cfg.client_id,
                    "aud": [cfg.issuer],
                    "iat": now,
                    "exp": now + 60,
                    "jti": str(uuid.uuid4()),
                },
                self._signing_key,
                algorithms=[self._signing_alg],
            )
            form["client_id"] = cfg.client_id
            form["client_assertion_type"] = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            form["client_assertion"] = assertion
        else:
            form["client_id"] = cfg.client_id
        return headers

    async def _token_request(self, op: str, form: dict[str, str]) -> dict[str, Any]:
        meta = await self._meta()
        headers = self._authenticate(meta, form)
        try:
            resp = await self._http.post(
                meta["token_endpoint"], data=form, headers=headers
            )
        except httpx.TransportError as e:
            raise ProviderUnreachableError(op, e) from None
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code >= 300 or not isinstance(body, dict) or "error" in body:
            raise TokenError(op, _oauth_error(resp))
        if not body.get("access_token"):
            raise TokenError(op, "access_token missing from token response")
        return body


def _load_client_key(pem: bytes) -> tuple[Any, str]:
    try:
        key = load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as e:
        raise ConfigError([f"client key is not a PEM private key: {e}"]) from None
    if isinstance(key, rsa.RSAPrivateKey):
        return jwk.import_key(pem, "RSA"), "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        alg = {"secp256r1": "ES256", "secp384r1": "ES384", "secp521r1": "ES512"}.get(
            key.curve.name
        )
        if alg:
            return jwk.import_key(pem, "EC"), alg
    raise ConfigError(["client key must be an RSA or EC (P-256/384/521) key"])


def _oauth_error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict) and body.get("error"):
        desc = body.get("error_description")
        return f"{body['error']}: {desc}" if desc else str(body["error"])
    return f"status {resp.status_code}: {resp.text.strip()[:200]}"


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _left_hash(alg: str, value: str) -> str:
    """at_hash / c_hash: the left half of the hash of value, with the hash of
    the signature algorithm (section 3.1.3.6)."""
    if alg == "EdDSA" or alg.endswith("512"):
        h = hashlib.sha512
    elif alg.endswith("384"):
        h = hashlib.sha384
    else:
        h = hashlib.sha256
    digest = h(value.encode()).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()


def _audience(claims: dict[str, Any]) -> list[str]:
    aud = claims.get("aud")
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list):
        return [a for a in aud if isinstance(a, str)]
    return []


def _num(claims: dict[str, Any], key: str) -> float | None:
    v = claims.get(key)
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v)


def _add_query(endpoint: str, params: list[tuple[str, str]]) -> str:
    u = urlsplit(endpoint)
    query = urlencode(params)
    if u.query:
        query = u.query + "&" + query
    return urlunsplit((u.scheme, u.netloc, u.path, query, u.fragment))


__all__ = [
    "BACKCHANNEL_LOGOUT_EVENT",
    "Client",
    "LoginOptions",
    "LogoutToken",
    "OIDCAuthError",
    "RefreshResult",
    "Result",
]
