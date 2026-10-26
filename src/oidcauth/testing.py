"""An in-process fake OpenID Provider for tests.

It serves discovery, JWKS, token (authorization_code with PKCE S256 and
refresh_token), userinfo, revocation and end-session endpoints through an
``httpx.MockTransport``, with RS256-signed ID tokens and back-channel logout
tokens, so applications test their OIDC login end to end without a real
provider or network::

    op = Provider("client-id", "client-secret")
    client = Client(Config(issuer=op.issuer, client_id="client-id", ...,
                           http_client=op.http_client()))
    auth_url, cookie = await client.start()
    params = op.authorize(auth_url, User(subject="u1", email="a@b.c",
                                         email_verified=True))
    result = await client.finish(params, cookie.value)

Claims follow the granted scopes like a real provider: email claims need the
email scope, profile claims the profile scope, and so on.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs, parse_qsl, unquote_plus, urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from joserfc import jwk, jwt
from joserfc.errors import JoseError

from .client import BACKCHANNEL_LOGOUT_EVENT

DEFAULT_ISSUER = "https://op.test"
ZITADEL_ROLES_CLAIM = "urn:zitadel:iam:org:project:roles"


@dataclass
class User:
    """The identity the fake provider asserts."""

    subject: str
    email: str = ""  # email scope
    email_verified: bool = False  # email scope
    name: str = ""  # profile scope
    phone_number: str = ""  # phone scope
    phone_verified: bool = False  # phone scope
    # address claim (address scope), e.g. {"locality": "Ha Noi", "country": "VN"}.
    address: dict[str, Any] = field(default_factory=dict)
    # auth_time claim (unix). Defaults to the time of authorize.
    auth_time: int | None = None
    # acr claim. Defaults to the first requested acr_values.
    acr: str = ""
    amr: list[str] = field(default_factory=list)
    # Emitted as Zitadel project roles (urn:zitadel:iam:org:project:roles),
    # whatever the scopes.
    roles: list[str] = field(default_factory=list)
    # Added to both the ID token and userinfo. Standard claims among them
    # (given_name, phone_number, ...) still follow the scopes.
    extra: dict[str, Any] = field(default_factory=dict)
    # Only in userinfo (not the ID token), like Zitadel profile claims without
    # "User Info inside ID Token". They also follow the scopes.
    userinfo_only: dict[str, Any] = field(default_factory=dict)


# Standard claims each scope releases (OpenID Connect Core 1.0, section 5.4).
SCOPE_CLAIMS = {
    "profile": [
        "name",
        "family_name",
        "given_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
    ],
    "email": ["email", "email_verified"],
    "address": ["address"],
    "phone": ["phone_number", "phone_number_verified"],
}
_CLAIM_SCOPE = {c: s for s, claims in SCOPE_CLAIMS.items() for c in claims}


@dataclass
class _Grant:
    user: User
    scopes: list[str]
    nonce: str
    challenge: str
    redirect: str
    sid: str
    auth_time: int
    acr: str


def random_string() -> str:
    return secrets.token_urlsafe(24)


class Provider:
    """A fake OpenID Provider.

    client_secret authenticates the client with client_secret_basic or
    client_secret_post; empty means a public client (auth method none), unless
    client_public_key is set, which enables private_key_jwt (the
    client_assertion must be signed by the matching private key).
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str = "",
        *,
        issuer: str = DEFAULT_ISSUER,
        client_public_key: Any = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_public_key = client_public_key
        # Alters the next issued ID tokens, for negative tests.
        self.mutate_id_token: Callable[[dict[str, Any]], None] | None = None
        # Decides the granted scopes from the requested ones. Defaults to
        # granting everything requested.
        self.grant_scopes: Callable[[list[str]], list[str]] | None = None
        # Leaves `scope` out of token responses.
        self.omit_scope_in_response = False
        # Makes refresh_token responses omit the ID token.
        self.refresh_without_id_token = False
        # Makes every request fail with a connection error, to test an
        # unreachable provider.
        self.down = False

        self.key = jwk.RSAKey.generate_key(
            2048, parameters={"kid": "test-key", "alg": "RS256", "use": "sig"}
        )
        self._codes: dict[str, _Grant] = {}
        self._access: dict[str, dict[str, Any]] = {}
        self._refresh: dict[str, _Grant] = {}
        self.revoked: list[str] = []
        # Client authentication method of the last token or revocation
        # request: client_secret_basic, client_secret_post, private_key_jwt
        # or none.
        self.last_client_auth = ""
        # Parameters of the last authorization request passed to authorize.
        self.last_auth_request: dict[str, str] = {}
        self.transport = httpx.MockTransport(self.handle)

    def http_client(self, **kwargs: Any) -> httpx.AsyncClient:
        """An AsyncClient that talks to this provider in-process."""
        return httpx.AsyncClient(transport=self.transport, **kwargs)

    # -- browser side --------------------------------------------------------

    def authorize(self, auth_url: str, user: User) -> dict[str, str]:
        """Plays the browser + provider login page: reads the authorization
        request produced by the relying party, records state, nonce, scopes and
        PKCE challenge, and returns the callback parameters (code, state and
        the RFC 9207 iss)."""
        q = dict(parse_qsl(urlsplit(auth_url).query, keep_blank_values=True))
        if q.get("client_id") != self.client_id:
            raise AssertionError(
                f"oidctest: client_id = {q.get('client_id')!r}, want {self.client_id!r}"
            )
        if q.get("response_type") != "code":
            raise AssertionError(
                f"oidctest: response_type = {q.get('response_type')!r}, want code"
            )
        if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
            raise AssertionError("oidctest: PKCE S256 challenge missing")
        requested = q.get("scope", "").split()
        if "openid" not in requested:
            raise AssertionError(f"oidctest: scope {q.get('scope')!r} lacks openid")
        scopes = self.grant_scopes(requested) if self.grant_scopes else requested
        auth_time = user.auth_time or int(time.time())
        acr = user.acr
        acr_values = q.get("acr_values", "").split()
        if not acr and acr_values:
            acr = acr_values[0]
        code = random_string()
        self.last_auth_request = q
        self._codes[code] = _Grant(
            user=user,
            scopes=scopes,
            nonce=q.get("nonce", ""),
            challenge=q.get("code_challenge", ""),
            redirect=q.get("redirect_uri", ""),
            sid="sid-" + random_string()[:12],
            auth_time=auth_time,
            acr=acr,
        )
        return {"code": code, "state": q.get("state", ""), "iss": self.issuer}

    def logout_token(
        self,
        sub: str = "",
        sid: str = "",
        mutate: Callable[[dict[str, Any]], None] | None = None,
    ) -> str:
        """Signs a back-channel logout token for the client (OpenID Connect
        Back-Channel Logout 1.0). Pass sub and/or sid. mutate alters the claims
        before signing, for negative tests."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": [self.client_id],
            "iat": now,
            "exp": now + 120,
            "jti": random_string(),
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
        }
        if sub:
            claims["sub"] = sub
        if sid:
            claims["sid"] = sid
        if mutate:
            mutate(claims)
        return self.sign(claims, "logout+jwt")

    def sign(self, claims: dict[str, Any], typ: str = "JWT") -> str:
        """Signs claims with the provider key."""
        return jwt.encode(
            {"alg": "RS256", "kid": "test-key", "typ": typ},
            claims,
            self.key,
            algorithms=["RS256"],
        )

    # -- endpoints -----------------------------------------------------------

    def handle(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("connection refused", request=request)
        base = urlsplit(self.issuer)
        if (request.url.scheme, request.url.host) != (base.scheme, base.hostname):
            raise httpx.ConnectError(
                f"unknown host {request.url.host}", request=request
            )
        path = request.url.path[len(base.path.rstrip("/")) :]
        if path == "/.well-known/openid-configuration":
            return _json(self.discovery_document())
        if path == "/keys":
            return _json({"keys": [self.key.as_dict(private=False)]})
        if path == "/oauth/v2/token":
            return self._token(request)
        if path == "/oauth/v2/revoke":
            return self._revoke(request)
        if path == "/oidc/v1/userinfo":
            return self._userinfo(request)
        if path == "/oidc/v1/end_session":
            return httpx.Response(200)
        return httpx.Response(404)

    def discovery_document(self) -> dict[str, Any]:
        base = self.issuer
        return {
            "issuer": base,
            "authorization_endpoint": base + "/oauth/v2/authorize",
            "token_endpoint": base + "/oauth/v2/token",
            "userinfo_endpoint": base + "/oidc/v1/userinfo",
            "revocation_endpoint": base + "/oauth/v2/revoke",
            "end_session_endpoint": base + "/oidc/v1/end_session",
            "jwks_uri": base + "/keys",
            "scopes_supported": [
                "openid",
                "profile",
                "email",
                "address",
                "phone",
                "offline_access",
            ],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query", "form_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "none",
            ],
            "claims_parameter_supported": True,
            "backchannel_logout_supported": True,
            "backchannel_logout_session_supported": True,
            "authorization_response_iss_parameter_supported": True,
        }

    def _authenticate_client(
        self, request: httpx.Request, form: dict[str, str]
    ) -> bool:
        method, ok = self._client_auth(request, form)
        self.last_client_auth = method
        return ok

    def _client_auth(
        self, request: httpx.Request, form: dict[str, str]
    ) -> tuple[str, bool]:
        auth = request.headers.get("authorization", "")
        if auth[:6].lower() == "basic ":
            try:
                raw = base64.b64decode(auth[6:]).decode()
                cid, _, secret = raw.partition(":")
                cid, secret = unquote_plus(cid), unquote_plus(secret)
            except ValueError:
                return "client_secret_basic", False
            ok = bool(self.client_secret) and (cid, secret) == (
                self.client_id,
                self.client_secret,
            )
            return "client_secret_basic", ok
        assertion = form.get("client_assertion", "")
        if assertion:
            if self.client_public_key is None or form.get("client_assertion_type") != (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ):
                return "private_key_jwt", False
            return "private_key_jwt", self._verify_client_assertion(assertion)
        secret = form.get("client_secret", "")
        if secret:
            ok = (
                bool(self.client_secret)
                and form.get("client_id") == self.client_id
                and secret == self.client_secret
            )
            return "client_secret_post", ok
        ok = (
            not self.client_secret
            and self.client_public_key is None
            and form.get("client_id") == self.client_id
        )
        return "none", ok

    def _verify_client_assertion(self, raw: str) -> bool:
        try:
            token = jwt.decode(
                raw,
                _public_jwk(self.client_public_key),
                algorithms=["RS256", "ES256", "PS256"],
            )
        except (JoseError, ValueError):
            return False
        c = token.claims
        exp = c.get("exp")
        if (
            c.get("iss") != self.client_id
            or c.get("sub") != self.client_id
            or not isinstance(exp, int)
            or exp < int(time.time())
        ):
            return False
        aud = c.get("aud")
        auds = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        return self.issuer in auds or self.issuer + "/oauth/v2/token" in auds

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = _form(request)
        if not self._authenticate_client(request, form):
            return _oauth_error(401, "invalid_client")
        grant_type = form.get("grant_type")
        if grant_type == "authorization_code":
            return self._code_grant(form)
        if grant_type == "refresh_token":
            return self._refresh_grant(form)
        return _oauth_error(400, "unsupported_grant_type")

    def _code_grant(self, form: dict[str, str]) -> httpx.Response:
        g = self._codes.pop(form.get("code", ""), None)
        if g is None or g.redirect != form.get("redirect_uri"):
            return _oauth_error(400, "invalid_grant")
        digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
        if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != g.challenge:
            return _oauth_error(400, "invalid_grant")
        return self._issue(g, True)

    def _refresh_grant(self, form: dict[str, str]) -> httpx.Response:
        # Rotation: a refresh token is single use.
        g = self._refresh.pop(form.get("refresh_token", ""), None)
        if g is None:
            return _oauth_error(400, "invalid_grant")
        requested = form.get("scope", "").split()
        if requested:
            # RFC 6749, section 6: a refresh may narrow but never widen the grant.
            if any(s not in g.scopes for s in requested):
                return _oauth_error(400, "invalid_scope")
            g = _Grant(**{**g.__dict__, "scopes": requested})
        return self._issue(g, not self.refresh_without_id_token)

    def _issue(self, g: _Grant, with_id_token: bool) -> httpx.Response:
        now = int(time.time())
        resp: dict[str, Any] = {"token_type": "Bearer", "expires_in": 3600}
        if not self.omit_scope_in_response:
            resp["scope"] = " ".join(g.scopes)
        if with_id_token:
            claims: dict[str, Any] = {
                "iss": self.issuer,
                "sub": g.user.subject,
                "aud": [self.client_id],
                "azp": self.client_id,
                "iat": now,
                "exp": now + 3600,
                "auth_time": g.auth_time,
                "sid": g.sid,
            }
            if g.nonce:
                claims["nonce"] = g.nonce
            if g.acr:
                claims["acr"] = g.acr
            if g.user.amr:
                claims["amr"] = list(g.user.amr)
            claims.update(self.public_claims(g.user, g.scopes, userinfo=False))
            if self.mutate_id_token:
                self.mutate_id_token(claims)
            resp["id_token"] = self.sign(claims, "JWT")
        access_token = random_string()
        info = {"sub": g.user.subject}
        info.update(self.public_claims(g.user, g.scopes, userinfo=True))
        resp["access_token"] = access_token
        self._access[access_token] = info
        if "offline_access" in g.scopes:
            refresh_token = random_string()
            self._refresh[refresh_token] = g
            resp["refresh_token"] = refresh_token
        return _json(resp)

    def _revoke(self, request: httpx.Request) -> httpx.Response:
        form = _form(request)
        if not self._authenticate_client(request, form):
            return _oauth_error(401, "invalid_client")
        token = form.get("token", "")
        self._refresh.pop(token, None)
        self._access.pop(token, None)
        self.revoked.append(token)
        # RFC 7009, section 2.2: 200 even for unknown tokens.
        return httpx.Response(200)

    def _userinfo(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if len(auth) <= 7 or auth[:7].lower() != "bearer ":
            return httpx.Response(401)
        info = self._access.get(auth[7:])
        if info is None:
            return httpx.Response(401)
        return _json(info)

    def public_claims(
        self, u: User, scopes: list[str], userinfo: bool
    ) -> dict[str, Any]:
        """The user claims released by scopes; userinfo adds userinfo_only."""
        claims: dict[str, Any] = {}
        if u.email:
            claims["email"] = u.email
            claims["email_verified"] = u.email_verified
        if u.name:
            claims["name"] = u.name
        if u.phone_number:
            claims["phone_number"] = u.phone_number
            claims["phone_number_verified"] = u.phone_verified
        if u.address:
            claims["address"] = dict(u.address)
        claims.update(u.extra)
        if userinfo:
            claims.update(u.userinfo_only)
        out = {
            k: v
            for k, v in claims.items()
            if k not in _CLAIM_SCOPE or _CLAIM_SCOPE[k] in scopes
        }
        if u.roles:
            out[ZITADEL_ROLES_CLAIM] = {r: {"org-id": "example.org"} for r in u.roles}
        return out


def _public_jwk(key: Any) -> Any:
    if isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        pem = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return jwk.import_key(pem, "RSA" if isinstance(key, rsa.RSAPublicKey) else "EC")
    return key


def _form(request: httpx.Request) -> dict[str, str]:
    parsed = parse_qs(request.content.decode(), keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


def _json(body: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )


def _oauth_error(status: int, code: str) -> httpx.Response:
    return _json({"error": code}, status)
