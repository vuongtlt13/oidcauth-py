# oidcauth-py

`oidcauth` is a thin OpenID Connect relying party for browser login in Python
(async) services. It adds **OIDC login next to local (username/password)
login** without changing how your app keeps users signed in.

It is the Python sibling of the Go library
[`github.com/vuongtlt13/oidcauth`](https://github.com/vuongtlt13/oidcauth),
with the same feature set and the same environment contract in the backend
templates. It provides:

- Authorization Code flow with **PKCE (S256)**, `state` and `nonce`.
- An encrypted, short-lived **flow cookie** that holds state, nonce, the PKCE
  verifier and the return path. It uses AES-256-GCM, is bound to `state`,
  and is set per login, so several tabs can log in at once.
- **ID token verification**: signature checked against the JWKS, plus `iss`,
  `aud`, `azp`, `exp`, `iat`, `nonce` and `at_hash`. Userinfo claims are then
  merged in. `sub`/`iss` and other protected claims are never overridden by
  userinfo.
- A normalized **`Identity`**: issuer, subject, email, `email_verified`,
  profile fields, roles (Zitadel project roles out of the box) and raw claims.
- `safe_return_to`, which prevents open redirects.
- A single-use **`TicketStore`** (`MemoryTicketStore`, `RedisTicketStore`), so
  the callback can hand a session token to an SPA without putting it in a URL.
- **Scopes and standard claims**: `openid`, `profile`, `email`, `phone`,
  `address` and `offline_access`, with every standard claim mapped. The
  scopes the provider actually granted are reported in `Tokens.scopes`.
- All authorization request parameters: `prompt`, `login_hint`,
  `id_token_hint`, `max_age` (with an `auth_time` check), `acr_values` (with
  an optional `acr` check), `ui_locales`, `claims_locales`, `display`,
  `response_mode` (`query` / `form_post`), `claims` and custom parameters.
- **Refresh** (`refresh_token` grant), **revocation** (RFC 7009) and
  **userinfo**.
- RP-initiated logout (`logout_url`) and **back-channel logout** token
  verification (`verify_logout_token`).
- **ID tokens from native apps** (`verify_id_token`): a mobile app logs in
  itself and the backend verifies its ID token.
- Client authentication: `client_secret_basic`, `client_secret_post`,
  `private_key_jwt` and `none` (public client + PKCE).
- A **FastAPI / Starlette adapter** (`oidcauth.fastapi`) and an in-process
  **fake provider** (`oidcauth.testing`) for end-to-end tests.

The core modules (`oidcauth`, `oidcauth.fastapi`, `oidcauth.testing`) work
with any OpenID Connect provider: Zitadel, Keycloak, Google, Microsoft Entra
ID, Auth0, Authentik, and others. The only Zitadel-aware default is the roles
claim, and `Config.role_extractor` overrides it. The optional
`oidcauth.zitadel` package (see
[Zitadel identity provider login](#zitadel-identity-provider-login-without-zitadels-pages))
is Zitadel-only.

`oidcauth` deliberately does **not** do the following. Each application
decides them:

- Create, link or reject local users. The app receives an `Identity` and does
  whatever its policy says.
- Issue sessions or JWTs. Keep using your existing token and middleware.

### Design notes

- **Async only.** Every call that may reach the provider is a coroutine
  (`await client.start(...)`, `await client.finish(...)`, ...). There is no
  sync API.
- Implemented directly on [httpx](https://www.python-httpx.org/) (async),
  [joserfc](https://jose.authlib.org/) and
  [cryptography](https://cryptography.io/) rather than Authlib: Authlib 1.9
  deprecates its httpx integration and `authlib.jose`.
- Python >= 3.10. Fully typed (`py.typed`, mypy strict).

## Install

```bash
pip install oidcauth-py              # core
pip install "oidcauth-py[fastapi]"   # + FastAPI / Starlette adapter
# or
uv add "oidcauth-py[fastapi]"
```

The distribution is `oidcauth-py`; the import name is `oidcauth`. The
`fastapi` extra only pulls in Starlette; `oidcauth.fastapi` works with plain
Starlette as well. `RedisTicketStore` takes any `redis.asyncio.Redis`
compatible client, which you install yourself.

## Documentation

Step-by-step guides (Vietnamese) are in [`docs/`](https://github.com/vuongtlt13/oidcauth-py/blob/master/docs/README.md):

- [Setup](https://github.com/vuongtlt13/oidcauth-py/blob/master/docs/setup.md): wiring, `Config` ↔ environment variables,
  `TicketStore`, cookies, local development, production checklist.
- [Zitadel](https://github.com/vuongtlt13/oidcauth-py/blob/master/docs/zitadel/README.md): web application (secret, Private Key
  JWT, PKCE), roles and organizations, Google through Zitadel with or without
  Zitadel's pages, logout and account linking, troubleshooting.
- [Other providers](https://github.com/vuongtlt13/oidcauth-py/blob/master/docs/providers.md): Google direct, Keycloak, Microsoft
  Entra ID, Auth0.

## Usage with FastAPI

```python
import os
from datetime import timedelta
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response

from oidcauth import (
    Client,
    Config,
    LoginOptions,
    MemoryTicketStore,
    Result,
    safe_return_to,
)
from oidcauth.fastapi import OIDCHandler

client = Client(
    Config(
        issuer="https://id.example.com",
        client_id=os.environ["AUTH_OIDC_CLIENT_ID"],
        client_secret=os.environ["AUTH_OIDC_CLIENT_SECRET"],
        redirect_url="https://app.example.com/api/v1/auth/oidc/callback",
        cookie_secret=os.environ["AUTH_OIDC_COOKIE_SECRET"],  # >= 32 chars
        cookie_path="/api/v1/auth/oidc",
    )
)  # raises oidcauth.ConfigError listing every config problem

tickets = MemoryTicketStore()  # RedisTicketStore (GETDEL) with replicas


async def on_success(request: Request, res: Result) -> Response:
    # App policy: link by (iss, sub), else match a local user by verified email.
    user = await users.from_oidc(res.identity)
    if user is None:
        return RedirectResponse("/auth/login?error=not_allowed", 302)
    token = sessions.issue(user)
    ticket = await tickets.put(token, timedelta(minutes=1))
    query = urlencode({"ticket": ticket, "redirect": safe_return_to(res.return_to, "/")})
    return RedirectResponse("/auth/callback?" + query, 302)


def on_error(request: Request, err: Exception) -> Response:
    return RedirectResponse("/auth/login?error=oidc_failed", 302)


h = OIDCHandler(client, on_success=on_success, on_error=on_error)

app = FastAPI()
app.add_api_route("/api/v1/auth/oidc/login", h.login, methods=["GET"])  # ?redirect=/path
# Register this as redirect URI. Add "POST" with response_mode=form_post.
app.add_api_route("/api/v1/auth/oidc/callback", h.callback, methods=["GET"])
# The SPA then POSTs the ticket to an endpoint that calls tickets.take.
```

`login_options(request)` returns the `LoginOptions` of one login (extra
scopes, prompt, ...). Its `return_to` wins; only when it is empty does
`return_to` come from the `?redirect=` query parameter (`return_to_param`).
Use that to sanitize the client value, or to set a server-side marker such as
`"link:<user id>"` for an account-linking flow, which `on_success` reads back
from `res.return_to`:

```python
def link_options(request: Request) -> LoginOptions:
    user = current_user(request)  # the app's own session
    return LoginOptions(return_to="link:" + str(user.id), prompt=["select_account"])
```

`oidcauth.fastapi.start_options(request, login_options, return_to_param)`
applies the same rule for custom handlers; `ZitadelIDPHandler` uses it too.

`on_success`, `on_error`, `login_options` and the back-channel `on_logout` may
be plain functions or coroutines. Without `on_error`, the handler answers 401
(`login failed`) for user errors and 502 (`identity provider unavailable`)
otherwise (`oidcauth.fastapi.default_error_handler`). The callback always
clears the flow cookie and sets `Cache-Control: no-store`. Form bodies
(`form_post` callbacks, back-channel logout) are parsed without
`python-multipart`.

The adapter is optional. `Client.start` and `Client.finish` work with any
framework: set the returned `Cookie`, redirect, then pass the callback
parameters and the cookie value back in, and always clear the cookie:

```python
auth_url, cookie = await client.start(return_to="/jobs")
# set cookie.name / value / path / max_age / secure / http_only / same_site, redirect

state = params.get("state", "")
cookie_value = request_cookies.get(client.cookie_name_for(state))
try:
    res = await client.finish(params, cookie_value)
finally:
    clear = client.clear_cookie(state)  # set it on the response, whatever the outcome
```

Close the HTTP client the library created on shutdown with
`await client.aclose()` (for example in the FastAPI lifespan). Pass your own
`httpx.AsyncClient` as `Config.http_client` for proxies, timeouts or a custom
CA.

## Errors

Every exception the core raises derives from `oidcauth.OIDCAuthError`:

| Exception | Meaning |
|---|---|
| `ConfigError` (also a `ValueError`) | invalid `Config`; `.errors` lists every problem |
| `InvalidStateError` | flow cookie missing, forged, foreign or expired; unknown or used ticket in the Zitadel handler |
| `MissingCodeError` | callback without `code` |
| `ProviderError` | the provider answered with `error=` (`.code`, `.description`), e.g. `access_denied` |
| `TokenError` | token request refused or token verification failed (`.op`, `.cause`) |
| `ProviderUnreachableError` | network error or timeout talking to the provider |
| `DiscoveryError` | discovery document or JWKS could not be loaded, or `issuer` mismatch |
| `UserInfoError` | userinfo request of a login failed |
| `InvalidLogoutTokenError` | back-channel logout token failed verification (`.reason`) |
| `NotSupportedError` | the provider lacks the endpoint (`end_session_endpoint`, `revocation_endpoint`, `userinfo_endpoint`) |
| `TicketNotFoundError` | ticket unknown, expired or already taken |

`oidcauth.is_user_error(err)` is true for `InvalidStateError`,
`MissingCodeError`, `ProviderError` and `TokenError`: answer those as a
refused login (401 / `oidc_failed`) and everything else as the provider being
unavailable (502 / `idp_unavailable`).

## Standards coverage

| Specification | Supported |
|---|---|
| OpenID Connect Core 1.0, Authorization Code flow | yes. Implicit and hybrid flows are intentionally not supported |
| RFC 7636 PKCE | S256, always on |
| OIDC Core §3.1.2.1 request parameters | `scope`, `prompt`, `login_hint`, `id_token_hint`, `max_age`, `acr_values`, `ui_locales`, `claims_locales`, `display`, `response_mode`, `claims` |
| OIDC Core §3.1.3.7 ID token validation | signature (JWKS, algs from discovery), `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`, `at_hash`, plus `auth_time` with `max_age` and `acr` with `require_acr` |
| OIDC Core §5.1 standard claims, §5.4 scope claims, §5.5 claims request | yes (`ClaimsRequest`, `ClaimRequest`) |
| OIDC Core §5.3 UserInfo | merged at login (`skip_userinfo` disables it); `sub` must match the ID token |
| OIDC Core §9 client authentication | `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none` |
| OIDC Core §12 refresh tokens | `refresh`; the refreshed ID token is verified |
| OAuth 2.0 Form Post Response Mode | `LoginOptions(response_mode=RESPONSE_MODE_FORM_POST)` |
| RFC 9207 `iss` authorization response parameter | checked when present |
| RFC 7009 token revocation | `revoke` |
| OIDC Discovery 1.0 | yes; `discovery_url` overrides the URL; `await client.discovery()` returns the metadata |
| OIDC RP-Initiated Logout 1.0 | `logout_url` (`id_token_hint`, `logout_hint`, `ui_locales`, `state`) |
| OIDC Back-Channel Logout 1.0 | `verify_logout_token`, `OIDCHandler.backchannel_logout` |

## Scopes and claims

The default scopes are `openid profile email`. Change them for every login
with `Config.scopes`, or for one login with `LoginOptions(scopes=...)` /
`LoginOptions(extra_scopes=...)`:

| Scope | `Identity` fields |
|---|---|
| `openid` (always sent) | `issuer`, `subject`, `auth_time`, `acr`, `amr`, `session_id` |
| `profile` | `name`, `given_name`, `family_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `phone` | `phone_number`, `phone_number_verified` |
| `address` | `address` (`Address`) |
| `offline_access` | `tokens.refresh_token` |

A provider may grant fewer scopes than requested. Check the result with
`identity.tokens.has_scope(oidcauth.SCOPE_EMAIL)`. All claims, standard or
not, are available in `identity.claims`. `identity.has_role(...)` and
`identity.display_name()` are small helpers.

```python
from datetime import timedelta

from oidcauth import (
    PROMPT_SELECT_ACCOUNT,
    SCOPE_OFFLINE_ACCESS,
    SCOPE_PHONE,
    LoginOptions,
)

auth_url, cookie = await client.start(
    LoginOptions(
        extra_scopes=[SCOPE_PHONE, SCOPE_OFFLINE_ACCESS],
        prompt=[PROMPT_SELECT_ACCOUNT],
        ui_locales=["vi", "en"],
        max_age=timedelta(minutes=15),  # re-authenticate if older; auth_time is checked
    )
)
# Keyword arguments work too: await client.start(return_to="/jobs", extra_scopes=[...])
```

Custom parameters go in `LoginOptions(params={"hd": "example.com"})`;
parameters with a dedicated option (`scope`, `prompt`, `state`, ...) raise
`ValueError` there.

## Refresh, revoke, userinfo

```python
from oidcauth import TOKEN_TYPE_HINT_REFRESH

res = await client.refresh(identity.tokens.refresh_token)  # res.identity is None without an ID token
await client.revoke(refresh_token, TOKEN_TYPE_HINT_REFRESH)
claims = await client.userinfo(access_token, identity.subject)
```

Most apps do not need these. They are for apps that call provider APIs on
behalf of the user, or that want to tie their own session lifetime to the
provider grant.

## ID tokens from native apps

A mobile or desktop app logs in itself (authorization code + PKCE in the
system browser, as a public client) and sends its ID token to the backend,
which verifies it and issues its own session:

```python
from datetime import timedelta

identity = await client.verify_id_token(
    id_token,
    access_token=access_token,     # optional: checks at_hash, merges userinfo
    audience="native-app-client",  # the app's client id; default Config.client_id
    nonce=nonce,                   # optional: when the app sends its nonce
    max_age=timedelta(minutes=5),  # optional: refuse older tokens (now - iat)
)
```

It checks the signature, `iss`, `aud`, `azp`, `exp` and `iat` like a browser
login, and raises `TokenError` for an invalid token. The app's client may
belong to another project of the same provider: only the issuer must match.
An ID token is a bearer proof of the login, so keep `max_age` short and the
transport on HTTPS.

## Logout

```python
from oidcauth import LogoutToken

# RP-initiated: redirect the browser here after clearing the app session.
url = await client.logout_url(id_token, "https://app.example.com/", "")


# Back-channel: register https://app.example.com/api/v1/auth/oidc/backchannel-logout at the provider.
async def on_logout(request: Request, t: LogoutToken) -> None:
    # End app sessions of t.subject (all) or t.session_id (Identity.session_id at login).
    # Reject a t.jwt_id seen before t.expiry to stop replays.
    await sessions.end_provider(t.subject, t.session_id)


app.add_api_route(
    "/api/v1/auth/oidc/backchannel-logout",
    h.backchannel_logout(on_logout),
    methods=["POST"],
)
```

The back-channel endpoint answers 200 on success, 400 for an invalid token,
502 when the provider keys cannot be fetched and 501 when `on_logout` raises.

## Client authentication

| Config | Method |
|---|---|
| `client_secret` | `client_secret_basic` (falls back to `client_secret_post` when discovery only lists that). Set `token_endpoint_auth_method=AUTH_METHOD_CLIENT_SECRET_POST` to force `client_secret_post` |
| `client_key` + `client_key_id` (PEM RSA or EC; Zitadel app key JSON `key` / `keyId`) | `private_key_jwt` |
| neither | `none`: a public client, protected by PKCE |

## Linking identities

Store `(identity.issuer, identity.subject)` as the unique key of an external
identity. Match by `email` only when `email_verified` is true, and only for
providers you trust to verify email.

## Zitadel notes

- Roles arrive in `urn:zitadel:iam:org:project:roles` once the project has
  **"Return user roles during authentication"** enabled. Turn on **"Only
  authorized users can authenticate"** to block users without a role
  assignment.
- To pin login to one organization, use
  `LoginOptions(extra_scopes=["urn:zitadel:iam:org:id:<orgId>"])`.

## Zitadel identity provider login without Zitadel's pages

The `oidcauth.zitadel` and `oidcauth.zitadel.fastapi` modules are optional and
**Zitadel-only**. With them, a "Sign in with Google" button can log in to
Zitadel without Zitadel's login UI: the browser only sees Google's page. The
app plays Zitadel's login UI through the v2 API, the way Login V2 does.

```text
GET  /auth/google/login                  ZitadelIDPHandler.login
     server side: authorize (not followed) → auth request V2_…
                  POST /v2/idp_intents → Google URL
  → Google → Zitadel /idps/callback
  → GET /auth/google/idp/callback?rq=…   ZitadelIDPHandler.callback
     retrieve intent → find / auto-link / auto-create the user
     POST /v2/sessions → POST /v2/oidc/auth_requests/{id}
  → GET <redirect_url>?code=…            OIDCHandler.callback (state, nonce, PKCE)
```

The result is a regular Zitadel login of the same client: same issuer,
subject, roles and back-channel logout.

```python
from oidcauth import LoginOptions
from oidcauth import zitadel
from oidcauth.zitadel.fastapi import ZitadelIDPHandler

api = zitadel.Client(client.config.issuer, os.environ["ZITADEL_SERVICE_PAT"])


def idp_error(request: Request, err: Exception) -> Response:
    if isinstance(err, zitadel.NotLinkedError):  # no user, no auto-link/creation
        ...
    elif isinstance(err, zitadel.MFARequiredError):  # org forces MFA for external logins
        ...
    return RedirectResponse("/login?error=...", 302)


idp = ZitadelIDPHandler(
    client,
    zitadel.IDPLogin(api, google_idp_id),
    tickets=tickets,  # the same TicketStore as the login tickets is fine
    callback_url="https://api.example.com/auth/google/idp/callback",
    login_options=lambda request: LoginOptions(
        extra_scopes=["urn:zitadel:iam:org:id:" + org_id]
    ),
    on_error=idp_error,
)
app.add_api_route("/auth/google/login", idp.login, methods=["GET"])
app.add_api_route("/auth/google/idp/callback", idp.callback, methods=["GET"])
# The code still arrives at the client's callback (OIDCHandler), with on_success as usual.
```

- **Service user**: a Zitadel service user with the *instance* role
  `IAM_LOGIN_CLIENT` and a personal access token.
- **Who can log in** follows the IdP options in Zitadel:
  - an already linked account;
  - *auto-linking* by verified email (exactly one matching user) or by
    username, if the user's org allows external IdPs and offers this IdP for
    linking;
  - *auto-creation* (a missing given or family name takes the other one, the
    display name or the email's local part) into the org of the
    `urn:zitadel:iam:org:id:` scope, or else the default org.
- **Errors** (`isinstance`; all `LoginError` subclasses carry `.detail`):

  | Exception | Meaning |
  |---|---|
  | `zitadel.NotLinkedError` | no user found or created |
  | `zitadel.NotAllowedError` | wrong org, or the org does not offer the IdP |
  | `zitadel.AccessDeniedError` | no project grant |
  | `zitadel.UserInactiveError` | user deactivated or locked |
  | `zitadel.MFARequiredError` | org forces MFA for external logins |
  | `zitadel.AuthRequestExpiredError` | auth request expired or already handled |
  | `zitadel.IntentFailedError` | cancelled at the IdP |
  | `oidcauth.InvalidStateError` | unknown or used ticket |
  | `zitadel.APIError` | other API failures (`.status`, `.message`) |
  | `zitadel.ZitadelError` | base class; also raised for network errors |

  `zitadel.is_user_error` separates refusals (any `LoginError`, or an
  `APIError` 4xx) from an unavailable Zitadel. The handler's default
  `on_error` answers 401 / 502 accordingly.
- **Why server-side authorize**: with Login V2 required on the instance,
  Zitadel ignores the per-app Login V2 base URI, so the app cannot be
  registered as the login UI.
- `oidcauth.zitadel.testing.FakeZitadel` is a fake of the v2 API on top of
  `oidcauth.testing.Provider`, for end-to-end tests.

## Testing

`oidcauth.testing.Provider` serves discovery, JWKS, token, userinfo,
revocation and end-session endpoints through an `httpx.MockTransport`, with
RS256-signed ID tokens. No network is needed:

```python
from oidcauth import Client, Config
from oidcauth.testing import Provider, User


async def test_login() -> None:
    op = Provider("client", "secret")
    client = Client(
        Config(
            issuer=op.issuer,
            client_id="client",
            client_secret="secret",
            redirect_url="https://app.example.com/callback",
            cookie_secret="0123456789abcdef0123456789abcdef",
            http_client=op.http_client(),
        )
    )
    auth_url, cookie = await client.start()
    params = op.authorize(
        auth_url, User(subject="u1", email="u1@example.com", email_verified=True)
    )
    res = await client.finish(params, cookie.value)
    assert res.identity.subject == "u1"
```

`User` also takes `roles` (emitted as Zitadel project roles), `extra`,
`userinfo_only`, `amr`, `acr`, `auth_time`, phone and address. The provider
has knobs for negative tests: `op.down = True` (unreachable),
`op.mutate_id_token`, `op.grant_scopes`, `op.refresh_without_id_token`, and
`op.logout_token(sub, sid)` signs a back-channel logout token.

The Zitadel IdP login is tested with `FakeZitadel`:

```python
from oidcauth import zitadel
from oidcauth.zitadel.testing import (
    DEFAULT_ORG_ID,
    IDP_ID,
    TOKEN,
    External,
    FakeZitadel,
    User as ZitadelUser,
)

op = Provider("c1", "s1")
fake = FakeZitadel(op)
fake.users["u1"] = ZitadelUser(id="u1", org_id=DEFAULT_ORG_ID)
fake.external = External(id="g-1", linked_to="u1")
login = zitadel.IDPLogin(zitadel.Client(op.issuer, TOKEN, fake.http_client()), IDP_ID)
# After ZitadelIDPHandler.login, follow fake.success_redirect() (or
# fake.failure_redirect("access_denied")) with the browser cookies.
```

See `tests/test_fastapi.py` and `tests/test_zitadel_fastapi.py` for complete
FastAPI wiring driven through `httpx.ASGITransport`.

## Development

```bash
uv sync                      # create .venv with the dev group
uv run pytest                # tests
uv run mypy                  # strict type check of src/oidcauth
uv run black src tests       # format
uv run isort src tests
uv run pre-commit install    # black, isort, mypy on commit
```

## License

MIT
