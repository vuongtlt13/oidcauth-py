# Provider khác Zitadel

Các module lõi (`oidcauth`, `oidcauth.fastapi`, `oidcauth.testing`) chạy với
mọi OpenID Provider có discovery. Các module `oidcauth.zitadel.*` chỉ dành cho
Zitadel.

Mọi provider đều cần ba thứ: **issuer**, **client ID / secret**, và **redirect
URI** của API đăng ký ở provider. Phần còn lại giống [setup.md](setup.md).

## 1. Google trực tiếp (không qua Zitadel)

User trong app là tài khoản Google (issuer `https://accounts.google.com`),
không có role hay back-channel logout. Dùng khi app không cần Zitadel.

### Google Cloud

1. <https://console.cloud.google.com/> → **APIs & Services** → **OAuth consent
   screen**: cấu hình như [03 §1](zitadel/03-google-zitadel-login.md#1-tạo-oauth-client-ở-google-cloud).
2. **Credentials** → **Create credentials** → **OAuth client ID**:
   - **Application type**: **Web application**.
   - **Authorized redirect URIs**:
     - `https://api.example.com/api/auth/oidc/google/callback`
     - `http://localhost:8000/api/auth/oidc/google/callback` (Google cho phép
       `http://localhost`).
   - **Create** → copy **Client ID**, **Client secret**.

### Env (nút phụ `google` bên cạnh provider chính)

```dotenv
AUTH_OIDC_PROVIDERS=google
AUTH_OIDC_GOOGLE_PROVIDER_NAME=Google
AUTH_OIDC_GOOGLE_ISSUER=https://accounts.google.com
AUTH_OIDC_GOOGLE_CLIENT_ID=<client id>.apps.googleusercontent.com
AUTH_OIDC_GOOGLE_CLIENT_SECRET=<client secret>
AUTH_OIDC_GOOGLE_REDIRECT_URL=https://api.example.com/api/auth/oidc/google/callback

# Chỉ Google Workspace: chỉ nhận tài khoản thuộc domain.
# Gmail thường không có claim hd → bị chặn hết nếu bật.
# AUTH_OIDC_GOOGLE_PARAMS=hd:example.com          # gợi ý ở màn chọn tài khoản
# AUTH_OIDC_GOOGLE_REQUIRED_CLAIMS=hd:example.com # kiểm tra thật sau login
```

Google là provider **duy nhất** của app: đặt các giá trị trên vào
`AUTH_OIDC_ISSUER`, `AUTH_OIDC_CLIENT_ID`... (không `_GOOGLE_`), redirect URI
`/api/auth/oidc/callback`.

Ai vào được: tài khoản Google có email verified trùng user app (`LINK_*`),
hoặc đã liên kết ở Profile. Google không có `end_session_endpoint`: đăng xuất
chỉ kết thúc session app (`await client.logout_url(...)` raise
`NotSupportedError`).

Tự wiring:

```python
from fastapi import Request
from fastapi.responses import RedirectResponse, Response

from oidcauth import Client, Config, LoginOptions, Result
from oidcauth.fastapi import OIDCHandler

client = Client(
    Config(
        issuer="https://accounts.google.com",
        client_id=client_id,
        client_secret=client_secret,
        redirect_url="https://api.example.com/api/auth/oidc/google/callback",
        cookie_secret=cookie_secret,
        cookie_path="/api/auth/oidc/",
    )
)


async def on_success(request: Request, res: Result) -> Response:
    if res.identity.claims.get("hd") != "example.com":
        return RedirectResponse(frontend + "/auth/login?error=oidc_forbidden", 302)
    ...


h = OIDCHandler(
    client,
    login_options=lambda request: LoginOptions(params={"hd": "example.com"}),
    on_success=on_success,
)
```

## 2. Keycloak

1. Admin console → chọn realm → **Clients** → **Create client**:
   - **Client type**: OpenID Connect; **Client ID**: `billing-web` → **Next**.
   - **Client authentication**: On (confidential); **Standard flow**: On →
     **Next**.
   - **Valid redirect URIs**: `https://api.example.com/api/auth/oidc/callback`;
     **Valid post logout redirect URIs**: `https://app.example.com/auth/login`
     → **Save**.
2. Tab **Credentials** → copy **Client secret**.
3. Tab **Advanced** (hoặc **Settings** → **Logout settings**): **Backchannel
   logout URL** `https://api.example.com/api/auth/oidc/backchannel-logout`,
   bật **Backchannel logout session required**.

```dotenv
AUTH_OIDC_ISSUER=https://keycloak.example.com/realms/<realm>
AUTH_OIDC_CLIENT_ID=billing-web
AUTH_OIDC_CLIENT_SECRET=<secret>
```

Role: Keycloak để role trong `realm_access.roles` và
`resource_access.<client>.roles`, không phải `roles`. Đặt `role_extractor`:

```python
from typing import Any


def keycloak_roles(claims: dict[str, Any]) -> list[str]:
    realm = claims.get("realm_access")
    roles = realm.get("roles") if isinstance(realm, dict) else None
    return [r for r in roles or [] if isinstance(r, str)]


Config(..., role_extractor=keycloak_roles)
```

Hoặc thêm mapper **User Realm Role** với **Token Claim Name** `roles` vào
client scope để role mặc định đọc được.

## 3. Microsoft Entra ID

1. Azure portal → **Microsoft Entra ID** → **App registrations** → **New
   registration**: tên, **Supported account types**, **Redirect URI** chọn
   **Web** = `https://api.example.com/api/auth/oidc/callback` → **Register**.
2. **Certificates & secrets** → **New client secret** → copy **Value**.
3. **Authentication** → **Front-channel logout URL** tuỳ chọn.
4. **App roles** → tạo role; gán ở **Enterprise applications** → **Users
   and groups**. Role nằm ở claim `roles` (mặc định đọc được).

```dotenv
AUTH_OIDC_ISSUER=https://login.microsoftonline.com/<tenant id>/v2.0
AUTH_OIDC_CLIENT_ID=<Application (client) ID>
AUTH_OIDC_CLIENT_SECRET=<secret value>
```

Tenant `common` / `organizations` có issuer thay đổi theo tenant của user,
không khớp discovery: dùng tenant ID cụ thể. Email Entra không phải lúc nào
cũng có `email_verified`; liên kết theo `preferred_username` hoặc liên kết thủ
công.

## 4. Auth0

1. Dashboard → **Applications** → **Create Application** → **Regular Web
   Applications**.
2. **Settings**: **Allowed Callback URLs**
   `https://api.example.com/api/auth/oidc/callback`, **Allowed Logout URLs**
   `https://app.example.com/auth/login` → **Save Changes**.
3. Copy **Domain**, **Client ID**, **Client Secret**.

```dotenv
AUTH_OIDC_ISSUER=https://<tenant>.auth0.com/   # có "/" cuối, đúng như discovery
AUTH_OIDC_CLIENT_ID=<client id>
AUTH_OIDC_CLIENT_SECRET=<client secret>
```

Role: thêm Action đặt custom claim (vd. `https://example.com/roles`) rồi đọc
bằng `role_extractor`.

## 5. Provider bất kỳ

1. Lấy issuer: `curl <issuer>/.well-known/openid-configuration | jq .issuer`;
   giá trị này phải khớp từng ký tự với `AUTH_OIDC_ISSUER`.
2. Tạo client loại "web / confidential", luồng Authorization Code, đăng ký
   redirect URI của API.
3. Provider không hỗ trợ `userinfo`: đặt `Config(skip_userinfo=True)`.
4. Role ở claim khác: `role_extractor`.
5. Thử end-to-end mà không cần provider thật: `oidcauth.testing.Provider`
   (xem README thư viện, mục Testing).
