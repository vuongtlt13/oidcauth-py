# Xử lý lỗi

Lỗi login về `<frontend>/auth/login?error=<mã>`, lỗi liên kết về
`<frontend>/profile?link_error=<mã>` (mã của backend template). Log API luôn
có lý do chi tiết; tìm theo `oidc` hoặc `zitadel idp login`.

## 1. Lỗi trên trang của Zitadel (chưa về app)

| Hiện tượng | Nguyên nhân | Cách sửa |
|---|---|---|
| `redirect_uri is missing in the client configuration` / invalid redirect | `AUTH_OIDC_REDIRECT_URL` không có trong **Redirect URIs** (sai scheme, host, port, `/` cuối) | Application → **Redirect Settings** → thêm đúng từng ký tự → **Save** |
| Redirect `http://…` bị từ chối | **Development Mode** tắt | Bật **Development Mode** (chỉ môi trường dev) |
| `post_logout_redirect_uri invalid` khi đăng xuất | Thiếu trong **Post Logout URIs** | Thêm như [05 §1](05-logout-and-linking.md#1-đăng-xuất-từ-app-rp-initiated-logout) |
| `Errors.App.NotFound` / `invalid_client` | Sai `AUTH_OIDC_CLIENT_ID`, application bị deactivate, hoặc sai instance | Đối chiếu Client ID ở trang application |
| Trang Zitadel không có nút Google | IdP chưa **Activate**, hoặc **set as not available** ở org, hoặc org tắt **External Login allowed** | [03 §3](03-google-zitadel-login.md#3-thêm-google-vào-zitadel) |
| Google báo `redirect_uri_mismatch` | OAuth client Google chưa có `https://<zitadel>/idps/callback` | [03 §1](03-google-zitadel-login.md#1-tạo-oauth-client-ở-google-cloud) |
| Google báo app chưa xác minh / chỉ test user vào được | OAuth consent screen ở **Testing** | Thêm test user hoặc **Publish app** |
| "User not authorized for this project" | Project check ([02 §2](02-roles-and-orgs.md#2-chặn-user-không-có-quyền-vào-app)) | Gán role, hoặc Project Grant cho org của user |

## 2. Mã lỗi trên trang login của app

| Mã | Nguyên nhân | Cách sửa |
|---|---|---|
| `not_linked` | Đăng nhập provider thành công nhưng không khớp user nào của app (`LINK_*`); hoặc (04) Zitadel không tìm / tạo được user | Tạo user app cùng email (email Zitadel phải **verified**), hoặc liên kết ở Profile. Với 04: bật auto-link / **Automatic creation** của IdP, đặt scope org, kiểm tra Google trả đủ họ + tên |
| `user_inactive` | User app bị khoá, hoặc user Zitadel bị deactivate / lock | Mở khoá |
| `not_allowed` | Không đạt `REQUIRED_CLAIMS` (vd. `hd`); hoặc (04) user ở org khác scope, org tắt **External Login allowed**, IdP không cho linking ở org đó | Kiểm tra `EXTRA_SCOPES` org, **Login Behavior and Security**, tuỳ chọn IdP |
| `access_denied` | Project check: thiếu role assignment hoặc org chưa được Project Grant | [02 §2](02-roles-and-orgs.md#2-chặn-user-không-có-quyền-vào-app) |
| `mfa_required` | (04) Org bật **Force MFA for all users** | [04 §5.1](04-google-headless.md#51-mfa) |
| `state_expired` | Flow cookie mất hoặc hết hạn: quá 10 phút ở trang login, mở lại link callback cũ, ấn Back, login và callback khác host (`localhost` vs `127.0.0.1`), cookie `Secure` trên HTTP | Thử lại; local HTTP đặt `AUTH_OIDC_COOKIE_INSECURE=true`; cùng host cho login và `REDIRECT_URL` |
| `oidc_failed` | Provider trả lỗi / user huỷ; code không đổi được (secret sai, PKCE); (04) PAT thiếu `IAM_LOGIN_CLIENT` (403) hoặc hết hạn (401) | Xem log; kiểm tra secret, PAT, role instance |
| `idp_unavailable` | Không gọi được provider (mạng, DNS, TLS, 5xx), hoặc discovery lỗi: `AUTH_OIDC_ISSUER` sai / thừa `/` cuối (`issuer does not match`) | Từ máy chạy API: `curl https://<zitadel>/.well-known/openid-configuration`, so `issuer` với env |
| `server_error` | Lỗi của app (DB, Redis TicketStore) | Xem log |

## 3. API không khởi động

| Log | Nguyên nhân |
|---|---|
| `ConfigError`: `cookie secret must be at least 32 characters` | `AUTH_OIDC_COOKIE_SECRET` < 32 ký tự |
| `IDP_ID needs SERVICE_TOKEN or SERVICE_TOKEN_FILE` | Thiếu PAT cho provider `IDP_ID` |
| `via "…" is not a provider with its own client` | `VIA` trỏ tới key không tồn tại hoặc provider cũng có `VIA` |
| `REQUIRED_CLAIMS is not supported with VIA` | Bỏ `REQUIRED_CLAIMS` hoặc dùng client riêng |
| `AUTH_OIDC_LINK_FIELD … want "email" or "username"` | Giá trị `LINK_FIELD` sai |

## 4. Kiểm tra nhanh

```bash
# Issuer đúng?
curl -s https://id.example.com/.well-known/openid-configuration | jq '.issuer, .end_session_endpoint'

# Các nút login đã bật
curl -s http://localhost:8000/api/auth/options | jq

# PAT còn hiệu lực và đủ quyền đọc IdP? (không in PAT ra terminal/log)
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $(cat /run/secrets/zitadel-login-pat)" \
  https://id.example.com/v2/idps/<idp id>
```

`200`: PAT dùng được. `401`: PAT sai / hết hạn. `403`: thiếu role
`IAM_LOGIN_CLIENT` ([04 §3](04-google-headless.md#3-gán-role-instance-iam_login_client)).
