# Tài liệu oidcauth-py

Hướng dẫn cài đặt `oidcauth-py` (import `oidcauth`) và tích hợp với Zitadel
(cùng các OpenID Provider khác), từng bước: vào màn hình nào, ấn nút gì, đặt
biến env gì.

| Tài liệu | Nội dung |
|---|---|
| [setup.md](setup.md) | Cài thư viện, wiring với FastAPI, bảng `Config` ↔ biến env, `TicketStore`, cookie, chạy local, checklist production |
| [zitadel/README.md](zitadel/README.md) | Bắt đầu với Zitadel: đăng nhập console, bản đồ màn hình, lấy issuer / Organization ID, **chọn trường hợp** |
| [zitadel/01-web-app.md](zitadel/01-web-app.md) | Tạo project + application cho app: client secret, Private Key JWT, PKCE (public client) |
| [zitadel/02-roles-and-orgs.md](zitadel/02-roles-and-orgs.md) | Role của project, chặn user không có quyền, ghim login vào một organization, project grant, mô hình 2 org (nội bộ / khách hàng) |
| [zitadel/03-google-zitadel-login.md](zitadel/03-google-zitadel-login.md) | Google qua Zitadel **có** trang login của Zitadel (tạo OAuth client Google, thêm IdP Google trong Zitadel) |
| [zitadel/04-google-headless.md](zitadel/04-google-headless.md) | Google qua Zitadel **không** qua trang Zitadel (`IDP_ID`, service account `IAM_LOGIN_CLIENT`) |
| [zitadel/05-logout-and-linking.md](zitadel/05-logout-and-linking.md) | Đăng xuất (RP-initiated, back-channel), liên kết tài khoản với user của app |
| [zitadel/troubleshooting.md](zitadel/troubleshooting.md) | Mã lỗi → nguyên nhân → cách sửa |
| [providers.md](providers.md) | Provider khác: Google trực tiếp, Keycloak, Microsoft Entra ID, Auth0, provider bất kỳ |

## Chọn nhanh

| Bạn muốn | Làm theo |
|---|---|
| Nút "Đăng nhập bằng Viset ID / SSO" (trang login của Zitadel) | [01-web-app](zitadel/01-web-app.md) |
| Phân quyền theo role từ Zitadel, chặn người ngoài | [01](zitadel/01-web-app.md) + [02](zitadel/02-roles-and-orgs.md) |
| App chỉ cho user của một organization (vd. khách hàng) | [01](zitadel/01-web-app.md) + [02 §3](zitadel/02-roles-and-orgs.md#3-ghim-login-vào-một-organization) |
| Nút "Đăng nhập bằng Google", user vẫn là user Zitadel, chấp nhận thấy trang Zitadel thoáng qua | [01](zitadel/01-web-app.md) + [03](zitadel/03-google-zitadel-login.md) |
| Nút "Đăng nhập bằng Google", trình duyệt chỉ thấy trang Google | [01](zitadel/01-web-app.md) + [03 §1–2](zitadel/03-google-zitadel-login.md) + [04](zitadel/04-google-headless.md) |
| Google mà không dùng Zitadel | [providers.md §1](providers.md#1-google-trực-tiếp-không-qua-zitadel) |
| Đăng xuất ở Zitadel thì app cũng đăng xuất | [05 §2](zitadel/05-logout-and-linking.md#2-back-channel-logout) |

## Quy ước trong tài liệu

- Nhãn giao diện (nút, menu, checkbox) giữ **nguyên tiếng Anh** như console
  Zitadel v4 hiển thị, in đậm: **Create**, **Save**...
- Biến env là quy ước của backend template Python (`templates/backend/python`,
  `AUTH_*`), giống hệt bộ biến của template Go. App tự wiring thư viện thì map
  sang trường `oidcauth.Config` theo bảng ở [setup.md](setup.md#2-config--biến-env).
- API của thư viện là **async**: mọi lời gọi có thể chạm tới provider đều
  `await` (`await client.start(...)`, `await client.finish(...)`...).
- Ví dụ dùng: Zitadel `https://id.example.com`, API `https://api.example.com`
  (local `http://localhost:8000`), SPA `https://app.example.com` (local
  `http://localhost:3000`). Thay bằng domain của bạn.
- Các route ví dụ theo backend template (prefix `/api`):

  | Route | Dùng cho |
  |---|---|
  | `GET /api/auth/oidc/login?redirect=/path` | Bắt đầu login provider chính |
  | `GET\|POST /api/auth/oidc/callback` | Redirect URI đăng ký ở provider |
  | `POST /api/auth/oidc/backchannel-logout` | Back-Channel Logout URI |
  | `GET /api/auth/oidc/<key>/login` | Nút login của provider phụ `<key>` |
  | `GET /api/auth/oidc/<key>/callback` | Callback của provider phụ có client riêng (không có `VIA`) |
  | `GET /api/auth/oidc/<key>/idp/callback` | Callback của Zitadel khi provider phụ có `IDP_ID` |
  | `POST /api/auth/oidc/exchange` | SPA đổi ticket lấy access token của app |
