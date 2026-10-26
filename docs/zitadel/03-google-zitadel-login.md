# 03. Google qua Zitadel (có trang Zitadel)

Kết quả: nút "Đăng nhập bằng Google" trong app. Trình duyệt đi
app → Zitadel → Google → Zitadel → app. User trong app là **user Zitadel**
(role, back-channel logout như [01](01-web-app.md)). Zitadel có thể hiện một
trang ở giữa (chọn tài khoản, đăng ký, MFA, báo lỗi).

Không muốn thấy trang Zitadel: làm §1–§3 ở đây rồi sang
[04](04-google-headless.md) thay cho §4.

Cần làm trước: [01](01-web-app.md).

## 1. Tạo OAuth client ở Google Cloud

Làm một lần cho mỗi instance Zitadel (một client Google dùng được cho nhiều
IdP / org).

1. Mở <https://console.cloud.google.com/> → chọn (hoặc tạo) project.
2. **APIs & Services** → **OAuth consent screen**:
   - Lần đầu: chọn **External** (Gmail bất kỳ) hoặc **Internal** (chỉ
     Google Workspace của công ty) → điền tên app, email hỗ trợ, domain →
     lưu.
   - App ở trạng thái **Testing** chỉ cho các test user đã khai báo đăng nhập;
     ấn **Publish app** khi chạy thật.
3. **APIs & Services** → **Credentials** → **Create credentials** →
   **OAuth client ID**:
   - **Application type**: **Web application**.
   - **Name**: vd. `zitadel`.
   - **Authorized redirect URIs** → **Add URI**:
     `https://<zitadel>/idps/callback` (vd. `https://id.example.com/idps/callback`).
     Đây là callback của Zitadel, **không** phải của app.
   - **Create**.
4. Copy **Client ID** và **Client secret**.

> Giao diện Google Cloud đổi tên menu theo thời gian (vd. **Google Auth
> Platform** → **Clients**); các trường giữ nguyên.

## 2. Quyết định cấp của IdP và ai được vào

| Cấp | Tạo ở | Áp dụng |
|---|---|---|
| Instance | **Default settings** → **Identity Providers** | Mọi org (mỗi org có thể **set as not available**) |
| Organization | **Organization** (chọn org) → **Identity Providers** | Chỉ org đó |

Các tuỳ chọn của IdP quyết định user nào đăng nhập được:

| Tuỳ chọn | Ý nghĩa | Gợi ý |
|---|---|---|
| **Automatic creation** | Chưa có user → tự tạo user Zitadel từ tài khoản Google | Bật cho org khách hàng (ai cũng đăng ký được). Tắt cho org nội bộ |
| **Automatic update** | Cập nhật tên/email từ Google mỗi lần login | Tuỳ |
| **Account creation allowed (manually)** | Trang Zitadel cho user tự tạo tài khoản từ Google | Theo **Automatic creation** |
| **Account linking allowed (manually)** | User đã có tài khoản Zitadel được liên kết Google | Bật |
| Auto-linking: **Disabled** / **Check for existing Username** / **Check for existing Email** | Tự liên kết Google với user Zitadel trùng email (hoặc username) | **Check for existing Email** cho nhân viên đã có tài khoản |

Mô hình phổ biến:

- Nội bộ: IdP cấp instance, **Check for existing Email**, **Automatic
  creation** tắt → chỉ nhân viên đã có tài khoản (trùng email) vào được.
- Khách hàng: IdP riêng của org khách, **Automatic creation** bật → khách
  mới được tạo trong org khách. Ở org khách **set as not available** IdP cấp
  instance để không có hai nút Google.

## 3. Thêm Google vào Zitadel

1. Vào **Default settings** (cấp instance) hoặc chọn org → **Organization**
   (cấp org) → **Identity Providers**.
2. **Add provider** → **Google Provider**.
3. Điền:
   - **Client ID**, **Client Secret**: từ §1.
   - **Name** (tuỳ chọn): chữ trên nút ở trang Zitadel, vd. `Google`.
   - **Scopes List** (tuỳ chọn): để mặc định (`openid profile email`).
   - Các tuỳ chọn theo §2.
4. **Create**.
5. Khung **What now?** hiện ra:
   - **Configure your Google Identity Provider**: URL callback để dán vào
     Google (đã làm ở §1; kiểm tra lại cho khớp).
   - **Activate the IdP** → ấn **Activate**. Chưa activate thì IdP không
     xuất hiện ở trang login.
6. Ghi lại **Identity Provider ID** (trang chi tiết IdP, hoặc phần cuối URL
   `/instance/provider/google/<id>` / `/org/provider/google/<id>`).

Kiểm tra trạng thái: danh sách **Identity Providers** có cột **Availability**,
**Name**, **Type**, **Status**, **Owner** (**Instance** / **Organization**).
Status phải là active, Availability là available ở org cần dùng (nếu không:
menu dòng → **set as available**).

### 3.1 Cho phép đăng nhập ngoài ở org

Org → **Settings** → **Login Behavior and Security**:

| Tuỳ chọn | Giá trị |
|---|---|
| **External Login allowed** | Bật (bắt buộc) |
| **Local authentication allowed** | Tuỳ: tắt nếu org chỉ dùng Google |
| **User Registration allowed** | Bật nếu muốn khách tự đăng ký |
| **Force MFA for all users** / **Force MFA for local authenticated users only** | Xem lưu ý MFA ở [04](04-google-headless.md#51-mfa) |

**Save**.

## 4. Nút Google trong app (qua trang Zitadel)

Nút Google dùng lại client của [01](01-web-app.md) và gửi thêm scope
`urn:zitadel:iam:org:idp:id:<idp id>`. Zitadel thấy scope này thì chuyển
thẳng sang Google thay vì hiện form đăng nhập.

```dotenv
AUTH_OIDC_PROVIDERS=google
AUTH_OIDC_GOOGLE_VIA=sso
AUTH_OIDC_GOOGLE_PROVIDER_NAME=Google
AUTH_OIDC_GOOGLE_EXTRA_SCOPES=urn:zitadel:iam:org:idp:id:<Identity Provider ID>
```

IdP riêng của org khách thì thêm cả scope org (cách nhau bởi dấu cách):

```dotenv
AUTH_OIDC_GOOGLE_EXTRA_SCOPES="urn:zitadel:iam:org:id:<org id> urn:zitadel:iam:org:idp:id:<idp id>"
```

Không cần thêm redirect URI: nút có `VIA` dùng callback của provider chính.
Khởi động lại API, trang login của SPA có thêm nút **Google** (route
`/api/auth/oidc/google/login`).

Tự wiring:

```python
idp_scope = "urn:zitadel:iam:org:idp:id:" + google_idp_id
# handler riêng cho nút Google, cùng client với nút Zitadel:
google = OIDCHandler(
    client,
    login_options=lambda request: LoginOptions(extra_scopes=[idp_scope]),
    on_success=on_success,
    on_error=on_error,
)
app.add_api_route("/api/auth/oidc/google/login", google.login, methods=["GET"])
# callback vẫn là /api/auth/oidc/callback của handler chính
```

## 5. Thử

1. Trang login SPA → **Google** → trang Google → chọn tài khoản.
2. Theo §2, Zitadel liên kết / tạo user (có thể hiện trang xác nhận) → quay về
   app.
3. App map user Zitadel sang user app theo `LINK_*`
   ([05 §3](05-logout-and-linking.md#3-liên-kết-tài-khoản-với-user-của-app)).

Không vào được: [troubleshooting.md](troubleshooting.md).
