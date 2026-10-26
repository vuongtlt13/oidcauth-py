# 01. Project và Web application

Kết quả: nút "Đăng nhập bằng `<Zitadel>`" trong app, chạy luồng Authorization
Code + PKCE, user đăng nhập ở trang login của Zitadel.

Làm một lần cho mỗi app (mỗi môi trường nên có application riêng, hoặc chung
application và đăng ký đủ redirect URI của các môi trường).

## Bước 1. Chọn organization

1. Console → ô chọn organization ở góc trên trái → chọn org sẽ **sở hữu**
   project. Với mô hình 2 org (xem [02 §4](02-roles-and-orgs.md#4-mô-hình-2-organization-nội-bộ--khách-hàng)),
   project nằm ở org nội bộ, org khách được cấp qua Project Grant.

## Bước 2. Tạo project

1. Menu **Projects** → **Create New Project**.
2. Nhập tên (vd. `Billing`) → **Continue** / **Create Project**.
3. Trang project mở ra. Ghi lại **Project ID** nếu cần.

Các checkbox của project (mục **General**) để ở mặc định cho trường hợp cơ
bản; bật chúng ở [02](02-roles-and-orgs.md) khi cần role.

## Bước 3. Tạo application: Name and Type

1. Trong trang project, khung **Applications** → **New**.
2. Bước **Name and Type**:
   - **Name**: tên hiển thị, vd. `billing-web` (hoặc `billing-web-dev`).
   - **Type of application**: chọn **Web** (backend giữ được secret).
3. **Continue**.

> Thấy form dài thay vì wizard: bạn đang ở chế độ **I'm a pro. Skip this
> wizard.** Các trường giống nhau, chỉ nằm trên một trang.

## Bước 4. Authentication Method

Chọn một trong các cách sau. Cả ba đều dùng PKCE (thư viện luôn gửi PKCE).

| Lựa chọn trong wizard | Phương thức | Biến env | Khi nào |
|---|---|---|---|
| **Code** | `client_secret_basic` | `AUTH_OIDC_CLIENT_SECRET` | Mặc định, đơn giản nhất |
| **POST** | `client_secret_post` | `AUTH_OIDC_CLIENT_SECRET` | Như Code; thư viện tự nhận ra qua discovery |
| **Private Key JWT** | `private_key_jwt` | `AUTH_OIDC_CLIENT_KEY_FILE` | Không muốn secret dạng chuỗi; xoay vòng key có hạn dùng |
| **PKCE** | `none` (public client) | không đặt secret lẫn key | Không có chỗ an toàn để giữ secret |

Chọn xong → **Continue**.

## Bước 5. Redirect URIs

1. **Redirect URIs**: nhập URL callback của API rồi Enter / nút **+**:
   - Production: `https://api.example.com/api/auth/oidc/callback`
   - Local: `http://localhost:8000/api/auth/oidc/callback`
2. **Post Logout URIs**: nơi Zitadel đưa user về sau khi đăng xuất:
   - Production: `https://app.example.com/auth/login`
   - Local: `http://localhost:3000/auth/login`
3. **Development Mode**: bật nếu có URI `http://` (local). Zitadel từ chối
   `http://` khi tắt. Ứng dụng production thì **tắt**.
4. **Continue**.

> Mỗi provider phụ có client riêng (không `VIA`) dùng callback
> `/api/auth/oidc/<key>/callback`, cũng phải nằm trong **Redirect URIs** của
> application tương ứng. Provider có `VIA` dùng lại callback của provider chính,
> không cần thêm.

## Bước 6. Overview → Create

1. Kiểm tra lại, ấn **Create**.
2. Với **Code** / **POST**: hộp thoại hiện **ClientId** và **ClientSecret**,
   kèm cảnh báo "Keep your client secret at a safe place as it will disappear
   once the dialog is closed." → **Copy to Clipboard** cho từng giá trị → lưu
   vào secret store → **Close**.
3. Với **PKCE** / **Private Key JWT**: chỉ có Client ID.

Mất secret: trang application → menu trên cùng → **Regenerate Client Secret**
(secret cũ hết hiệu lực ngay, phải cập nhật env và khởi động lại API).

## Bước 7 (chỉ Private Key JWT). Tạo key

1. Trang application → khung **Keys** → **New**.
2. Kiểu key **JSON**, ngày hết hạn tuỳ chọn → xác nhận.
3. **Download** → được file JSON dạng:

   ```json
   {"type":"application","keyId":"…","key":"-----BEGIN RSA PRIVATE KEY-----…","appId":"…","clientId":"…"}
   ```

4. Đặt file vào chỗ API đọc được (secret mount), vd. `/run/secrets/oidc-key.json`.

Template đọc file này; app tự wiring thì truyền `key` vào `Config.client_key`
và `keyId` vào `Config.client_key_id`:

```python
import json
from pathlib import Path

from oidcauth import Config

key = json.loads(Path("/run/secrets/oidc-key.json").read_text())
cfg = Config(
    issuer="https://id.example.com",
    client_id=key["clientId"],
    client_key=key["key"],        # PEM RSA/EC
    client_key_id=key["keyId"],
    redirect_url="https://api.example.com/api/auth/oidc/callback",
    cookie_secret=cookie_secret,
)
```

## Bước 8. Cấu hình application (trang chi tiết)

Trang application có sidenav **Settings**, **Token Settings**, **Redirect
Settings**, **Additional Origins**, **URLs**.

| Mục | Trường | Giá trị khuyên dùng |
|---|---|---|
| **Settings** | **Refresh Token** | Tắt, trừ khi app gọi API Zitadel thay user (`offline_access`) |
| **Settings** | **Use new Login UI** | Theo cấu hình instance; không ảnh hưởng thư viện |
| **Settings** | **Back-Channel Logout URI** | Xem [05 §2](05-logout-and-linking.md#2-back-channel-logout) |
| **Token Settings** | **Auth Token Type** | **Bearer Token** (thư viện không đọc access token) |
| **Token Settings** | **User roles inside ID Token** | Không bắt buộc: thư viện gọi userinfo và nhận role ở đó |
| **Token Settings** | **Include user's profile info in the ID Token** | Không bắt buộc, cùng lý do |
| **Redirect Settings** | **Redirect URIs**, **Post Logout URIs**, **Development Mode** | Sửa sau khi tạo |
| **URLs** | Issuer, các endpoint | Đối chiếu `AUTH_OIDC_ISSUER` |

Mỗi lần sửa ấn **Save** của khung đó.

## Bước 9. Biến env

```dotenv
AUTH_OIDC_ENABLED=true
AUTH_OIDC_PROVIDER_NAME=Viset ID              # chữ trên nút login
AUTH_OIDC_ISSUER=https://id.example.com
AUTH_OIDC_CLIENT_ID=<Client ID ở bước 6>

# Chọn MỘT theo bước 4:
AUTH_OIDC_CLIENT_SECRET=<ClientSecret>        # Code / POST
# AUTH_OIDC_CLIENT_KEY_FILE=/run/secrets/oidc-key.json   # Private Key JWT
#                                              # PKCE: để trống cả hai

AUTH_OIDC_REDIRECT_URL=https://api.example.com/api/auth/oidc/callback
AUTH_OIDC_POST_LOGOUT_REDIRECT_URL=https://app.example.com/auth/login
AUTH_OIDC_SCOPES="openid profile email"
AUTH_OIDC_COOKIE_SECRET=<openssl rand -base64 32>
AUTH_OIDC_COOKIE_INSECURE=false               # true chỉ khi local HTTP

# Liên kết lần đầu với user có sẵn trong app (xem 05 §3)
AUTH_OIDC_LINK_CLAIM=email
AUTH_OIDC_LINK_FIELD=email
```

Muốn **chỉ** đăng nhập qua Zitadel: thêm `AUTH_LOCAL_ENABLED=false`.

Khởi động lại API.

## Bước 10. Thử

1. Mở trang login của SPA → nút **Viset ID** (theo `PROVIDER_NAME`).
2. Đăng nhập ở Zitadel → quay về app, đã đăng nhập.
3. Lần đầu: user Zitadel phải khớp một user của app theo `LINK_*`, nếu không
   trang login báo `not_linked`. Tạo user trong app với cùng email (email phải
   **verified** ở Zitadel), hoặc liên kết từ trang profile.

Lỗi thường gặp: [troubleshooting.md](troubleshooting.md).
