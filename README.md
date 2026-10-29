# Fresh Vegbox

A responsive vegetable storefront with a local Python backend, SQLite database, customer accounts, and protected shop administration. The storefront and admin UI use plain HTML, CSS, and JavaScript; Python's standard library provides the server and database, so no third-party packages are needed.

## Start the local shop

Install Python 3.10 or later, then open a terminal in this folder and create the first admin account:

```text
python server.py --setup-admin
```

Enter `haramsatish970@gmail.com` as the admin username and choose a unique password with at least 12 characters when prompted; typed password characters display only as `*`. The password is hashed before it is saved; it is not stored in a project file. If you need to change the admin password later, run `python server.py --reset-admin-password`. Next, start the application:

```text
python server.py
```

Open the shop at <http://127.0.0.1:8000/> and the admin panel at <http://127.0.0.1:8000/admin>. On Windows, double-click `run_server.bat` to start the backend in a separate minimized window; the script waits for the API to respond before opening the shop. Keep the **Fresh Vegbox Server** window open while using the site. Close that window to stop the server. Alternatively, run `python server.py` in a terminal and keep that terminal open. `setup_admin.bat` is the Windows admin setup helper.

The server binds to `127.0.0.1` only; it is not public or accessible from other devices. The SQLite database is created in `data/fresh-vegbox.sqlite3` and is excluded from the source ZIP. Back up this database to preserve products, customer accounts, orders, stock, and subscriptions. Set `FRESH_VEGBOX_PORT` or `FRESH_VEGBOX_DATABASE` before launching to override the local port or database path.

Open the admin panel using its `http://127.0.0.1:8000/admin` address while the backend is running; opening `admin.html` directly from the folder bypasses the API.

For product images, either paste an online `https://` image URL or select a PNG, JPEG, or WebP image from your computer (up to 5 MB). Uploaded images are copied into `assets/uploads/`, and products use the resulting local URL. Keep that folder alongside the project and back it up with the database; uploaded images are excluded from source-code ZIPs.

## Features

- Responsive desktop and mobile layouts
- Individual Home (`/`), About (`/about`), Products (`/products`), Blog (`/blog`), Contact Us (`/contact`), Sign in (`/signin`), and Create account (`/signup`) pages
- Products navigation dropdown links to product categories
- About section with Fresh Vegbox mission, vision, and a supply-chain comparison table
- Search, category filters, and products loaded from the database
- Price and weight filters, plus product sorting
- Persistent product catalog and stock management
- Product images can use an online URL or be uploaded from the admin computer
- Customer signup and sign-in with salted PBKDF2 password hashes
- Customer password recovery by 6-digit OTP sent to the registered email and WhatsApp when delivery services are configured
- Checkout orders with stock checks and inventory updates
- Admin order status management, including stock restoration on cancellation
- Subscription requests with admin status management
- Admin can add subscription plans with per-delivery pricing, delivery frequency, and free delivery up to 3 km
- Admin customer, product, order, and subscription views
- Floating WhatsApp contact button for the Fresh Vegbox business number
- Favorite buttons
- Accessible labels and reduced-motion support

## Local accounts, orders, and subscriptions

Customers can register/sign in, place orders, and request a subscription plan offered in the admin panel. Subscription requests require admin confirmation. Orders are recorded as pending and payment is handled offline; there is no payment processor, order/subscription notification email or SMS, automatic recurring billing, or scheduled delivery integration.

Admin data and customer records are stored on this computer. The login protects the admin panel and API, but the application is intended for local development and single-machine use, not public internet deployment. Hosting it publicly requires a production deployment review, HTTPS, backups, monitoring, rate limits, privacy/legal review, and payment/delivery integrations.

### Customer password recovery

The sign-in panel offers **Forgot password?** recovery using a 6-digit OTP sent to both the customer's registered email and WhatsApp number. The same OTP expires after 3 minutes, can be used once, and is limited to five verification attempts. A WhatsApp contact link is also available for help.

Configure email delivery with `FRESH_VEGBOX_SMTP_HOST`, `FRESH_VEGBOX_EMAIL_FROM`, and optionally `FRESH_VEGBOX_SMTP_PORT` (defaults to STARTTLS port 587), `FRESH_VEGBOX_SMTP_USERNAME`, and `FRESH_VEGBOX_SMTP_PASSWORD`. Port 465 uses implicit TLS. Configure Meta WhatsApp Cloud API delivery with `FRESH_VEGBOX_WHATSAPP_TOKEN`, `FRESH_VEGBOX_WHATSAPP_PHONE_NUMBER_ID`, `FRESH_VEGBOX_WHATSAPP_TEMPLATE_NAME`, and `FRESH_VEGBOX_WHATSAPP_API_VERSION` (for example `v23.0`); optionally set `FRESH_VEGBOX_WHATSAPP_TEMPLATE_LANGUAGE` (defaults to `en`). The approved WhatsApp message template must contain a body text placeholder for the OTP and be eligible for delivery to the customer's opted-in number. Set configuration in the private environment used to launch the server, never in project files or chat, then restart the server. `FRESH_VEGBOX_PUBLIC_URL` may be set for public deployments but is not used by the local OTP flow.

The OTP is stored as a salted PBKDF2 hash. After a successful password reset, existing customer sessions are signed out. Both delivery channels must be configured; otherwise recovery reports that OTP delivery is unavailable rather than claiming a code was sent.

## Run tests

```text
python -m unittest discover -s tests -v
```

## External resources

The supplied Fresh Vegbox logo is displayed in the website header as `assets/fresh-vegbox-logo.png`, with its basket artwork used for the browser tab icon in `assets/fresh-vegbox-favicon.png`. The Home and About image sliders use local copies of Unsplash photos in `assets/hero-*.jpg` and `assets/about-*.jpg`; these third-party images are not covered by the project license. Product photographs load from the image CDN used by the referenced catalog. An internet connection is required to display product photos. Image rights and terms are set by their providers; the project license below does not apply to third-party assets.

## License

Original project code is provided under the MIT License. See `LICENSE`.
