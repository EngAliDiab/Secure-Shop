# SecureShop

Security-hardened e-commerce demo: **Python 3.10+ / Flask / SQLite / Jinja2 / plain CSS** (no JavaScript, so a strict CSP with no `unsafe-inline` works).

## Setup
```bash
python -m venv venv && source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python seed.py                                          # creates instance/secureshop.db + sample data
SECURESHOP_DEV=1 python run.py                          # http://127.0.0.1:5000  (Windows PowerShell: $env:SECURESHOP_DEV=1)
python -m unittest tests.test_security                  # 14 security/business-logic tests
```
`SECURESHOP_DEV=1` is for plain-HTTP localhost only: it relaxes the `Secure` cookie flag and HSTS. Never set it in production (serve behind HTTPS; set `SECRET_KEY` in the environment).

**Email verification:** there is no SMTP server, so the verification link is printed to the server console (look for `EMAIL VERIFICATION LINK`). Open it to activate a new account.

## Test accounts (pre-verified, dev only; override with `SEED_USER_PASSWORD` / `SEED_ADMIN_PASSWORD`)
| Role | Email | Password | Store credit |
|---|---|---|---|
| User | alice@secureshop.test | `User#Pass2026!` | $150.00 |
| Admin | admin@secureshop.test | `Admin#Pass2026!` | $0.00 |

Seeded coupon: `WELCOME10` (10%, once per user). The newsletter form issues a single-use 10% coupon tied to the subscriber's email.

## Architecture & security overview
```
secureshop/
  __init__.py   app factory: cookie config, before_request (CSRF + session load), security headers, error pages
  security.py   Argon2 hashing, CSRF, rate limiter, login_required/admin_required, input parsing
  db.py         schema (CHECK/UNIQUE/FK constraints), connection, tx() = BEGIN IMMEDIATE
  auth.py       register, verify, login, logout, account, password change
  shop.py       catalogue, cart, coupons, newsletter, checkout, orders
  admin.py      CRUD for users/products/coupons (blueprint-wide admin gate)
  templates/ static/    Jinja2 (autoescape on), CSS only
```
Request flow: **rate limit** (decorator) → **CSRF check** (`guard`) → **session load** (user re-read from DB each request, role never trusted from the cookie) → **authorization** (`login_required` / `only_admin`) → handler using **parameterised SQL** and **server-side validation** → template with **auto-escaping** → **security headers** added in `add_headers`.

Defence in depth for money: totals are always recomputed from DB prices; the database itself rejects negative credit, negative/zero prices, bad quantities and over-used coupons via `CHECK` constraints.

## Security coverage matrix
| Defense | Attack scenario in SecureShop | Root cause | Defense implemented | Location |
|---|---|---|---|---|
| SQL injection | `/?q=' OR 1=1--` on search; crafted login email | String-built SQL | Parameter binding everywhere; fixed SQL fragments; LIKE wildcards escaped; numeric filters parsed to ints | `shop.py:index`, `shop.py:_like`, `auth.py:login`, all of `admin.py` |
| Reflected/stored XSS | `<script>` in search, profile name, product description | Unescaped output | Jinja2 autoescape (no `\|safe` anywhere); control-char stripping; CSP `script-src 'self'`, no inline JS | `templates/*`, `security.py:clean`, `__init__.py:add_headers` |
| CSRF | Hostile page auto-submits "checkout", profile edit or admin delete | State change relies only on cookie | Per-session token, constant-time compare on every POST; `SameSite=Strict` cookie; logout is POST | `security.py:csrf_token/csrf_protect`, `__init__.py:guard`, `csrf_field()` in every form |
| Broken access control | User opens `/admin/users`, or `/orders/<other id>` | Missing authz / ownership checks | `only_admin` before every admin route; role read from DB; order lookup filtered by `user_id`, 404 on miss; cart queries scoped to current user | `admin.py:only_admin`, `security.py:admin_required`, `shop.py:order`, `shop.py:cart_*` |
| Mass assignment | Posting `role=admin` or `credit=9999` to profile | Binding all form fields | Profile endpoint writes only `name`/`email`; admin updates use explicit column lists | `auth.py:update_profile`, `admin.py:user_update` |
| Cart tampering | Quantity `-5`, `999`, `abc`; price in form | Trusting client values | `parse_int` bounds 1-10, clamped to stock; price never read from the client; DB `CHECK(qty BETWEEN 1 AND 10)` | `shop.py:cart_add/cart_update`, `db.py:SCHEMA` |
| Coupon abuse | Reuse, stacking, guessing codes, using someone else's newsletter code | No server-side state | Single session slot (no stacking); `coupon_redemptions` PK per user; atomic `used_count` increment; email-bound codes; one generic error; rate limit 10/5 min | `shop.py:check_coupon`, `coupon_apply`, `checkout`, `newsletter` |
| Race conditions / credit manipulation | Parallel checkouts to double-spend credit, oversell stock or reuse a coupon | Check-then-act without atomicity | `BEGIN IMMEDIATE` transaction; guarded `UPDATE ... WHERE credit_cents>=? / stock>=? / used_count<max_uses` with rowcount checks; integer cents; DB CHECKs | `db.py:tx`, `shop.py:checkout` |
| Password storage | DB leak | Weak/fast hashes | Argon2id (scrypt fallback if package missing); 10-128 char policy | `security.py:hash_pw/check_pw`, `auth.py` |
| Session attacks | Fixation, stolen cookie, replay after logout | Long-lived/unchanging session | `session.clear()` on login; `HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` prefix; 30 min lifetime; `session_ver` bump on logout/password/role change | `__init__.py:create_app`, `auth.py:login/logout/change_password` |
| Brute force / enumeration | Credential stuffing; probing which emails exist | Unlimited attempts, distinguishable responses | 10 logins/5 min/IP; 15 min account lockout after 5 failures; identical error + dummy hash verify; identical registration response; no `next` redirect (no open redirect) | `security.py:limited`, `auth.py:login/register` |
| Email verification | Registering with someone else's address | No ownership proof | 256-bit random token, only SHA-256 stored, 24 h expiry, single use; unverified accounts cannot log in | `auth.py:_issue_token/verify` |
| Headers & error handling | Clickjacking, MIME sniffing, stack-trace leakage | Defaults leak info | CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, HSTS, `no-store` for logged-in pages; custom 400/403/404/405/413/429/500; `DEBUG` off; exceptions logged, not shown; 32 KB request cap | `__init__.py:add_headers`, error `handler`, `templates/error.html` |

## Known limitations (be upfront in a report/viva)
- Rate limiter and lockout counters for IPs are in-memory (per process). Use Redis/Flask-Limiter with multiple workers, and configure a trusted proxy (`ProxyFix`) so `remote_addr` is correct.
- Email is logged to the console, not sent. Email changes are protected by password re-entry but not re-verified.
- No product reviews feature (not required); XSS defenses already cover all user-controlled fields.
- Store credit can only be granted by an admin (no payment gateway).
