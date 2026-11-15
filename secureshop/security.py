"""Security middleware: hashing, CSRF, rate limiting, authz decorators, input helpers."""
import hmac, re, secrets, time
from decimal import Decimal, InvalidOperation
from functools import wraps
from flask import abort, g, redirect, request, session, url_for

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerifyMismatchError
    _ph = PasswordHasher()

    def hash_pw(p): return _ph.hash(p)

    def check_pw(h, p):
        try:
            return _ph.verify(h, p)
        except (VerifyMismatchError, InvalidHashError):
            return False
except ImportError:  # fallback so the app still runs without argon2-cffi installed
    from werkzeug.security import check_password_hash, generate_password_hash

    def hash_pw(p): return generate_password_hash(p, method="scrypt")
    def check_pw(h, p): return check_password_hash(h, p)

DUMMY_HASH = hash_pw("timing-equaliser")  # verified when the email is unknown (no user enumeration)
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")

# ---------- input helpers ----------
def clean(s, maxlen):
    return _CTRL.sub("", (s or "")).strip()[:maxlen]

def parse_int(v, lo, hi):
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if lo <= n <= hi else None

def to_cents(v, hi_dollars=1_000_000):
    try:
        d = Decimal(str(v).strip())
    except InvalidOperation:
        return None
    if not d.is_finite():
        return None
    c = int((d * 100).to_integral_value())
    return c if 0 <= c <= hi_dollars * 100 else None

# ---------- CSRF ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]

def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        expected = session.get("csrf", "")
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400)

# ---------- rate limiting (in-memory; use Redis behind multiple workers) ----------
_hits = {}

def allow(key, limit, window):
    now = time.time()
    q = [t for t in _hits.get(key, []) if now - t < window]
    ok = len(q) < limit
    if ok:
        q.append(now)
    _hits[key] = q
    return ok

def limited(name, limit, window):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if request.method == "POST" and not allow(f"{name}:{request.remote_addr}", limit, window):
                abort(429)
            return f(*a, **k)
        return w
    return deco

# ---------- authorization ----------
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if g.user is None:
            return redirect(url_for("auth.login"))
        if g.user["role"] != "admin":  # role comes from the DB, never from the cookie
            abort(403)
        return f(*a, **k)
    return w
