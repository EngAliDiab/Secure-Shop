import secrets, sqlite3, time
from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for
from .db import get_db
from .security import EMAIL_RE, EMAIL_RE as _E, clean, hash_pw, parse_int, to_cents

bp = Blueprint("admin", __name__, url_prefix="/admin")

@bp.before_request
def only_admin():  # every /admin/* route (GET and POST) passes through this gate
    if g.user is None:
        return redirect(url_for("auth.login"))
    if g.user["role"] != "admin":
        abort(403)

def _log(action):
    current_app.logger.info("ADMIN %s (id=%s): %s", g.user["email"], g.user["id"], action)

def _back(endpoint): return redirect(url_for(endpoint))

@bp.get("/")
def dashboard():
    db = get_db()
    stats = {t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("users", "products", "coupons", "orders")}
    return render_template("admin/index.html", stats=stats)

# ---------- users ----------
@bp.get("/users")
def users():
    return render_template("admin/users.html", users=get_db().execute("SELECT * FROM users ORDER BY id").fetchall())

@bp.post("/users/create")
def user_create():
    name, email = clean(request.form.get("name"), 60), clean(request.form.get("email"), 320).lower()
    pw, role = request.form.get("password", ""), request.form.get("role")
    if not name or not EMAIL_RE.match(email) or not 10 <= len(pw) <= 128 or role not in ("user", "admin"):
        flash("Provide a name, valid email, role and a password of 10-128 characters.", "error")
        return _back("admin.users")
    try:
        get_db().execute("INSERT INTO users(email,name,password_hash,role,verified,created_at) VALUES(?,?,?,?,1,?)",
                         (email, name, hash_pw(pw), role, int(time.time())))
        _log(f"created user {email} role={role}")
    except sqlite3.IntegrityError:
        flash("A user with that email already exists.", "error")
    return _back("admin.users")

@bp.post("/users/<int:uid>/update")
def user_update(uid):
    f = request.form
    name, email, role = clean(f.get("name"), 60), clean(f.get("email"), 320).lower(), f.get("role")
    credit, active = to_cents(f.get("credit", "")), 1 if f.get("active") == "1" else 0
    if not name or not EMAIL_RE.match(email) or role not in ("user", "admin") or credit is None:
        flash("Invalid user data.", "error")
        return _back("admin.users")
    if uid == g.user["id"] and (role != "admin" or not active):
        flash("You can't remove your own admin access.", "error")
        return _back("admin.users")
    try:  # explicit column whitelist; session_ver bump forces re-login after role/status changes
        n = get_db().execute("""UPDATE users SET name=?,email=?,role=?,credit_cents=?,active=?,
            session_ver=session_ver+? WHERE id=?""", (name, email, role, credit, active, 0 if uid == g.user["id"] else 1, uid)).rowcount
    except sqlite3.IntegrityError:
        flash("That email is already in use.", "error")
        return _back("admin.users")
    if not n:
        abort(404)
    _log(f"updated user {uid}")
    flash("User updated.", "ok")
    return _back("admin.users")

@bp.post("/users/<int:uid>/delete")
def user_delete(uid):
    if uid == g.user["id"]:
        flash("You can't delete your own account.", "error")
    else:
        try:
            get_db().execute("DELETE FROM users WHERE id=?", (uid,))
            _log(f"deleted user {uid}")
            flash("User deleted.", "ok")
        except sqlite3.IntegrityError:
            flash("This user has orders. Deactivate them instead of deleting.", "error")
    return _back("admin.users")

# ---------- products ----------
def _product_fields(f):
    name, cat, desc = clean(f.get("name"), 120), clean(f.get("category"), 40), clean(f.get("description"), 1000)
    price, stock = to_cents(f.get("price", "")), parse_int(f.get("stock"), 0, 100000)
    if not name or not cat or not price or stock is None:  # price must be > 0
        return None
    return name, desc, cat, price, stock

@bp.get("/products")
def products():
    return render_template("admin/products.html", products=get_db().execute("SELECT * FROM products ORDER BY id").fetchall())

@bp.post("/products/create")
def product_create():
    v = _product_fields(request.form)
    if not v:
        flash("Provide a name, category, a price above zero and a stock count of 0 or more.", "error")
    else:
        get_db().execute("INSERT INTO products(name,description,category,price_cents,stock) VALUES(?,?,?,?,?)", v)
        _log(f"created product {v[0]}")
        flash("Product created.", "ok")
    return _back("admin.products")

@bp.post("/products/<int:pid>/update")
def product_update(pid):
    v = _product_fields(request.form)
    if not v:
        flash("Invalid product data.", "error")
    else:
        n = get_db().execute("UPDATE products SET name=?,description=?,category=?,price_cents=?,stock=?,active=? WHERE id=?",
                             (*v, 1 if request.form.get("active") == "1" else 0, pid)).rowcount
        if not n:
            abort(404)
        _log(f"updated product {pid}")
        flash("Product updated.", "ok")
    return _back("admin.products")

@bp.post("/products/<int:pid>/delete")
def product_delete(pid):
    db = get_db()
    try:
        db.execute("DELETE FROM products WHERE id=?", (pid,))
        flash("Product deleted.", "ok")
    except sqlite3.IntegrityError:  # referenced by past orders: keep history, hide from shop
        db.execute("UPDATE products SET active=0 WHERE id=?", (pid,))
        flash("Product is part of past orders, so it was hidden instead of deleted.", "ok")
    _log(f"deleted product {pid}")
    return _back("admin.products")

# ---------- coupons ----------
@bp.get("/coupons")
def coupons():
    return render_template("admin/coupons.html", coupons=get_db().execute("SELECT * FROM coupons ORDER BY id DESC").fetchall())

@bp.post("/coupons/create")
def coupon_create():
    f = request.form
    code = clean(f.get("code"), 40).upper() or "SS-" + secrets.token_hex(4).upper()
    pct, uses, days = parse_int(f.get("percent"), 1, 90), parse_int(f.get("max_uses"), 1, 100000), parse_int(f.get("days"), 1, 3650)
    if None in (pct, uses, days):
        flash("Percent must be 1-90, max uses 1 or more, and validity 1-3650 days.", "error")
        return _back("admin.coupons")
    try:
        get_db().execute("INSERT INTO coupons(code,percent,max_uses,expires_at) VALUES(?,?,?,?)",
                         (code, pct, uses, int(time.time()) + days * 86400))
        _log(f"created coupon {code}")
        flash(f"Coupon {code} created.", "ok")
    except sqlite3.IntegrityError:
        flash("That coupon code already exists.", "error")
    return _back("admin.coupons")

@bp.post("/coupons/<int:cid>/update")
def coupon_update(cid):
    f = request.form
    pct, uses = parse_int(f.get("percent"), 1, 90), parse_int(f.get("max_uses"), 1, 100000)
    if None in (pct, uses):
        flash("Invalid coupon data.", "error")
        return _back("admin.coupons")
    try:
        get_db().execute("UPDATE coupons SET percent=?,max_uses=?,active=? WHERE id=?",
                         (pct, uses, 1 if f.get("active") == "1" else 0, cid))
        _log(f"updated coupon {cid}")
        flash("Coupon updated.", "ok")
    except sqlite3.IntegrityError:
        flash("Max uses can't be lower than the number of times it was already used.", "error")
    return _back("admin.coupons")

@bp.post("/coupons/<int:cid>/delete")
def coupon_delete(cid):
    get_db().execute("DELETE FROM coupons WHERE id=?", (cid,))
    _log(f"deleted coupon {cid}")
    flash("Coupon deleted.", "ok")
    return _back("admin.coupons")
