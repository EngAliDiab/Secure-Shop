import secrets, sqlite3, time
from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for
from .db import get_db, tx
from .security import EMAIL_RE, clean, limited, login_required, parse_int

bp = Blueprint("shop", __name__)
COUPON_ERR = "That coupon code isn't valid."

def _like(s):  # neutralise LIKE wildcards in addition to parameter binding
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

@bp.get("/")
def index():
    db = get_db()
    q, cat = clean(request.args.get("q"), 80), clean(request.args.get("category"), 40)
    lo, hi = parse_int(request.args.get("min"), 0, 100000), parse_int(request.args.get("max"), 0, 100000)
    sql, args = "SELECT * FROM products WHERE active=1", []
    if q:
        sql += " AND (name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')"
        args += [_like(q)] * 2
    if cat:
        sql += " AND category=?"; args.append(cat)
    if lo is not None:
        sql += " AND price_cents>=?"; args.append(lo * 100)
    if hi is not None:
        sql += " AND price_cents<=?"; args.append(hi * 100)
    products = db.execute(sql + " ORDER BY name", args).fetchall()
    cats = [r[0] for r in db.execute("SELECT DISTINCT category FROM products WHERE active=1 ORDER BY 1")]
    return render_template("index.html", products=products, cats=cats, q=q, cat=cat,
                           lo=request.args.get("min", ""), hi=request.args.get("max", ""))

@bp.get("/product/<int:pid>")
def product(pid):
    p = get_db().execute("SELECT * FROM products WHERE id=? AND active=1", (pid,)).fetchone()
    if not p:
        abort(404)
    return render_template("product.html", p=p)

# ---------- coupons ----------
def check_coupon(db, code, user):
    c = db.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
    if (not c or not c["active"] or c["expires_at"] < time.time() or c["used_count"] >= c["max_uses"]
            or (c["bound_email"] and c["bound_email"].lower() != user["email"].lower())):
        return None, COUPON_ERR  # one message for every failure: no code probing
    if db.execute("SELECT 1 FROM coupon_redemptions WHERE coupon_id=? AND user_id=?", (c["id"], user["id"])).fetchone():
        return None, "You've already used this coupon."
    return c, None

def cart_view(db, user):
    items = db.execute("""SELECT c.product_id, c.qty, p.name, p.price_cents, p.stock FROM cart_items c
        JOIN products p ON p.id=c.product_id WHERE c.user_id=? AND p.active=1 ORDER BY p.name""", (user["id"],)).fetchall()
    subtotal = sum(i["qty"] * i["price_cents"] for i in items)   # prices always come from the DB
    coupon = None
    if session.get("coupon"):
        coupon, err = check_coupon(db, session["coupon"], user)
        if err:
            session.pop("coupon", None)
    discount = subtotal * coupon["percent"] // 100 if coupon else 0
    return dict(items=items, subtotal=subtotal, discount=discount, total=subtotal - discount, coupon=coupon)

@bp.get("/cart")
@login_required
def cart():
    return render_template("cart.html", **cart_view(get_db(), g.user))

@bp.post("/cart/add")
@login_required
def cart_add():
    db = get_db()
    pid, qty = parse_int(request.form.get("product_id"), 1, 10**9), parse_int(request.form.get("qty", "1"), 1, 10)
    p = db.execute("SELECT * FROM products WHERE id=? AND active=1", (pid,)).fetchone() if pid else None
    if not p or qty is None:
        flash("Choose a valid product and a quantity from 1 to 10.", "error")
        return redirect(url_for("shop.index"))
    have = db.execute("SELECT qty FROM cart_items WHERE user_id=? AND product_id=?", (g.user["id"], pid)).fetchone()
    new = min((have["qty"] if have else 0) + qty, 10, p["stock"])
    if new < 1:
        flash("That item is out of stock.", "error")
        return redirect(url_for("shop.product", pid=pid))
    db.execute("""INSERT INTO cart_items(user_id,product_id,qty) VALUES(?,?,?)
        ON CONFLICT(user_id,product_id) DO UPDATE SET qty=excluded.qty""", (g.user["id"], pid, new))
    flash("Added to cart.", "ok")
    return redirect(url_for("shop.cart"))

@bp.post("/cart/update")
@login_required
def cart_update():
    pid, qty = parse_int(request.form.get("product_id"), 1, 10**9), parse_int(request.form.get("qty"), 1, 10)
    if pid is None or qty is None:
        flash("Quantity must be a whole number from 1 to 10.", "error")
    else:  # scoped to the current user: another user's cart row can never match
        db = get_db()
        stock = db.execute("SELECT stock FROM products WHERE id=?", (pid,)).fetchone()
        db.execute("UPDATE cart_items SET qty=? WHERE user_id=? AND product_id=?",
                   (min(qty, stock["stock"] if stock else 1) or 1, g.user["id"], pid))
    return redirect(url_for("shop.cart"))

@bp.post("/cart/remove")
@login_required
def cart_remove():
    get_db().execute("DELETE FROM cart_items WHERE user_id=? AND product_id=?",
                     (g.user["id"], parse_int(request.form.get("product_id"), 1, 10**9)))
    return redirect(url_for("shop.cart"))

@bp.post("/cart/coupon")
@login_required
@limited("coupon", 10, 300)
def coupon_apply():
    code = clean(request.form.get("code"), 40)
    c, err = check_coupon(get_db(), code, g.user)
    if err:
        flash(err, "error")
    else:
        session["coupon"] = c["code"]   # a single slot: applying a new code replaces the old one (no stacking)
        flash(f"Coupon applied: {c['percent']}% off.", "ok")
    return redirect(url_for("shop.cart"))

@bp.post("/newsletter")
@limited("newsletter", 5, 3600)
def newsletter():
    email = clean(request.form.get("email"), 320).lower()
    if not EMAIL_RE.match(email):
        flash("Enter a valid email address.", "error")
        return redirect(request.referrer and url_for("shop.index") or url_for("shop.index"))
    db = get_db()
    try:
        db.execute("INSERT INTO subscribers VALUES(?,?)", (email, int(time.time())))
        code = "SS-" + secrets.token_hex(4).upper()
        db.execute("INSERT INTO coupons(code,percent,max_uses,expires_at,bound_email) VALUES(?,10,1,?,?)",
                   (code, int(time.time()) + 30 * 86400, email))
        flash(f"Thanks for subscribing! Your 10% coupon: {code} (single use, valid 30 days, tied to {email}).", "ok")
    except sqlite3.IntegrityError:
        flash("This address is already subscribed.", "ok")
    return redirect(url_for("shop.index"))

# ---------- checkout ----------
@bp.post("/checkout")
@login_required
def checkout():
    db, uid = get_db(), g.user["id"]
    try:
        with tx(db):  # one write transaction: everything below commits or nothing does
            items = db.execute("""SELECT c.product_id, c.qty, p.name, p.price_cents, p.active FROM cart_items c
                JOIN products p ON p.id=c.product_id WHERE c.user_id=?""", (uid,)).fetchall()
            if not items:
                raise ValueError("Your cart is empty.")
            subtotal = 0
            for i in items:
                if not i["active"] or i["qty"] < 1:
                    raise ValueError(f"{i['name']} is no longer available.")
                ok = db.execute("UPDATE products SET stock=stock-? WHERE id=? AND stock>=?",
                                (i["qty"], i["product_id"], i["qty"])).rowcount
                if ok != 1:                      # atomic guard: cannot oversell under concurrency
                    raise ValueError(f"Not enough stock for {i['name']}.")
                subtotal += i["qty"] * i["price_cents"]
            user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            coupon, discount = None, 0
            if session.get("coupon"):
                coupon, err = check_coupon(db, session["coupon"], user)
                if err:
                    raise ValueError(err)
                discount = subtotal * coupon["percent"] // 100
                if db.execute("UPDATE coupons SET used_count=used_count+1 WHERE id=? AND used_count<max_uses",
                              (coupon["id"],)).rowcount != 1:
                    raise ValueError(COUPON_ERR)
                db.execute("INSERT INTO coupon_redemptions VALUES(?,?)", (coupon["id"], uid))  # PK blocks reuse
            total = subtotal - discount
            if db.execute("UPDATE users SET credit_cents=credit_cents-? WHERE id=? AND credit_cents>=?",
                          (total, uid, total)).rowcount != 1:
                raise ValueError("Insufficient store credit for this order.")
            oid = db.execute("INSERT INTO orders(user_id,subtotal_cents,discount_cents,total_cents,coupon_code,created_at)"
                             " VALUES(?,?,?,?,?,?)", (uid, subtotal, discount, total,
                             coupon["code"] if coupon else None, int(time.time()))).lastrowid
            db.executemany("INSERT INTO order_items(order_id,product_id,name,unit_price_cents,qty) VALUES(?,?,?,?,?)",
                           [(oid, i["product_id"], i["name"], i["price_cents"], i["qty"]) for i in items])
            db.execute("DELETE FROM cart_items WHERE user_id=?", (uid,))
    except (ValueError, sqlite3.IntegrityError) as e:
        flash(str(e) if isinstance(e, ValueError) else "Checkout failed. Please review your cart.", "error")
        return redirect(url_for("shop.cart"))
    session.pop("coupon", None)
    return redirect(url_for("shop.order", oid=oid))

@bp.get("/orders/<int:oid>")
@login_required
def order(oid):
    db = get_db()
    o = db.execute("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, g.user["id"])).fetchone()  # ownership check
    if not o:
        abort(404)  # 404 rather than 403: don't confirm that other users' order ids exist
    items = db.execute("SELECT * FROM order_items WHERE order_id=?", (oid,)).fetchall()
    return render_template("order.html", o=o, items=items)
