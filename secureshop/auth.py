import hashlib, secrets, sqlite3, time
from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for
from .db import get_db
from .security import (DUMMY_HASH, EMAIL_RE, check_pw, clean, hash_pw, limited, login_required)

bp = Blueprint("auth", __name__)
GENERIC_LOGIN_ERR = "Invalid email or password."

def _issue_token(db, uid):
    raw = secrets.token_urlsafe(32)
    db.execute("INSERT INTO email_tokens VALUES(?,?,?)",
               (hashlib.sha256(raw.encode()).hexdigest(), uid, int(time.time()) + 86400))
    link = url_for("auth.verify", token=raw, _external=True)
    # No SMTP in this project: the "email" is written to the server console. Swap for smtplib in production.
    current_app.logger.warning("EMAIL VERIFICATION LINK: %s", link)

@bp.route("/register", methods=["GET", "POST"])
@limited("register", 5, 3600)
def register():
    if request.method == "POST":
        name = clean(request.form.get("name"), 60)
        email = clean(request.form.get("email"), 320).lower()
        pw = request.form.get("password", "")
        if not name or not EMAIL_RE.match(email) or not (10 <= len(pw) <= 128):
            flash("Enter your name, a valid email and a password of 10-128 characters.", "error")
            return render_template("register.html"), 400
        db = get_db()
        try:
            cur = db.execute("INSERT INTO users(email,name,password_hash,created_at) VALUES(?,?,?,?)",
                             (email, name, hash_pw(pw), int(time.time())))
            _issue_token(db, cur.lastrowid)
        except sqlite3.IntegrityError:
            pass  # same response either way: no account enumeration
        flash("Check your email for a verification link, then sign in.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("register.html")

@bp.get("/verify/<token>")
def verify(token):
    db = get_db()
    h = hashlib.sha256(token.encode()).hexdigest()
    row = db.execute("SELECT * FROM email_tokens WHERE token_hash=? AND expires_at>?", (h, int(time.time()))).fetchone()
    if not row:
        flash("That verification link is invalid or has expired.", "error")
        return redirect(url_for("auth.login"))
    db.execute("UPDATE users SET verified=1 WHERE id=?", (row["user_id"],))
    db.execute("DELETE FROM email_tokens WHERE user_id=?", (row["user_id"],))  # single use
    flash("Email verified. You can sign in now.", "ok")
    return redirect(url_for("auth.login"))

@bp.route("/login", methods=["GET", "POST"])
@limited("login", 10, 300)
def login():
    if request.method == "POST":
        db = get_db()
        email = clean(request.form.get("email"), 320).lower()
        pw = request.form.get("password", "")[:128]
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        now = int(time.time())
        ok = check_pw(u["password_hash"] if u else DUMMY_HASH, pw)  # always hash: constant-ish timing
        if u and ok and u["active"] and u["locked_until"] <= now:
            if not u["verified"]:
                flash("Please verify your email before signing in.", "error")
                return render_template("login.html"), 403
            db.execute("UPDATE users SET failed_logins=0 WHERE id=?", (u["id"],))
            session.clear()                       # new session identity on login (fixation defence)
            session["uid"], session["sv"] = u["id"], u["session_ver"]
            session.permanent = True
            return redirect(url_for("shop.index"))
        if u:
            fails = u["failed_logins"] + 1
            lock = now + 900 if fails >= 5 else 0   # 15 min lockout after 5 failures
            db.execute("UPDATE users SET failed_logins=?, locked_until=MAX(locked_until,?) WHERE id=?",
                       (0 if lock else fails, lock, u["id"]))
        flash(GENERIC_LOGIN_ERR, "error")
        return render_template("login.html"), 401
    return render_template("login.html")

@bp.post("/logout")
def logout():
    if g.user:  # bumping session_ver invalidates any copy of the old cookie
        get_db().execute("UPDATE users SET session_ver=session_ver+1 WHERE id=?", (g.user["id"],))
    session.clear()
    return redirect(url_for("shop.index"))

@bp.get("/account")
@login_required
def account():
    orders = get_db().execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (g.user["id"],)).fetchall()
    return render_template("account.html", orders=orders)

@bp.post("/account/profile")
@login_required
def update_profile():
    name = clean(request.form.get("name"), 60)
    email = clean(request.form.get("email"), 320).lower()
    if not name or not EMAIL_RE.match(email):
        flash("Enter a name and a valid email.", "error")
        return redirect(url_for("auth.account"))
    if email != g.user["email"].lower() and not check_pw(g.user["password_hash"], request.form.get("current_password", "")):
        flash("Enter your current password to change your email.", "error")
        return redirect(url_for("auth.account"))
    try:  # whitelist: only name and email are writable here (no mass assignment of role/credit)
        get_db().execute("UPDATE users SET name=?, email=? WHERE id=?", (name, email, g.user["id"]))
        flash("Profile updated.", "ok")
    except sqlite3.IntegrityError:
        flash("That email can't be used.", "error")
    return redirect(url_for("auth.account"))

@bp.post("/account/password")
@login_required
def change_password():
    new = request.form.get("new_password", "")
    if not check_pw(g.user["password_hash"], request.form.get("current_password", "")):
        flash("Current password is incorrect.", "error")
    elif not (10 <= len(new) <= 128) or new != request.form.get("confirm_password"):
        flash("New passwords must match and be 10-128 characters.", "error")
    else:
        get_db().execute("UPDATE users SET password_hash=?, session_ver=session_ver+1 WHERE id=?",
                         (hash_pw(new), g.user["id"]))
        session.clear()  # all existing sessions die
        flash("Password changed. Please sign in again.", "ok")
        return redirect(url_for("auth.login"))
    return redirect(url_for("auth.account"))
