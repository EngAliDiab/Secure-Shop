import os, secrets, time
from datetime import timedelta
from flask import Flask, g, render_template, session
from markupsafe import Markup
from . import db as database
from . import security

def _secret_key(instance_path):
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(instance_path, "secret.key")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)
    dev = os.environ.get("SECURESHOP_DEV") == "1"   # plain-HTTP localhost only
    app.config.update(
        DATABASE=os.path.join(app.instance_path, "secureshop.db"),
        SECRET_KEY=_secret_key(app.instance_path),
        SESSION_COOKIE_NAME="ss" if dev else "__Host-ss",
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=not dev,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=32 * 1024, DEV=dev, DEBUG=False,
    )
    if test_config:
        app.config.update(test_config)
    app.teardown_appcontext(database.close_db)

    @app.before_request
    def guard():
        security.csrf_protect()
        g.user = None
        uid = session.get("uid")
        if uid:
            u = database.get_db().execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
            if u and u["session_ver"] == session.get("sv"):
                g.user = u
            else:
                session.clear()

    @app.after_request
    def add_headers(r):
        r.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        r.headers["X-Frame-Options"] = "DENY"
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["Referrer-Policy"] = "no-referrer"
        r.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not app.config["DEV"]:
            r.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if g.get("user") is not None:
            r.headers["Cache-Control"] = "no-store"
        return r

    @app.context_processor
    def ctx():
        n = 0
        if g.get("user") is not None:
            n = database.get_db().execute(
                "SELECT COALESCE(SUM(qty),0) FROM cart_items WHERE user_id=?", (g.user["id"],)).fetchone()[0]
        return dict(csrf_field=lambda: Markup(
            f'<input type="hidden" name="csrf_token" value="{security.csrf_token()}">'), cart_count=n)

    @app.template_filter("money")
    def money(c): return f"${c / 100:,.2f}"

    @app.template_filter("date")
    def date(ts): return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts))

    msgs = {400: ("Bad request", "The request could not be processed. Go back and try again."),
            403: ("Access denied", "You don't have permission to view this page."),
            404: ("Page not found", "We couldn't find what you were looking for."),
            405: ("Not allowed", "That action isn't supported here."),
            413: ("Request too large", "The data you sent was too large."),
            429: ("Slow down", "Too many attempts. Please wait a few minutes and try again."),
            500: ("Something went wrong", "An unexpected error occurred. We've logged it.")}

    def handler(e):
        code = getattr(e, "code", 500) or 500
        if code not in msgs:
            code = 500
        if code == 500:
            app.logger.exception("Unhandled error")  # details go to the log, never the response
        t, m = msgs[code]
        return render_template("error.html", code=code, title=t, message=m), code
    for c in msgs:
        app.register_error_handler(c, handler)
    app.register_error_handler(Exception, handler)

    from . import auth, shop, admin
    for m in (auth, shop, admin):
        app.register_blueprint(m.bp)
    return app
