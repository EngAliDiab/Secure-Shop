import os, re, tempfile, unittest
os.environ["SECURESHOP_DEV"] = "1"
from secureshop import create_app, security
from secureshop.db import init_db, connect
import seed

class Base(unittest.TestCase):
    def setUp(self):
        security._hits.clear()
        self.dir = tempfile.mkdtemp()
        self.app = create_app({"DATABASE": os.path.join(self.dir, "t.db"), "TESTING": False})
        seed_app = self.app
        init_db(self.app.config["DATABASE"])
        seed.create_app = lambda: seed_app
        seed.main()
        self.c = self.app.test_client()

    def token(self, c=None, path="/login"):
        r = (c or self.c).get(path)
        return re.search(r'name="csrf_token" value="([^"]+)"', r.get_data(as_text=True)).group(1)

    def login(self, email="alice@secureshop.test", pw="User#Pass2026!", c=None):
        c = c or self.c
        return c.post("/login", data={"email": email, "password": pw, "csrf_token": self.token(c)})

    def post(self, path, c=None, **data):
        c = c or self.c
        data["csrf_token"] = self.token(c, "/cart")
        return c.post(path, data=data)

class Tests(Base):
    def test_headers(self):
        h = self.c.get("/").headers
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY"); self.assertEqual(h["X-Content-Type-Options"], "nosniff")

    def test_csrf_required(self):
        self.login()
        self.assertEqual(self.c.post("/cart/add", data={"product_id": 1, "qty": 1}).status_code, 400)

    def test_sqli_search(self):
        r = self.c.get("/?q=' OR 1=1 --")
        self.assertEqual(r.status_code, 200); self.assertNotIn("Trail Backpack", r.get_data(as_text=True))

    def test_xss_reflection_escaped(self):
        self.assertNotIn("<script>alert(1)</script>", self.c.get("/?q=<script>alert(1)</script>").get_data(as_text=True))

    def test_admin_forbidden_for_user(self):
        self.login(); self.assertEqual(self.c.get("/admin/").status_code, 403)
        self.assertEqual(self.c.get("/admin/users").status_code, 403)

    def test_anonymous_redirected(self):
        self.assertEqual(self.c.get("/admin/").status_code, 302); self.assertEqual(self.c.get("/cart").status_code, 302)

    def test_negative_and_huge_qty_rejected(self):
        self.login()
        for q in ("-5", "0", "999", "abc"):
            self.post("/cart/add", product_id=1, qty=q)
        self.assertEqual(connect(self.app.config["DATABASE"]).execute("SELECT COUNT(*) FROM cart_items").fetchone()[0], 0)

    def test_checkout_and_idor(self):
        self.login(); self.post("/cart/add", product_id=3, qty=2)
        r = self.post("/checkout"); self.assertEqual(r.status_code, 302); self.assertIn("/orders/1", r.location)
        db = connect(self.app.config["DATABASE"])
        self.assertEqual(db.execute("SELECT credit_cents FROM users WHERE id=1").fetchone()[0], 15000 - 4400)
        other = self.app.test_client()   # a second user must get 404 for Alice's order
        db.execute("INSERT INTO users(email,name,password_hash,verified,created_at) VALUES('bob@x.io','Bob',?,1,0)", (security.hash_pw("Bobpassword123"),))
        self.login("bob@x.io", "Bobpassword123", other)
        self.assertEqual(other.get("/orders/1").status_code, 404)

    def test_insufficient_credit_and_stock_unchanged(self):
        self.login()
        for _ in range(2): self.post("/cart/add", product_id=7, qty=10)  # 10 x $129 > $150
        self.post("/checkout")
        db = connect(self.app.config["DATABASE"])
        self.assertEqual(db.execute("SELECT stock FROM products WHERE id=7").fetchone()[0], 10)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM orders").fetchone()[0], 0)

    def test_coupon_single_use_per_user(self):
        self.login()
        for _ in range(2):
            self.post("/cart/add", product_id=3, qty=1); self.post("/cart/coupon", code="WELCOME10"); self.post("/checkout")
        db = connect(self.app.config["DATABASE"])
        self.assertEqual(db.execute("SELECT COUNT(*) FROM coupon_redemptions").fetchone()[0], 1)
        self.assertEqual(db.execute("SELECT discount_cents FROM orders ORDER BY id").fetchall()[1][0], 0)

    def test_login_lockout_and_generic_error(self):
        for _ in range(5): self.login(pw="wrong-password")
        self.assertEqual(self.login().status_code, 401)  # locked even with the right password

    def test_unverified_cannot_login(self):
        self.c.post("/register", data={"name": "N", "email": "n@x.io", "password": "LongPassword123", "csrf_token": self.token(path="/register")})
        self.assertEqual(self.login("n@x.io", "LongPassword123").status_code, 403)

    def test_logout_invalidates_old_cookie(self):
        self.login(); old = self.c.get_cookie("ss").value
        self.post("/logout")
        self.c.set_cookie("ss", old)
        self.assertEqual(self.c.get("/cart").status_code, 302)

    def test_404_hides_internals(self):
        r = self.c.get("/nope"); self.assertEqual(r.status_code, 404); self.assertNotIn("Traceback", r.get_data(as_text=True))

if __name__ == "__main__":
    unittest.main()
