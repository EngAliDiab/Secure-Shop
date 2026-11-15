"""Create the schema and seed sample data. Usage: python seed.py"""
import os, time
from secureshop import create_app
from secureshop.db import init_db, connect
from secureshop.security import hash_pw

PRODUCTS = [
    ("Trail Backpack 30L", "Water-resistant daypack with laptop sleeve.", "Bags", 5900, 25),
    ("City Commuter Bag", "Slim messenger bag for daily carry.", "Bags", 4500, 40),
    ("Insulated Bottle 750ml", "Keeps drinks cold for 24 hours.", "Outdoors", 2200, 100),
    ("Headlamp 400lm", "Rechargeable, three brightness modes.", "Outdoors", 2900, 60),
    ("Mechanical Keyboard", "Tenkeyless, hot-swappable switches.", "Tech", 8900, 15),
    ("USB-C Hub 7-in-1", "HDMI, SD, Ethernet and 3 USB ports.", "Tech", 3400, 50),
    ("Noise-Cancelling Headphones", "30h battery, Bluetooth 5.3.", "Tech", 12900, 10),
    ("Wool Beanie", "Merino blend, one size.", "Apparel", 1800, 80),
]

def main():
    app = create_app()
    path = app.config["DATABASE"]
    init_db(path)
    db = connect(path)
    now = int(time.time())
    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        user_pw = os.environ.get("SEED_USER_PASSWORD", "User#Pass2026!")
        admin_pw = os.environ.get("SEED_ADMIN_PASSWORD", "Admin#Pass2026!")
        db.execute("INSERT INTO users(email,name,password_hash,role,credit_cents,verified,created_at) VALUES(?,?,?,?,?,1,?)",
                   ("alice@secureshop.test", "Alice Customer", hash_pw(user_pw), "user", 15000, now))
        db.execute("INSERT INTO users(email,name,password_hash,role,credit_cents,verified,created_at) VALUES(?,?,?,?,?,1,?)",
                   ("admin@secureshop.test", "Site Admin", hash_pw(admin_pw), "admin", 0, now))
        db.executemany("INSERT INTO products(name,description,category,price_cents,stock) VALUES(?,?,?,?,?)", PRODUCTS)
        db.execute("INSERT INTO coupons(code,percent,max_uses,expires_at) VALUES('WELCOME10',10,1000,?)", (now + 365 * 86400,))
        print("Seeded users, products and coupon WELCOME10.")
    else:
        print("Database already seeded; nothing to do.")

if __name__ == "__main__":
    main()
