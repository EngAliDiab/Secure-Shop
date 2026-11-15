import sqlite3
from contextlib import contextmanager
from flask import g, current_app

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
  credit_cents INTEGER NOT NULL DEFAULT 0 CHECK(credit_cents >= 0),
  verified INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  session_ver INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS email_tokens(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL,
  price_cents INTEGER NOT NULL CHECK(price_cents > 0),
  stock INTEGER NOT NULL CHECK(stock >= 0),
  active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS cart_items(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  qty INTEGER NOT NULL CHECK(qty BETWEEN 1 AND 10),
  PRIMARY KEY(user_id, product_id));
CREATE TABLE IF NOT EXISTS coupons(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE COLLATE NOCASE,
  percent INTEGER NOT NULL CHECK(percent BETWEEN 1 AND 90),
  max_uses INTEGER NOT NULL CHECK(max_uses >= 1),
  used_count INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  bound_email TEXT COLLATE NOCASE,
  CHECK(used_count <= max_uses));
CREATE TABLE IF NOT EXISTS coupon_redemptions(
  coupon_id INTEGER NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY(coupon_id, user_id));
CREATE TABLE IF NOT EXISTS subscribers(
  email TEXT PRIMARY KEY COLLATE NOCASE, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  subtotal_cents INTEGER NOT NULL, discount_cents INTEGER NOT NULL,
  total_cents INTEGER NOT NULL CHECK(total_cents >= 0),
  coupon_code TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS order_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  unit_price_cents INTEGER NOT NULL CHECK(unit_price_cents > 0),
  qty INTEGER NOT NULL CHECK(qty > 0));
"""

def connect(path):
    # isolation_level=None -> autocommit; transactions are explicit via tx().
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db

def init_db(path):
    db = connect(path)
    db.executescript(SCHEMA)
    db.close()

def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db

def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

@contextmanager
def tx(db):
    """BEGIN IMMEDIATE takes the write lock up front, serialising concurrent checkouts."""
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
