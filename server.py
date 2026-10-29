#!/usr/bin/env python3
"""Loopback-only Fresh Vegbox shop, API, and admin server."""

from __future__ import annotations

import base64
import binascii
import argparse
from contextlib import contextmanager
from email.message import EmailMessage
import hashlib
import hmac
import http.cookies
import json
import mimetypes
import os
import re
import secrets
import smtplib
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from datetime import datetime, timezone
from getpass import getpass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("FRESH_VEGBOX_DATABASE", ROOT / "data" / "fresh-vegbox.sqlite3"))
UPLOADS_DIR = ROOT / "assets" / "uploads"
HOST = "127.0.0.1"
PORT = int(os.environ.get("FRESH_VEGBOX_PORT", "8000"))
SESSION_TTL = 60 * 60 * 12
PASSWORD_ITERATIONS = 310_000
MAX_REQUEST_BYTES = 64 * 1024
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGE_REQUEST_BYTES = 7 * 1024 * 1024
PASSWORD_RESET_TTL = 3 * 60
PASSWORD_RESET_MAX_ATTEMPTS = 5
ALLOWED_ORDER_STATUSES = {"pending", "confirmed", "packed", "delivered", "cancelled"}
ALLOWED_SUBSCRIPTION_STATUSES = {"pending", "active", "paused", "cancelled"}
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,190}\.[^@\s]{2,63}$")
_server: ThreadingHTTPServer | None = None


class APIError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def read_password(prompt: str, *, read_character: Callable[[], str] | None = None) -> str:
    if os.name != "nt":
        return getpass(prompt)

    if read_character is None:
        import msvcrt

        read_character = msvcrt.getwch

    sys.stdout.write(prompt)
    sys.stdout.flush()
    characters: list[str] = []
    while True:
        character = read_character()
        if character in {"\r", "\n"}:
            sys.stdout.write(os.linesep)
            sys.stdout.flush()
            return "".join(characters)
        if character == "\x03":
            raise KeyboardInterrupt
        if character == "\b":
            if characters:
                characters.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
            continue
        if character in {"\x00", "\xe0"}:
            read_character()
            continue
        if character and ord(character) >= 32:
            characters.append(character)
            sys.stdout.write("*")
            sys.stdout.flush()


@contextmanager
def connect_database() -> Iterator[sqlite3.Connection]:
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, saved_hash: str | None) -> bool:
    if not saved_hash:
        return False
    try:
        algorithm, iterations, salt_hex, digest_hex = saved_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        calculated = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(calculated.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def init_database() -> None:
    with connect_database() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                phone TEXT NOT NULL DEFAULT '',
                address TEXT NOT NULL DEFAULT '',
                password_hash TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS products (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                price INTEGER NOT NULL CHECK (price >= 0),
                old_price INTEGER,
                unit TEXT NOT NULL DEFAULT '',
                discount TEXT NOT NULL DEFAULT '',
                image_url TEXT NOT NULL DEFAULT '',
                stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                sort_order INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS subscriptions (
                id TEXT PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id),
                frequency TEXT NOT NULL,
                box_size TEXT NOT NULL,
                address TEXT NOT NULL,
                plan_id TEXT,
                plan_name TEXT,
                plan_price INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscription_plans (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                price INTEGER NOT NULL CHECK (price >= 0),
                frequency TEXT NOT NULL,
                delivery_note TEXT NOT NULL DEFAULT 'Free delivery up to 3 km',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id),
                phone TEXT NOT NULL,
                address TEXT NOT NULL,
                total INTEGER NOT NULL CHECK (total >= 0),
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS order_items (
                id INTEGER PRIMARY KEY,
                order_id TEXT NOT NULL REFERENCES orders(id),
                product_id TEXT NOT NULL REFERENCES products(id),
                product_name TEXT NOT NULL,
                quantity INTEGER NOT NULL CHECK (quantity > 0),
                unit_price INTEGER NOT NULL CHECK (unit_price >= 0)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS customer_password_resets (
                token_hash TEXT PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                used_at INTEGER,
                otp_salt TEXT,
                attempts INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_subscriptions_created ON subscriptions(created_at DESC);
            """
        )
        subscription_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(subscriptions)")
        }
        for column, definition in (
            ("plan_id", "TEXT"),
            ("plan_name", "TEXT"),
            ("plan_price", "INTEGER"),
        ):
            if column not in subscription_columns:
                db.execute(f"ALTER TABLE subscriptions ADD COLUMN {column} {definition}")
        reset_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(customer_password_resets)")
        }
        for column, definition in (
            ("otp_salt", "TEXT"),
            ("attempts", "INTEGER NOT NULL DEFAULT 0"),
        ):
            if column not in reset_columns:
                db.execute(f"ALTER TABLE customer_password_resets ADD COLUMN {column} {definition}")
        if db.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
            seed_file = ROOT / "products.json"
            if not seed_file.is_file():
                raise RuntimeError(f"Product seed file is missing: {seed_file}")
            catalog = json.loads(seed_file.read_text(encoding="utf-8"))
            for position, product in enumerate(catalog, start=1):
                db.execute(
                    """INSERT INTO products
                       (id, name, category, price, old_price, unit, discount,
                        image_url, stock, active, sort_order)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        uuid.uuid4().hex,
                        product["name"],
                        product["category"],
                        product["price"],
                        product.get("old_price"),
                        product["unit"],
                        product.get("discount", ""),
                        product["image_url"],
                        int(product.get("stock", 20)),
                        1,
                        position,
                    ),
                )
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))


def setup_admin(username: str, password: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,80}", username):
        raise ValueError("Username must be 3–80 characters: letters, digits, dot, underscore, @, or hyphen.")
    if not 12 <= len(password) <= 256:
        raise ValueError("Admin password must contain between 12 and 256 characters.")
    with connect_database() as db:
        if db.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
            raise ValueError("An admin account already exists. Use --reset-admin-password to change its password.")
        db.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, hash_password(password), now_utc()),
        )


def reset_admin_password(username: str, password: str) -> None:
    if not 12 <= len(password) <= 256:
        raise ValueError("Admin password must contain between 12 and 256 characters.")
    with connect_database() as db:
        cursor = db.execute(
            "UPDATE admins SET password_hash = ? WHERE username = ?",
            (hash_password(password), username),
        )
        if cursor.rowcount == 0:
            raise ValueError("Admin username was not found.")


def clean_text(value: object, label: str, limit: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise APIError(400, f"{label} must be text.")
    result = value.strip()
    if required and not result:
        raise APIError(400, f"{label} is required.")
    if len(result) > limit:
        raise APIError(400, f"{label} must be {limit} characters or fewer.")
    return result


def validate_email(value: object) -> str:
    email = clean_text(value, "Email address", 254).lower()
    if not EMAIL_PATTERN.fullmatch(email):
        raise APIError(400, "Enter a valid email address.")
    return email


def validate_password(value: object) -> str:
    if not isinstance(value, str) or not 12 <= len(value) <= 256:
        raise APIError(400, "Password must contain between 12 and 256 characters.")
    return value


def product_from_row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "category": row["category"],
        "price": row["price"],
        "old_price": row["old_price"],
        "unit": row["unit"],
        "discount": row["discount"],
        "image_url": row["image_url"],
        "stock": row["stock"],
        "active": bool(row["active"]),
        "sort_order": row["sort_order"],
    }


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "FreshVegbox/1.0"
    sys_version = ""

    def log_message(self, format_string: str, *args: object) -> None:
        print(f"{self.log_date_time_string()} {self.address_string()} {format_string % args}")

    def send_json(self, status: int, payload: object, *, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if headers:
            for name, value in headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, *, max_bytes: int = MAX_REQUEST_BYTES) -> dict:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise APIError(415, "Content-Type must be application/json.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise APIError(400, "Invalid Content-Length.") from exc
        if length <= 0 or length > max_bytes:
            size_limit = "64 KB" if max_bytes == MAX_REQUEST_BYTES else f"{max_bytes // (1024 * 1024)} MB"
            raise APIError(413, f"Request must contain JSON and be no larger than {size_limit}.")
        try:
            value = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise APIError(400, "Request body must be valid JSON.") from exc
        if not isinstance(value, dict):
            raise APIError(400, "JSON request body must be an object.")
        return value

    def enforce_same_origin(self) -> None:
        origin = self.headers.get("Origin")
        if not origin:
            return
        parsed = urlsplit(origin)
        request_host = self.headers.get("Host", "").split(":", 1)[0].lower()
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.hostname != request_host
        ):
            raise APIError(403, "Cross-origin requests are not allowed.")

    def cookie_token(self) -> str | None:
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookies = http.cookies.SimpleCookie()
        try:
            cookies.load(cookie_header)
        except http.cookies.CookieError:
            return None
        morsel = cookies.get("fvb_session")
        return morsel.value if morsel else None

    def session(self) -> sqlite3.Row | None:
        token = self.cookie_token()
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()
        with connect_database() as db:
            return db.execute(
                """SELECT s.*, a.username AS admin_username, c.name AS customer_name,
                          c.email AS customer_email, c.phone AS customer_phone,
                          c.address AS customer_address
                   FROM sessions s
                   LEFT JOIN admins a ON s.role = 'admin' AND a.id = s.user_id
                   LEFT JOIN customers c ON s.role = 'customer' AND c.id = s.user_id
                   WHERE s.token_hash = ? AND s.expires_at > ?""",
                (token_hash, int(time.time())),
            ).fetchone()

    def require_role(self, role: str, *, mutate: bool = False) -> sqlite3.Row:
        session = self.session()
        if not session or session["role"] != role:
            raise APIError(401, "Please sign in to continue.")
        if mutate:
            self.enforce_same_origin()
            csrf = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf, session["csrf_token"]):
                raise APIError(403, "Your session token expired. Sign in again.")
        return session

    def create_session(self, user_id: int, role: str) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        expires_at = int(time.time()) + SESSION_TTL
        with connect_database() as db:
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
            db.execute(
                "INSERT INTO sessions (token_hash, csrf_token, user_id, role, expires_at) VALUES (?, ?, ?, ?, ?)",
                (token_hash, csrf, user_id, role, expires_at),
            )
        return token, csrf

    def set_session_cookie(self, token: str) -> str:
        cookie = http.cookies.SimpleCookie()
        cookie["fvb_session"] = token
        cookie["fvb_session"]["path"] = "/"
        cookie["fvb_session"]["httponly"] = True
        cookie["fvb_session"]["samesite"] = "Strict"
        cookie["fvb_session"]["max-age"] = str(SESSION_TTL)
        return cookie.output(header="").strip()

    def clear_session(self) -> None:
        token = self.cookie_token()
        if token:
            token_hash = hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()
            with connect_database() as db:
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def do_GET(self) -> None:
        try:
            parsed = urlsplit(self.path)
            if parsed.path.startswith("/api/"):
                self.api_get(parsed.path)
            else:
                self.serve_static(parsed.path)
        except APIError as exc:
            self.send_json(exc.status, {"error": str(exc)})
        except (sqlite3.Error, OSError) as exc:
            print(f"GET {self.path} failed: {exc}", file=sys.stderr)
            self.send_json(500, {"error": "The local server could not complete this request."})

    def do_POST(self) -> None:
        try:
            self.enforce_same_origin()
            path = urlsplit(self.path).path
            if path == "/api/admin/images":
                self.require_role("admin", mutate=True)
            body_limit = MAX_IMAGE_REQUEST_BYTES if path == "/api/admin/images" else MAX_REQUEST_BYTES
            body = self.read_json(max_bytes=body_limit)
            self.api_post(path, body)
        except APIError as exc:
            self.send_json(exc.status, {"error": str(exc)})
        except sqlite3.IntegrityError as exc:
            self.send_json(409, {"error": f"This change conflicts with existing data: {exc}"})
        except sqlite3.Error as exc:
            print(f"POST {self.path} failed: {exc}", file=sys.stderr)
            self.send_json(500, {"error": "The local database could not complete this request."})
        except OSError as exc:
            print(f"POST {self.path} failed: {exc}", file=sys.stderr)
            self.send_json(500, {"error": "The local server could not save this image."})

    def do_PUT(self) -> None:
        try:
            self.enforce_same_origin()
            body = self.read_json()
            self.api_put(urlsplit(self.path).path, body)
        except APIError as exc:
            self.send_json(exc.status, {"error": str(exc)})
        except sqlite3.IntegrityError as exc:
            self.send_json(409, {"error": f"This change conflicts with existing data: {exc}"})
        except sqlite3.Error as exc:
            print(f"PUT {self.path} failed: {exc}", file=sys.stderr)
            self.send_json(500, {"error": "The local database could not complete this request."})

    def do_DELETE(self) -> None:
        try:
            self.enforce_same_origin()
            self.api_delete(urlsplit(self.path).path)
        except APIError as exc:
            self.send_json(exc.status, {"error": str(exc)})
        except sqlite3.Error as exc:
            print(f"DELETE {self.path} failed: {exc}", file=sys.stderr)
            self.send_json(500, {"error": "The local database could not complete this request."})

    def serve_static(self, path: str) -> None:
        routes = {
            "/": ROOT / "index.html",
            "/index.html": ROOT / "index.html",
            "/home": ROOT / "index.html",
            "/about": ROOT / "index.html",
            "/products": ROOT / "index.html",
            "/blog": ROOT / "index.html",
            "/contact": ROOT / "index.html",
            "/signin": ROOT / "index.html",
            "/signup": ROOT / "index.html",
            "/admin": ROOT / "admin.html",
            "/admin/": ROOT / "admin.html",
            "/admin.html": ROOT / "admin.html",
        }
        asset_prefix = "/assets/"
        if path in routes:
            file_path = routes[path]
        elif path.startswith(asset_prefix):
            relative = Path(unquote(path[len(asset_prefix):]))
            assets_root = ROOT.joinpath("assets").resolve()
            if relative.parts[:1] == ("uploads",):
                upload_root = UPLOADS_DIR.resolve()
                file_path = (upload_root / Path(*relative.parts[1:])).resolve()
                allowed_root = upload_root
            else:
                file_path = (assets_root / relative).resolve()
                allowed_root = assets_root
            if not relative.parts or relative.parts[0] in {".", ".."} or allowed_root not in file_path.parents:
                raise APIError(404, "File not found.")
        else:
            raise APIError(404, "Page not found.")
        if not file_path.is_file():
            raise APIError(404, "File not found.")
        content = file_path.read_bytes()
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        if file_path.suffix in {".html", ".json"}:
            content_type += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'self'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
        if file_path.name == "index.html":
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def api_get(self, path: str) -> None:
        if path == "/api/products":
            with connect_database() as db:
                rows = db.execute(
                    "SELECT * FROM products WHERE active = 1 ORDER BY sort_order, name"
                ).fetchall()
            return self.send_json(200, {"products": [product_from_row(row) for row in rows]})
        if path == "/api/subscription-plans":
            with connect_database() as db:
                rows = db.execute(
                    "SELECT id, name, price, frequency, delivery_note FROM subscription_plans ORDER BY created_at, name"
                ).fetchall()
            return self.send_json(200, {"plans": [dict(row) for row in rows]})
        if path == "/api/me":
            session = self.session()
            if not session:
                return self.send_json(200, {"authenticated": False})
            if session["role"] == "admin":
                user = {"username": session["admin_username"]}
            else:
                user = {
                    "name": session["customer_name"],
                    "email": session["customer_email"],
                    "phone": session["customer_phone"],
                    "address": session["customer_address"],
                }
            return self.send_json(
                200, {"authenticated": True, "role": session["role"], "user": user, "csrf": session["csrf_token"]}
            )
        if path == "/api/admin/summary":
            self.require_role("admin")
            with connect_database() as db:
                summary = {
                    "products": db.execute("SELECT COUNT(*) FROM products WHERE active = 1").fetchone()[0],
                    "low_stock": db.execute("SELECT COUNT(*) FROM products WHERE active = 1 AND stock <= 5").fetchone()[0],
                    "orders": db.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
                    "pending_orders": db.execute("SELECT COUNT(*) FROM orders WHERE status = 'pending'").fetchone()[0],
                    "subscriptions": db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0],
                    "customers": db.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
                }
            return self.send_json(200, summary)
        if path == "/api/admin/products":
            self.require_role("admin")
            with connect_database() as db:
                rows = db.execute("SELECT * FROM products ORDER BY sort_order, name").fetchall()
            return self.send_json(200, {"products": [product_from_row(row) for row in rows]})
        if path == "/api/admin/orders":
            self.require_role("admin")
            with connect_database() as db:
                orders = db.execute(
                    """SELECT o.*, c.name AS customer_name, c.email AS customer_email,
                              c.phone AS customer_phone
                       FROM orders o JOIN customers c ON c.id = o.customer_id
                       ORDER BY o.created_at DESC"""
                ).fetchall()
                output = []
                for order in orders:
                    items = db.execute(
                        "SELECT product_id, product_name, quantity, unit_price FROM order_items WHERE order_id = ?",
                        (order["id"],),
                    ).fetchall()
                    output.append({**dict(order), "items": [dict(item) for item in items]})
            return self.send_json(200, {"orders": output})
        if path == "/api/admin/subscriptions":
            self.require_role("admin")
            with connect_database() as db:
                rows = db.execute(
                    """SELECT s.*, c.name AS customer_name, c.email AS customer_email, c.phone AS customer_phone
                       FROM subscriptions s JOIN customers c ON c.id = s.customer_id
                       ORDER BY s.created_at DESC"""
                ).fetchall()
            return self.send_json(200, {"subscriptions": [dict(row) for row in rows]})
        if path == "/api/admin/subscription-plans":
            self.require_role("admin")
            with connect_database() as db:
                rows = db.execute(
                    "SELECT id, name, price, frequency, delivery_note, created_at FROM subscription_plans ORDER BY created_at, name"
                ).fetchall()
            return self.send_json(200, {"plans": [dict(row) for row in rows]})
        if path == "/api/admin/customers":
            self.require_role("admin")
            with connect_database() as db:
                rows = db.execute(
                    """SELECT c.id, c.name, c.email, c.phone, c.address, c.created_at,
                              COUNT(DISTINCT o.id) AS order_count,
                              COUNT(DISTINCT s.id) AS subscription_count
                       FROM customers c
                       LEFT JOIN orders o ON o.customer_id = c.id
                       LEFT JOIN subscriptions s ON s.customer_id = c.id
                       GROUP BY c.id ORDER BY c.created_at DESC"""
                ).fetchall()
            return self.send_json(200, {"customers": [dict(row) for row in rows]})
        raise APIError(404, "API route not found.")

    def api_post(self, path: str, body: dict) -> None:
        if path in {
            "/api/customer/signup", "/api/customer/login", "/api/admin/login",
            "/api/customer/password-reset-request", "/api/customer/password-reset",
        }:
            if path == "/api/customer/password-reset-request":
                self.request_customer_password_reset(body)
                return
            if path == "/api/customer/password-reset":
                self.reset_customer_password(body)
                return
            self.login(path, body)
        elif path in {"/api/customer/logout", "/api/admin/logout"}:
            role = "admin" if path == "/api/admin/logout" else "customer"
            self.require_role(role, mutate=True)
            self.clear_session()
            self.send_json(200, {"ok": True}, headers={"Set-Cookie": "fvb_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        elif path == "/api/subscriptions":
            self.create_subscription(body)
        elif path == "/api/orders":
            self.create_order(body)
        elif path == "/api/admin/products":
            self.require_role("admin", mutate=True)
            product = self.validate_product(body)
            product_id = uuid.uuid4().hex
            with connect_database() as db:
                next_order = db.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 FROM products").fetchone()[0]
                db.execute(
                    """INSERT INTO products
                       (id, name, category, price, old_price, unit, discount, image_url, stock, active, sort_order)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        product_id, product["name"], product["category"], product["price"],
                        product["old_price"], product["unit"], product["discount"],
                        product["image_url"], product["stock"], product["active"], next_order,
                    ),
                )
                row = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
            return self.send_json(201, {"product": product_from_row(row)})
        elif path == "/api/admin/subscription-plans":
            self.require_role("admin", mutate=True)
            plan = self.validate_subscription_plan(body)
            plan_id = uuid.uuid4().hex
            with connect_database() as db:
                db.execute(
                    """INSERT INTO subscription_plans
                       (id, name, price, frequency, delivery_note, created_at)
                       VALUES (?, ?, ?, ?, 'Free delivery up to 3 km', ?)""",
                    (plan_id, plan["name"], plan["price"], plan["frequency"], now_utc()),
                )
                row = db.execute(
                    "SELECT id, name, price, frequency, delivery_note, created_at FROM subscription_plans WHERE id = ?",
                    (plan_id,),
                ).fetchone()
            return self.send_json(201, {"plan": dict(row)})
        elif path == "/api/admin/images":
            self.require_role("admin", mutate=True)
            return self.upload_product_image(body)
        else:
            raise APIError(404, "API route not found.")

    def upload_product_image(self, body: dict) -> None:
        image_data = body.get("data_url")
        if not isinstance(image_data, str):
            raise APIError(400, "Choose an image file to upload.")
        match = re.fullmatch(
            r"data:(image/(?:png|jpeg|webp));base64,([A-Za-z0-9+/]+={0,2})",
            image_data,
        )
        if not match:
            raise APIError(400, "Use a PNG, JPEG, or WebP image.")
        mime_type, encoded = match.groups()
        max_encoded_length = ((MAX_IMAGE_BYTES + 2) // 3) * 4
        if len(encoded) > max_encoded_length:
            raise APIError(413, "Images must be 5 MB or smaller.")
        try:
            image_bytes = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise APIError(400, "The selected image could not be decoded.") from exc
        if not image_bytes or len(image_bytes) > MAX_IMAGE_BYTES:
            raise APIError(413, "Images must be 5 MB or smaller.")

        formats = {
            "image/png": (".png", lambda data: data.startswith(b"\x89PNG\r\n\x1a\n")),
            "image/jpeg": (".jpg", lambda data: data.startswith(b"\xff\xd8\xff")),
            "image/webp": (
                ".webp",
                lambda data: len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP",
            ),
        }
        extension, validate_signature = formats[mime_type]
        if not validate_signature(image_bytes):
            raise APIError(400, "The selected file does not match its image format.")

        UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
        filename = f"{uuid.uuid4().hex}{extension}"
        destination = UPLOADS_DIR / filename
        destination.write_bytes(image_bytes)
        self.send_json(201, {"image_url": f"/assets/uploads/{filename}"})

    def validate_subscription_plan(self, body: dict) -> dict:
        name = clean_text(body.get("name"), "Plan name", 100)
        frequency = clean_text(body.get("frequency"), "Delivery frequency", 20)
        if frequency not in {"weekly", "fortnightly", "monthly"}:
            raise APIError(400, "Select a valid delivery frequency.")
        price = body.get("price")
        if not isinstance(price, int) or isinstance(price, bool) or price < 0:
            raise APIError(400, "Plan price must be a non-negative whole number of rupees.")
        return {"name": name, "price": price, "frequency": frequency}

    def send_password_reset_otp_email(self, recipient: str, otp: str) -> None:
        host = os.environ.get("FRESH_VEGBOX_SMTP_HOST", "").strip()
        sender = os.environ.get("FRESH_VEGBOX_EMAIL_FROM", "").strip()
        if not host or not sender:
            raise APIError(503, "Email and WhatsApp OTP delivery are not configured on this shop.")
        try:
            port = int(os.environ.get("FRESH_VEGBOX_SMTP_PORT", "587"))
        except ValueError as exc:
            raise APIError(500, "The email server port configuration is invalid.") from exc
        username = os.environ.get("FRESH_VEGBOX_SMTP_USERNAME", "")
        password = os.environ.get("FRESH_VEGBOX_SMTP_PASSWORD", "")
        if bool(username) != bool(password):
            raise APIError(500, "Configure both SMTP username and password, or neither.")

        message = EmailMessage()
        message["Subject"] = "Your Fresh Vegbox verification code"
        message["From"] = sender
        message["To"] = recipient
        message.set_content(
            f"Your Fresh Vegbox password-reset OTP is {otp}.\n\n"
            "It expires in 3 minutes and can be used once. If you did not request this, ignore this email."
        )
        try:
            if port == 465:
                with smtplib.SMTP_SSL(host, port, timeout=10) as smtp:
                    if username:
                        smtp.login(username, password)
                    smtp.send_message(message)
            else:
                with smtplib.SMTP(host, port, timeout=10) as smtp:
                    smtp.ehlo()
                    smtp.starttls()
                    smtp.ehlo()
                    if username:
                        smtp.login(username, password)
                    smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            print(f"Password reset OTP email delivery failed: {exc}", file=sys.stderr)
            raise APIError(502, "The OTP could not be delivered to both email and WhatsApp.") from exc

    def send_password_reset_otp_whatsapp(self, recipient: str, otp: str) -> None:
        access_token = os.environ.get("FRESH_VEGBOX_WHATSAPP_TOKEN", "").strip()
        phone_number_id = os.environ.get("FRESH_VEGBOX_WHATSAPP_PHONE_NUMBER_ID", "").strip()
        template_name = os.environ.get("FRESH_VEGBOX_WHATSAPP_TEMPLATE_NAME", "").strip()
        api_version = os.environ.get("FRESH_VEGBOX_WHATSAPP_API_VERSION", "").strip()
        language = os.environ.get("FRESH_VEGBOX_WHATSAPP_TEMPLATE_LANGUAGE", "en").strip()
        if not all((access_token, phone_number_id, template_name, api_version)):
            raise APIError(503, "Email and WhatsApp OTP delivery are not configured on this shop.")
        if not re.fullmatch(r"v\d+\.\d+", api_version):
            raise APIError(500, "WhatsApp Cloud API version must have the form vNN.N.")
        phone = re.sub(r"\D", "", recipient)
        if not 8 <= len(phone) <= 15:
            raise APIError(400, "The account phone number cannot receive a WhatsApp OTP.")

        payload = {
            "messaging_product": "whatsapp",
            "to": phone,
            "type": "template",
            "template": {
                "name": template_name,
                "language": {"code": language},
                "components": [
                    {
                        "type": "body",
                        "parameters": [{"type": "text", "text": otp}],
                    }
                ],
            },
        }
        request = urllib.request.Request(
            f"https://graph.facebook.com/{api_version}/{phone_number_id}/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if not 200 <= response.status < 300:
                    raise APIError(502, "The OTP could not be delivered to both email and WhatsApp.")
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            print("Password reset OTP WhatsApp delivery failed.", file=sys.stderr)
            raise APIError(502, "The OTP could not be delivered to both email and WhatsApp.") from exc

    def request_customer_password_reset(self, body: dict) -> None:
        email = validate_email(body.get("email"))
        host = os.environ.get("FRESH_VEGBOX_SMTP_HOST", "").strip()
        sender = os.environ.get("FRESH_VEGBOX_EMAIL_FROM", "").strip()
        whatsapp_config = (
            os.environ.get("FRESH_VEGBOX_WHATSAPP_TOKEN", "").strip(),
            os.environ.get("FRESH_VEGBOX_WHATSAPP_PHONE_NUMBER_ID", "").strip(),
            os.environ.get("FRESH_VEGBOX_WHATSAPP_TEMPLATE_NAME", "").strip(),
            os.environ.get("FRESH_VEGBOX_WHATSAPP_API_VERSION", "").strip(),
        )
        if not host or not sender or not all(whatsapp_config):
            raise APIError(
                503,
                "Email and WhatsApp OTP delivery are not configured on this shop.",
            )

        with connect_database() as db:
            customer = db.execute(
                "SELECT id, phone FROM customers WHERE email = ? AND password_hash IS NOT NULL",
                (email,),
            ).fetchone()
            if not customer:
                return self.send_json(
                    200,
                    {
                        "ok": True,
                        "message": "If an account exists, an OTP was sent to its registered email and WhatsApp. It expires in 3 minutes.",
                    },
                )
            if not 8 <= len(re.sub(r"\D", "", customer["phone"])) <= 15:
                raise APIError(400, "The account has no valid phone number for WhatsApp OTP recovery.")
            if bool(os.environ.get("FRESH_VEGBOX_SMTP_USERNAME", "")) != bool(
                os.environ.get("FRESH_VEGBOX_SMTP_PASSWORD", "")
            ):
                raise APIError(500, "Configure both SMTP username and password, or neither.")
            try:
                smtp_port = int(os.environ.get("FRESH_VEGBOX_SMTP_PORT", "587"))
            except ValueError as exc:
                raise APIError(500, "The email server port configuration is invalid.") from exc
            if not 1 <= smtp_port <= 65535:
                raise APIError(500, "The email server port configuration is invalid.")
            api_version = os.environ["FRESH_VEGBOX_WHATSAPP_API_VERSION"].strip()
            if not re.fullmatch(r"v\d+\.\d+", api_version):
                raise APIError(500, "WhatsApp Cloud API version must have the form vNN.N.")

            otp = f"{secrets.randbelow(1_000_000):06d}"
            salt = secrets.token_bytes(16)
            code_hash = hashlib.pbkdf2_hmac(
                "sha256", otp.encode("ascii"), salt, PASSWORD_ITERATIONS
            ).hex()
            reset_id = uuid.uuid4().hex
            db.execute("DELETE FROM customer_password_resets WHERE customer_id = ?", (customer["id"],))
            db.execute(
                """INSERT INTO customer_password_resets
                   (token_hash, customer_id, expires_at, otp_salt, attempts)
                   VALUES (?, ?, ?, ?, 0)""",
                (
                    reset_id,
                    customer["id"],
                    int(time.time()) + PASSWORD_RESET_TTL,
                    salt.hex() + ":" + code_hash,
                ),
            )

        try:
            self.send_password_reset_otp_email(email, otp)
            self.send_password_reset_otp_whatsapp(customer["phone"], otp)
        except APIError:
            with connect_database() as db:
                db.execute("DELETE FROM customer_password_resets WHERE token_hash = ?", (reset_id,))
            raise
        self.send_json(
            200,
            {
                "ok": True,
                "message": "If an account exists, an OTP was sent to its registered email and WhatsApp. It expires in 3 minutes.",
            },
        )

    def reset_customer_password(self, body: dict) -> None:
        email = validate_email(body.get("email"))
        otp = clean_text(body.get("otp"), "OTP", 6)
        if not re.fullmatch(r"\d{6}", otp):
            raise APIError(400, "Enter the 6-digit OTP.")
        password = validate_password(body.get("password"))
        with connect_database() as db:
            db.execute("BEGIN IMMEDIATE")
            customer = db.execute(
                "SELECT id FROM customers WHERE email = ? AND password_hash IS NOT NULL",
                (email,),
            ).fetchone()
            if not customer:
                raise APIError(400, "OTP is invalid or expired. Request a new one.")
            reset_rows = db.execute(
                """SELECT token_hash, otp_salt, attempts FROM customer_password_resets
                   WHERE customer_id = ? AND used_at IS NULL AND expires_at > ?
                     AND attempts < ? AND otp_salt IS NOT NULL""",
                (customer["id"], int(time.time()), PASSWORD_RESET_MAX_ATTEMPTS),
            ).fetchall()
            matched_reset = None
            for reset in reset_rows:
                salt_hex, saved_hash = reset["otp_salt"].split(":", 1)
                candidate_hash = hashlib.pbkdf2_hmac(
                    "sha256", otp.encode("ascii"), bytes.fromhex(salt_hex), PASSWORD_ITERATIONS
                ).hex()
                if hmac.compare_digest(candidate_hash, saved_hash):
                    matched_reset = reset
                    break
            if not matched_reset:
                db.execute(
                    """UPDATE customer_password_resets SET attempts = attempts + 1
                       WHERE customer_id = ? AND used_at IS NULL AND expires_at > ?""",
                    (customer["id"], int(time.time())),
                )
                reset_failed = True
            else:
                db.execute(
                    "UPDATE customers SET password_hash = ? WHERE id = ?",
                    (hash_password(password), customer["id"]),
                )
                db.execute(
                    "UPDATE customer_password_resets SET used_at = ? WHERE customer_id = ?",
                    (int(time.time()), customer["id"]),
                )
                db.execute(
                    "DELETE FROM sessions WHERE role = 'customer' AND user_id = ?",
                    (customer["id"],),
                )
                db.execute(
                    "DELETE FROM customer_password_resets WHERE customer_id = ?",
                    (customer["id"],),
                )
                reset_failed = False
        if reset_failed:
            raise APIError(400, "OTP is invalid, expired, or has too many attempts. Request a new one.")
        self.send_json(200, {"ok": True, "message": "Password updated. You can now sign in."})

    def login(self, path: str, body: dict) -> None:
        self.enforce_same_origin()
        username = ""
        if path == "/api/customer/signup":
            name = clean_text(body.get("name"), "Name", 120)
            email = validate_email(body.get("email"))
            phone = clean_text(body.get("phone"), "Phone number", 40)
            password = validate_password(body.get("password"))
            with connect_database() as db:
                existing = db.execute("SELECT id, password_hash FROM customers WHERE email = ?", (email,)).fetchone()
                if existing:
                    if existing["password_hash"]:
                        raise APIError(409, "An account already exists for this email. Please sign in.")
                    user_id = existing["id"]
                    db.execute(
                        "UPDATE customers SET name = ?, phone = ?, password_hash = ? WHERE id = ?",
                        (name, phone, hash_password(password), user_id),
                    )
                else:
                    cursor = db.execute(
                        """INSERT INTO customers (name, email, phone, password_hash, created_at)
                           VALUES (?, ?, ?, ?, ?)""",
                        (name, email, phone, hash_password(password), now_utc()),
                    )
                    user_id = cursor.lastrowid
                username = name
            role = "customer"
        elif path == "/api/customer/login":
            email = validate_email(body.get("email"))
            password = validate_password(body.get("password"))
            with connect_database() as db:
                user = db.execute(
                    "SELECT id, name, password_hash FROM customers WHERE email = ?", (email,)
                ).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                raise APIError(401, "Email or password is incorrect.")
            user_id, username, role = user["id"], user["name"], "customer"
        else:
            admin_name = clean_text(body.get("username"), "Username", 80)
            password = validate_password(body.get("password"))
            with connect_database() as db:
                user = db.execute(
                    "SELECT id, username, password_hash FROM admins WHERE username = ?", (admin_name,)
                ).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                raise APIError(401, "Username or password is incorrect.")
            user_id, username, role = user["id"], user["username"], "admin"
        token, csrf = self.create_session(user_id, role)
        self.send_json(
            200,
            {"authenticated": True, "role": role, "name": username, "csrf": csrf},
            headers={"Set-Cookie": self.set_session_cookie(token)},
        )

    def create_subscription(self, body: dict) -> None:
        name = clean_text(body.get("name"), "Name", 120)
        email = validate_email(body.get("email"))
        phone = clean_text(body.get("phone"), "Phone number", 40)
        address = clean_text(body.get("address"), "Delivery address", 1000)
        plan_id = body.get("plan_id")
        plan = None
        if plan_id is not None:
            plan_id = clean_text(plan_id, "Subscription plan", 32)
            with connect_database() as db:
                plan = db.execute(
                    "SELECT id, name, price, frequency FROM subscription_plans WHERE id = ?",
                    (plan_id,),
                ).fetchone()
            if not plan:
                raise APIError(400, "Select an available subscription plan.")
            frequency = plan["frequency"]
            box_size = plan["name"]
            plan_name = plan["name"]
            plan_price = plan["price"]
        else:
            frequency = clean_text(body.get("frequency"), "Frequency", 20)
            box_size = clean_text(body.get("box_size"), "Box size", 20)
            if frequency not in {"weekly", "fortnightly", "monthly"}:
                raise APIError(400, "Select a valid delivery frequency.")
            if box_size not in {"small", "medium", "family"}:
                raise APIError(400, "Select a valid box size.")
            plan_name = None
            plan_price = None
        with connect_database() as db:
            customer = db.execute("SELECT id FROM customers WHERE email = ?", (email,)).fetchone()
            if customer:
                customer_id = customer["id"]
                db.execute(
                    "UPDATE customers SET name = ?, phone = ?, address = ? WHERE id = ?",
                    (name, phone, address, customer_id),
                )
            else:
                customer_id = db.execute(
                    """INSERT INTO customers (name, email, phone, address, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (name, email, phone, address, now_utc()),
                ).lastrowid
            subscription_id = uuid.uuid4().hex
            db.execute(
                """INSERT INTO subscriptions
                   (id, customer_id, frequency, box_size, address, plan_id, plan_name, plan_price, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (
                    subscription_id, customer_id, frequency, box_size, address,
                    plan["id"] if plan else None, plan_name, plan_price, now_utc(),
                ),
            )
        self.send_json(201, {"ok": True, "id": subscription_id, "status": "pending"})

    def create_order(self, body: dict) -> None:
        session = self.require_role("customer", mutate=True)
        address = clean_text(body.get("address"), "Delivery address", 1000)
        phone = clean_text(body.get("phone"), "Phone number", 40)
        items = body.get("items")
        if not isinstance(items, list) or not items or len(items) > 100:
            raise APIError(400, "Your basket must contain between 1 and 100 products.")
        quantities: dict[str, int] = {}
        for item in items:
            if not isinstance(item, dict):
                raise APIError(400, "Each basket item must be an object.")
            product_id = clean_text(item.get("product_id"), "Product ID", 80)
            quantity = item.get("quantity")
            if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity < 1 or quantity > 99:
                raise APIError(400, "Product quantities must be between 1 and 99.")
            quantities[product_id] = quantities.get(product_id, 0) + quantity
        if any(quantity > 99 for quantity in quantities.values()):
            raise APIError(400, "Product quantities must be 99 or fewer.")

        order_id = uuid.uuid4().hex
        timestamp = now_utc()
        total = 0
        with connect_database() as db:
            db.execute("BEGIN IMMEDIATE")
            customer = db.execute("SELECT id FROM customers WHERE id = ?", (session["user_id"],)).fetchone()
            if not customer:
                raise APIError(401, "Customer account was not found. Please sign in again.")
            prepared = []
            for product_id, quantity in quantities.items():
                product = db.execute(
                    "SELECT id, name, price, stock FROM products WHERE id = ? AND active = 1",
                    (product_id,),
                ).fetchone()
                if not product:
                    raise APIError(409, "A product in your basket is no longer available.")
                if product["stock"] < quantity:
                    raise APIError(409, f"Not enough stock for {product['name']}.")
                total += product["price"] * quantity
                prepared.append((product, quantity))
            db.execute(
                """INSERT INTO orders (id, customer_id, phone, address, total, status, created_at)
                   VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
                (order_id, session["user_id"], phone, address, total, timestamp),
            )
            for product, quantity in prepared:
                db.execute(
                    """INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price)
                       VALUES (?, ?, ?, ?, ?)""",
                    (order_id, product["id"], product["name"], quantity, product["price"]),
                )
                db.execute("UPDATE products SET stock = stock - ? WHERE id = ?", (quantity, product["id"]))
            db.execute(
                "UPDATE customers SET phone = ?, address = ? WHERE id = ?",
                (phone, address, session["user_id"]),
            )
        self.send_json(201, {"ok": True, "id": order_id, "total": total, "status": "pending"})

    def validate_product(self, body: dict) -> dict:
        name = clean_text(body.get("name"), "Product name", 160)
        category = clean_text(body.get("category"), "Category", 80)
        unit = clean_text(body.get("unit", ""), "Unit", 80, required=False)
        discount = clean_text(body.get("discount", ""), "Discount", 40, required=False)
        image_url = clean_text(body.get("image_url", ""), "Image URL", 2000, required=False)
        if image_url:
            if re.fullmatch(r"/assets/uploads/[a-f0-9]{32}\.(?:png|jpg|webp)", image_url):
                pass
            else:
                parsed = urlsplit(image_url)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    raise APIError(400, "Image URL must use http or https or be a saved local upload.")
        price = body.get("price")
        old_price = body.get("old_price")
        stock = body.get("stock", 0)
        active = body.get("active", True)
        if not isinstance(price, int) or isinstance(price, bool) or price < 0:
            raise APIError(400, "Price must be a non-negative whole number of rupees.")
        if old_price is not None and (
            not isinstance(old_price, int) or isinstance(old_price, bool) or old_price < 0
        ):
            raise APIError(400, "Old price must be a non-negative whole number or blank.")
        if not isinstance(stock, int) or isinstance(stock, bool) or stock < 0:
            raise APIError(400, "Stock must be a non-negative whole number.")
        if not isinstance(active, bool):
            raise APIError(400, "Active must be true or false.")
        return {
            "name": name, "category": category, "price": price, "old_price": old_price,
            "unit": unit, "discount": discount, "image_url": image_url,
            "stock": stock, "active": int(active),
        }

    def api_put(self, path: str, body: dict) -> None:
        session = self.session()
        if path.startswith("/api/admin/"):
            session = self.require_role("admin", mutate=True)
        match = re.fullmatch(r"/api/admin/products/([a-f0-9]{32})", path)
        if match:
            product = self.validate_product(body)
            with connect_database() as db:
                cursor = db.execute(
                    """UPDATE products
                       SET name = ?, category = ?, price = ?, old_price = ?, unit = ?,
                           discount = ?, image_url = ?, stock = ?, active = ?
                       WHERE id = ?""",
                    (
                        product["name"], product["category"], product["price"], product["old_price"],
                        product["unit"], product["discount"], product["image_url"],
                        product["stock"], product["active"], match.group(1),
                    ),
                )
                if cursor.rowcount == 0:
                    raise APIError(404, "Product not found.")
                row = db.execute("SELECT * FROM products WHERE id = ?", (match.group(1),)).fetchone()
            return self.send_json(200, {"product": product_from_row(row)})
        order_match = re.fullmatch(r"/api/admin/orders/([a-f0-9]{32})", path)
        if order_match:
            status = clean_text(body.get("status"), "Order status", 20)
            if status not in ALLOWED_ORDER_STATUSES:
                raise APIError(400, "Select a valid order status.")
            with connect_database() as db:
                db.execute("BEGIN IMMEDIATE")
                order = db.execute("SELECT status FROM orders WHERE id = ?", (order_match.group(1),)).fetchone()
                if not order:
                    raise APIError(404, "Order not found.")
                if order["status"] == "cancelled" and status != "cancelled":
                    raise APIError(409, "Cancelled orders cannot be reopened.")
                if order["status"] == "delivered" and status != "delivered":
                    raise APIError(409, "Delivered orders cannot be cancelled or reopened.")
                if status == "cancelled" and order["status"] != "cancelled":
                    items = db.execute(
                        "SELECT product_id, quantity FROM order_items WHERE order_id = ?",
                        (order_match.group(1),),
                    ).fetchall()
                    for item in items:
                        db.execute("UPDATE products SET stock = stock + ? WHERE id = ?", (item["quantity"], item["product_id"]))
                db.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_match.group(1)))
            return self.send_json(200, {"ok": True, "status": status})
        sub_match = re.fullmatch(r"/api/admin/subscriptions/([a-f0-9]{32})", path)
        if sub_match:
            status = clean_text(body.get("status"), "Subscription status", 20)
            if status not in ALLOWED_SUBSCRIPTION_STATUSES:
                raise APIError(400, "Select a valid subscription status.")
            with connect_database() as db:
                cursor = db.execute(
                    "UPDATE subscriptions SET status = ? WHERE id = ?",
                    (status, sub_match.group(1)),
                )
                if cursor.rowcount == 0:
                    raise APIError(404, "Subscription not found.")
            return self.send_json(200, {"ok": True, "status": status})
        raise APIError(404, "API route not found.")

    def api_delete(self, path: str) -> None:
        self.require_role("admin", mutate=True)
        match = re.fullmatch(r"/api/admin/products/([a-f0-9]{32})", path)
        if not match:
            raise APIError(404, "API route not found.")
        with connect_database() as db:
            cursor = db.execute("UPDATE products SET active = 0 WHERE id = ?", (match.group(1),))
            if cursor.rowcount == 0:
                raise APIError(404, "Product not found.")
        self.send_json(200, {"ok": True})


class LocalHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Fresh Vegbox local shop and admin panel.")
    setup = parser.add_mutually_exclusive_group()
    setup.add_argument("--setup-admin", action="store_true", help="Create the first protected admin account.")
    setup.add_argument("--reset-admin-password", action="store_true", help="Set a new password for an existing admin account.")
    arguments = parser.parse_args()
    init_database()
    if arguments.setup_admin or arguments.reset_admin_password:
        username = input("Admin username: ").strip()
        password = read_password("New admin password (at least 12 characters): ")
        confirmation = read_password("Confirm new admin password: ")
        if password != confirmation:
            parser.error("Passwords do not match.")
        try:
            if arguments.setup_admin:
                setup_admin(username, password)
            else:
                reset_admin_password(username, password)
        except ValueError as exc:
            parser.error(str(exc))
        action = "created" if arguments.setup_admin else "password updated"
        print(f"Admin account {action}. Start the website with: python server.py")
        return
    global _server
    try:
        _server = LocalHTTPServer((HOST, PORT), RequestHandler)
    except OSError as exc:
        parser.error(f"Cannot bind to http://{HOST}:{PORT}: {exc}")
    print(f"Fresh Vegbox shop:  http://127.0.0.1:{PORT}/")
    print(f"Fresh Vegbox admin: http://127.0.0.1:{PORT}/admin")
    print(f"Database:           {DATABASE}")
    try:
        _server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Fresh Vegbox server.")
    finally:
        _server.server_close()


if __name__ == "__main__":
    main()
