#!/usr/bin/env python3
"""Gruppe Sechs portal: dependency-free Python/SQLite backend."""
from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

# Keep newly created database/WAL/session files private to the service account.
os.umask(0o077)

ROOT = Path(__file__).resolve().parent
HTML_FILE = ROOT / "index.html"
DB_FILE = Path(os.environ.get("G6_DB_PATH", ROOT / "gruppe6.sqlite3"))
HOST = os.environ.get("G6_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", os.environ.get("G6_PORT", "8080")))
COOKIE_SECURE = os.environ.get("G6_COOKIE_SECURE", "1") != "0"
SESSION_HOURS = int(os.environ.get("G6_SESSION_HOURS", "12"))
MAX_BODY = 64 * 1024

ROLE_LABEL = {"manager": "Руководство", "officer": "Офицер охраны", "client": "Клиент"}
REPORT_LABEL = {"shift": "Сменный отчёт", "incident": "Происшествие", "shooting": "Инцидент со стрельбой"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_FILE, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=15000")
    return con


def init_db() -> None:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    with connect() as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          phone TEXT NOT NULL DEFAULT '', company TEXT NOT NULL DEFAULT '', role TEXT NOT NULL
            CHECK(role IN ('manager','officer','client')),
          password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS objects (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, address TEXT NOT NULL,
          contact TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', owner_id TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL,
          FOREIGN KEY(owner_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS object_officers (
          object_id TEXT NOT NULL, user_id TEXT NOT NULL,
          PRIMARY KEY(object_id,user_id),
          FOREIGN KEY(object_id) REFERENCES objects(id) ON DELETE CASCADE,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS shifts (
          id TEXT PRIMARY KEY, user_id TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_shifts_user_open ON shifts(user_id,ended_at);
        CREATE TABLE IF NOT EXISTS reports (
          id TEXT PRIMARY KEY, type TEXT NOT NULL, title TEXT NOT NULL, object_id TEXT,
          author_id TEXT NOT NULL, event_time TEXT NOT NULL, circumstances TEXT NOT NULL DEFAULT '',
          response TEXT NOT NULL DEFAULT '', emergency TEXT NOT NULL DEFAULT '',
          notified TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
          FOREIGN KEY(object_id) REFERENCES objects(id), FOREIGN KEY(author_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, csrf_token TEXT NOT NULL,
          expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        CREATE TABLE IF NOT EXISTS login_attempts (
          key TEXT PRIMARY KEY, count INTEGER NOT NULL, window_start INTEGER NOT NULL,
          blocked_until INTEGER NOT NULL DEFAULT 0
        );
        """)
    # Optional one-time administrator bootstrap for hosted deployments.
    # The account is created only when no manager exists; remove these env vars afterwards.
    admin_name = os.environ.get("G6_ADMIN_NAME", "").strip()
    admin_email = os.environ.get("G6_ADMIN_EMAIL", "").strip().lower()
    admin_password = os.environ.get("G6_ADMIN_PASSWORD", "")
    if admin_name and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", admin_email) and len(admin_password) >= 12:
        with connect() as con:
            exists = con.execute("SELECT 1 FROM users WHERE role='manager' LIMIT 1").fetchone()
            if not exists:
                salt, digest = password_hash(admin_password)
                con.execute("INSERT INTO users(id,name,email,role,password_salt,password_hash,active,created_at) VALUES(?,?,?,'manager',?,?,1,?)",
                            ("u_" + secrets.token_urlsafe(12), admin_name, admin_email, salt, digest, now_iso()))
                print("Первый администратор создан из переменных окружения.")



def password_hash(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt: str, expected: str) -> bool:
    try:
        _, actual = password_hash(password, salt)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def row_user(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"], "name": row["name"], "email": row["email"],
        "phone": row["phone"], "company": row["company"], "role": row["role"],
        "active": bool(row["active"]), "createdAt": row["created_at"]
    }


def public_user_by_id(con: sqlite3.Connection, user_id: str) -> dict | None:
    row = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return row_user(row) if row else None


def create_session(con: sqlite3.Connection, user_id: str) -> tuple[str, str, int]:
    token = secrets.token_urlsafe(40)
    csrf = secrets.token_urlsafe(32)
    now = int(time.time())
    expires = now + SESSION_HOURS * 3600
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    con.execute("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)",
                (token_hash, user_id, csrf, expires, now))
    con.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    return token, csrf, expires


def user_session(handler: BaseHTTPRequestHandler):
    cookie = handler.headers.get("Cookie", "")
    token = None
    for part in cookie.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == "g6_session":
            token = value
            break
    if not token:
        return None, None, None
    digest = hashlib.sha256(token.encode()).hexdigest()
    con = connect()
    row = con.execute("""SELECT s.csrf_token,s.expires_at,u.* FROM sessions s
      JOIN users u ON u.id=s.user_id WHERE s.token_hash=?""", (digest,)).fetchone()
    if not row or row["expires_at"] < int(time.time()) or not row["active"]:
        con.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
        con.commit()
        con.close()
        return None, None, None
    return con, row, digest


def clean_text(value, field, maximum, required=False):
    value = str(value or "").strip()
    if required and not value:
        raise ValueError(f"Заполните поле «{field}».")
    if len(value) > maximum:
        raise ValueError(f"Поле «{field}» слишком длинное.")
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "Gruppe6/1.0"

    def log_message(self, fmt, *args):
        # Avoid writing email addresses, form contents or session-related data to logs.
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    def send_json(self, status: int, payload: dict, headers: dict | None = None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Некорректный размер запроса.")
        if length <= 0 or length > MAX_BODY:
            raise ValueError("Размер запроса недопустим.")
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Ожидались данные формы.")
        return data

    def origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return False
        try:
            parsed = urlparse(origin)
            host = self.headers.get("Host", "").lower()
            return parsed.netloc.lower() == host and parsed.scheme in ("http", "https")
        except Exception:
            return False

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/bootstrap":
            self.api_bootstrap()
            return
        if path == "/api/health":
            self.send_json(200, {"status": "ok"})
            return
        # Only the public page is served. Never expose the Python source, SQLite
        # database, WAL files, backups, or any other server-side files.
        if path not in ("/", "/index.html"):
            self.send_error(404)
            return
        safe = HTML_FILE
        if not safe.is_file():
            self.send_error(404)
            return
        content = safe.read_bytes()
        mime = mimetypes.guess_type(safe.name)[0] or "application/octet-stream"
        if mime.startswith("text/") or mime in ("application/javascript", "application/json"):
            mime += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; object-src 'none'")
        self.send_header("Cache-Control", "no-store" if safe.name == "index.html" else "public, max-age=3600")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        path = urlparse(self.path).path
        if not self.origin_ok():
            self.send_json(403, {"error": "Запрос отклонён. Обновите страницу и повторите попытку."})
            return
        try:
            data = self.read_json()
            if path == "/api/login":
                self.api_login(data)
            elif path == "/api/register-client":
                self.api_register(data)
            elif path == "/api/logout":
                self.api_logout()
            elif path == "/api/employees":
                self.api_create_employee(data)
            elif path == "/api/objects":
                self.api_create_object(data)
            elif path == "/api/shifts/toggle":
                self.api_toggle_shift()
            elif path == "/api/reports":
                self.api_create_report(data)
            elif path == "/api/export":
                self.api_export()
            else:
                self.send_json(404, {"error": "Маршрут не найден."})
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
        except PermissionError as exc:
            self.send_json(403, {"error": str(exc)})
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "Запись с такими данными уже существует или связанная запись не найдена."})
        except Exception:
            self.send_json(500, {"error": "Внутренняя ошибка сервера. Попробуйте позже."})

    def do_PATCH(self):
        path = urlparse(self.path).path
        if not self.origin_ok():
            self.send_json(403, {"error": "Запрос отклонён. Обновите страницу и повторите попытку."})
            return
        m = re.fullmatch(r"/api/employees/([A-Za-z0-9_-]+)/active", path)
        if not m:
            self.send_json(404, {"error": "Маршрут не найден."})
            return
        try:
            data = self.read_json()
            self.api_set_employee_active(m.group(1), data)
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
        except PermissionError as exc:
            self.send_json(403, {"error": str(exc)})
        except Exception:
            self.send_json(500, {"error": "Не удалось изменить статус сотрудника."})

    def auth_required(self):
        con, row, digest = user_session(self)
        if not con:
            self.send_json(401, {"error": "Сессия завершилась. Войдите в систему заново."})
            return None
        csrf = self.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(csrf, row["csrf_token"]):
            con.close()
            self.send_json(403, {"error": "Проверка безопасности не пройдена. Обновите страницу."})
            return None
        return con, row, digest

    def cookie_header(self, token: str, max_age: int):
        parts = [f"g6_session={token}", "Path=/", "HttpOnly", "SameSite=Strict", f"Max-Age={max_age}"]
        if COOKIE_SECURE:
            parts.append("Secure")
        return "; ".join(parts)

    def api_login(self, data):
        email = clean_text(data.get("email"), "Email", 120, True).lower()
        password = str(data.get("password") or "")
        if len(password) > 200:
            raise ValueError("Неверный email или пароль.")
        ip = self.client_address[0]
        attempt_key = hashlib.sha256(f"{ip}|{email}".encode()).hexdigest()
        now = int(time.time())
        with connect() as con:
            attempt = con.execute("SELECT * FROM login_attempts WHERE key=?", (attempt_key,)).fetchone()
            if attempt and attempt["blocked_until"] > now:
                self.send_json(429, {"error": "Слишком много попыток входа. Повторите позже."})
                return
            user = con.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
            valid = bool(user and user["active"] and verify_password(password, user["password_salt"], user["password_hash"]))
            if not valid:
                if attempt and now - attempt["window_start"] < 900:
                    count = attempt["count"] + 1
                    blocked = now + 900 if count >= 8 else 0
                    con.execute("UPDATE login_attempts SET count=?,blocked_until=? WHERE key=?", (count, blocked, attempt_key))
                else:
                    con.execute("INSERT OR REPLACE INTO login_attempts(key,count,window_start,blocked_until) VALUES(?,?,?,0)", (attempt_key, 1, now))
                self.send_json(401, {"error": "Неверный email или пароль, либо аккаунт отключён."})
                return
            con.execute("DELETE FROM login_attempts WHERE key=?", (attempt_key,))
            token, csrf, expires = create_session(con, user["id"])
        self.send_json(200, {"ok": True, "csrfToken": csrf}, {"Set-Cookie": self.cookie_header(token, expires - now)})

    def api_register(self, data):
        name = clean_text(data.get("name"), "Имя", 80, True)
        phone = clean_text(data.get("phone"), "Телефон", 30, True)
        company = clean_text(data.get("company"), "Компания", 100)
        email = clean_text(data.get("email"), "Email", 120, True).lower()
        password = str(data.get("password") or "")
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("Укажите корректный email.")
        if len(password) < 10 or len(password) > 200:
            raise ValueError("Пароль должен содержать не менее 10 символов.")
        salt, digest = password_hash(password)
        user_id = "u_" + secrets.token_urlsafe(12)
        created = now_iso()
        with connect() as con:
            con.execute("INSERT INTO users(id,name,email,phone,company,role,password_salt,password_hash,active,created_at) VALUES(?,?,?,?,?,'client',?,?,1,?)",
                        (user_id, name, email, phone, company, salt, digest, created))
            token, csrf, expires = create_session(con, user_id)
        now = int(time.time())
        self.send_json(201, {"ok": True, "csrfToken": csrf}, {"Set-Cookie": self.cookie_header(token, expires - now)})

    def api_logout(self):
        con, row, digest = user_session(self)
        if con:
            csrf = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(csrf, row["csrf_token"]):
                con.close()
                self.send_json(403, {"error": "Проверка безопасности не пройдена."})
                return
            con.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
            con.commit()
            con.close()
        expired = "g6_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + ("; Secure" if COOKIE_SECURE else "")
        self.send_json(200, {"ok": True}, {"Set-Cookie": expired})

    def api_bootstrap(self):
        con, row, digest = user_session(self)
        if not con:
            self.send_json(200, {"authenticated": False})
            return
        user = row_user(row)
        role = user["role"]
        if role == "manager":
            users = con.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
            objects = con.execute("SELECT * FROM objects ORDER BY created_at DESC").fetchall()
            shifts = con.execute("SELECT * FROM shifts ORDER BY started_at DESC").fetchall()
            reports = con.execute("SELECT * FROM reports ORDER BY created_at DESC").fetchall()
        elif role == "officer":
            objects = con.execute("""SELECT DISTINCT o.* FROM objects o LEFT JOIN object_officers oo ON oo.object_id=o.id
              WHERE o.status='active' AND oo.user_id=?
              ORDER BY o.created_at DESC""", (user["id"],)).fetchall()
            object_ids = [r["id"] for r in objects]
            owner_ids = [r["owner_id"] for r in objects]
            officer_ids = [user["id"]]
            for oid in object_ids:
                officer_ids += [x[0] for x in con.execute("SELECT user_id FROM object_officers WHERE object_id=?", (oid,)).fetchall()]
            allowed_ids = list(dict.fromkeys(owner_ids + officer_ids))
            users = []
            if allowed_ids:
                marks = ",".join("?" for _ in allowed_ids)
                users = con.execute(f"SELECT * FROM users WHERE id IN ({marks})", allowed_ids).fetchall()
            shifts = con.execute("SELECT * FROM shifts WHERE user_id=? ORDER BY started_at DESC", (user["id"],)).fetchall()
            reports = con.execute("SELECT * FROM reports WHERE author_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
        else:
            objects = con.execute("SELECT * FROM objects WHERE owner_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
            officer_ids = []
            for obj in objects:
                officer_ids += [x[0] for x in con.execute("SELECT user_id FROM object_officers WHERE object_id=?", (obj["id"],)).fetchall()]
            allowed_ids = list(dict.fromkeys([user["id"]] + officer_ids))
            marks = ",".join("?" for _ in allowed_ids)
            users = con.execute(f"SELECT * FROM users WHERE id IN ({marks})", allowed_ids).fetchall() if allowed_ids else []
            shifts = []
            reports = []
        object_out = []
        for obj in objects:
            officer_ids = [x[0] for x in con.execute("SELECT user_id FROM object_officers WHERE object_id=?", (obj["id"],)).fetchall()]
            object_out.append({"id": obj["id"], "name": obj["name"], "type": obj["type"], "address": obj["address"],
                               "contact": obj["contact"], "notes": obj["notes"], "ownerId": obj["owner_id"],
                               "assignedOfficerIds": officer_ids, "status": obj["status"], "createdAt": obj["created_at"]})
        shift_out = [{"id": s["id"], "userId": s["user_id"], "startedAt": s["started_at"], "endedAt": s["ended_at"]} for s in shifts]
        report_out = [{"id": r["id"], "type": r["type"], "typeLabel": REPORT_LABEL.get(r["type"], "Отчёт"),
                       "title": r["title"], "objectId": r["object_id"] or "", "authorId": r["author_id"],
                       "eventTime": r["event_time"], "circumstances": r["circumstances"], "response": r["response"],
                       "emergency": r["emergency"], "notified": r["notified"], "notes": r["notes"], "createdAt": r["created_at"]} for r in reports]
        response = {"authenticated": True, "currentUser": user, "csrfToken": row["csrf_token"],
                    "db": {"users": [row_user(u) for u in users], "objects": object_out,
                           "shifts": shift_out, "reports": report_out}}
        con.close()
        self.send_json(200, response)

    def manager_session(self):
        auth = self.auth_required()
        if not auth:
            return None
        con, row, digest = auth
        if row["role"] != "manager":
            con.close()
            self.send_json(403, {"error": "Это действие доступно только руководству."})
            return None
        return con, row

    def api_create_employee(self, data):
        auth = self.manager_session()
        if not auth: return
        con, manager = auth
        name = clean_text(data.get("name"), "Имя", 80, True)
        phone = clean_text(data.get("phone"), "Телефон", 30)
        email = clean_text(data.get("email"), "Email", 120, True).lower()
        role = data.get("role")
        password = str(data.get("password") or "")
        if role not in ("manager", "officer"):
            con.close(); raise ValueError("Недопустимая роль сотрудника.")
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            con.close(); raise ValueError("Укажите корректный email.")
        if len(password) < 10 or len(password) > 200:
            con.close(); raise ValueError("Временный пароль должен содержать не менее 10 символов.")
        salt, digest = password_hash(password)
        user_id = "u_" + secrets.token_urlsafe(12)
        con.execute("INSERT INTO users(id,name,email,phone,company,role,password_salt,password_hash,active,created_at) VALUES(?,?,?,?,?,?,?,?,1,?)",
                    (user_id, name, email, phone, "Gruppe Sechs", role, salt, digest, now_iso()))
        con.commit()
        con.close()
        self.send_json(201, {"ok": True})

    def api_set_employee_active(self, user_id, data):
        auth = self.manager_session()
        if not auth: return
        con, manager = auth
        target = con.execute("SELECT * FROM users WHERE id=? AND role IN ('manager','officer')", (user_id,)).fetchone()
        if not target:
            con.close(); self.send_json(404, {"error": "Сотрудник не найден."}); return
        if user_id == manager["id"]:
            con.close(); raise ValueError("Нельзя отключить собственный аккаунт.")
        active = data.get("active")
        if not isinstance(active, bool):
            con.close(); raise ValueError("Некорректный статус.")
        if target["role"] == "manager" and not active:
            count = con.execute("SELECT COUNT(*) FROM users WHERE role='manager' AND active=1").fetchone()[0]
            if count <= 1:
                con.close(); raise ValueError("Нельзя отключить последнего активного руководителя.")
        con.execute("UPDATE users SET active=? WHERE id=?", (1 if active else 0, user_id))
        con.commit()
        con.close()
        self.send_json(200, {"ok": True})

    def api_create_object(self, data):
        auth = self.auth_required()
        if not auth: return
        con, row, _ = auth
        if row["role"] not in ("manager", "client"):
            con.close(); self.send_json(403, {"error": "У вас нет доступа к созданию объектов."}); return
        name = clean_text(data.get("name"), "Название объекта", 100, True)
        kind = clean_text(data.get("type"), "Тип объекта", 80, True)
        address = clean_text(data.get("address"), "Адрес", 180, True)
        contact = clean_text(data.get("contact"), "Контакт", 80)
        notes = clean_text(data.get("notes"), "Примечание", 600)
        owner_id = row["id"] if row["role"] == "client" else clean_text(data.get("ownerId"), "Клиент", 80, True)
        owner = con.execute("SELECT id FROM users WHERE id=? AND role='client' AND active=1", (owner_id,)).fetchone()
        if not owner:
            con.close(); raise ValueError("Выбранный клиент не найден или отключён.")
        officer_id = clean_text(data.get("officerId"), "Ответственный сотрудник", 80) if row["role"] == "manager" else ""
        if officer_id:
            officer = con.execute("SELECT id FROM users WHERE id=? AND role='officer' AND active=1", (officer_id,)).fetchone()
            if not officer:
                con.close(); raise ValueError("Выбранный сотрудник не найден или отключён.")
        object_id = "o_" + secrets.token_urlsafe(12)
        con.execute("INSERT INTO objects(id,name,type,address,contact,notes,owner_id,status,created_at) VALUES(?,?,?,?,?,?,?,'active',?)",
                    (object_id, name, kind, address, contact, notes, owner_id, now_iso()))
        if officer_id:
            con.execute("INSERT INTO object_officers(object_id,user_id) VALUES(?,?)", (object_id, officer_id))
        con.commit()
        con.close()
        self.send_json(201, {"ok": True})

    def api_toggle_shift(self):
        auth = self.auth_required()
        if not auth: return
        con, row, _ = auth
        if row["role"] not in ("manager", "officer"):
            con.close(); self.send_json(403, {"error": "Учёт смен доступен только сотрудникам."}); return
        active = con.execute("SELECT * FROM shifts WHERE user_id=? AND ended_at IS NULL", (row["id"],)).fetchone()
        if active:
            con.execute("UPDATE shifts SET ended_at=? WHERE id=?", (now_iso(), active["id"]))
            message = "Окончание смены зафиксировано."
        else:
            con.execute("INSERT INTO shifts(id,user_id,started_at) VALUES(?,?,?)",
                        ("s_" + secrets.token_urlsafe(12), row["id"], now_iso()))
            message = "Выход на смену зафиксирован."
        con.commit()
        con.close()
        self.send_json(200, {"ok": True, "message": message})

    def api_create_report(self, data):
        auth = self.auth_required()
        if not auth: return
        con, row, _ = auth
        if row["role"] not in ("manager", "officer"):
            con.close(); self.send_json(403, {"error": "Создавать служебные отчёты могут только сотрудники."}); return
        report_type = data.get("type")
        if report_type not in REPORT_LABEL:
            con.close(); raise ValueError("Недопустимый тип отчёта.")
        title = clean_text(data.get("title"), "Тема отчёта", 120, True)
        object_id = clean_text(data.get("objectId"), "Объект", 80)
        event_time = clean_text(data.get("eventTime"), "Дата и время", 40, True)
        circumstances = clean_text(data.get("circumstances"), "Обстоятельства", 1200)
        response = clean_text(data.get("response"), "Принятые меры", 1000)
        emergency = clean_text(data.get("emergency"), "Экстренная помощь", 80)
        notified = clean_text(data.get("notified"), "Уведомление руководства", 80)
        notes = clean_text(data.get("notes"), "Комментарий", 800)
        if report_type in ("incident", "shooting") and not circumstances:
            con.close(); raise ValueError("Заполните поле с обстоятельствами события.")
        if object_id:
            obj = con.execute("SELECT * FROM objects WHERE id=? AND status='active'", (object_id,)).fetchone()
            if not obj:
                con.close(); raise ValueError("Объект не найден или неактивен.")
            if row["role"] == "officer":
                allowed = con.execute("SELECT 1 FROM object_officers WHERE object_id=? AND user_id=?", (object_id, row["id"])).fetchone()
                if not allowed:
                    con.close(); raise PermissionError("Этот объект вам не назначен.")
        report_id = "r_" + secrets.token_urlsafe(12)
        con.execute("INSERT INTO reports(id,type,title,object_id,author_id,event_time,circumstances,response,emergency,notified,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (report_id, report_type, title, object_id or None, row["id"], event_time, circumstances, response, emergency, notified, notes, now_iso()))
        con.commit()
        con.close()
        self.send_json(201, {"ok": True})

    def api_export(self):
        auth = self.manager_session()
        if not auth: return
        con, row = auth
        users = [row_user(u) for u in con.execute("SELECT * FROM users ORDER BY created_at").fetchall()]
        objects = []
        for o in con.execute("SELECT * FROM objects").fetchall():
            officers = [x[0] for x in con.execute("SELECT user_id FROM object_officers WHERE object_id=?", (o["id"],)).fetchall()]
            objects.append({"id":o["id"],"name":o["name"],"type":o["type"],"address":o["address"],"contact":o["contact"],"notes":o["notes"],"ownerId":o["owner_id"],"assignedOfficerIds":officers,"status":o["status"],"createdAt":o["created_at"]})
        shifts = [{"id":s["id"],"userId":s["user_id"],"startedAt":s["started_at"],"endedAt":s["ended_at"]} for s in con.execute("SELECT * FROM shifts").fetchall()]
        reports = [{"id":r["id"],"type":r["type"],"typeLabel":REPORT_LABEL.get(r["type"],"Отчёт"),"title":r["title"],"objectId":r["object_id"] or "","authorId":r["author_id"],"eventTime":r["event_time"],"circumstances":r["circumstances"],"response":r["response"],"emergency":r["emergency"],"notified":r["notified"],"notes":r["notes"],"createdAt":r["created_at"]} for r in con.execute("SELECT * FROM reports").fetchall()]
        con.close()
        body = json.dumps({"exportedAt":now_iso(),"users":users,"objects":objects,"shifts":shifts,"reports":reports}, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="gruppe6-backup.json"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def create_admin():
    init_db()
    import getpass
    name = input("Имя администратора: ").strip()
    email = input("Email администратора: ").strip().lower()
    password = getpass.getpass("Пароль (минимум 12 символов): ")
    confirm = getpass.getpass("Повторите пароль: ")
    if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        print("Имя и корректный email обязательны.", file=sys.stderr); sys.exit(2)
    if len(password) < 12 or password != confirm:
        print("Пароли должны совпадать и содержать не менее 12 символов.", file=sys.stderr); sys.exit(2)
    salt, digest = password_hash(password)
    with connect() as con:
        if con.execute("SELECT 1 FROM users WHERE role='manager' LIMIT 1").fetchone():
            print("Руководитель уже существует. Нового администратора можно создать из кабинета.", file=sys.stderr); sys.exit(2)
        con.execute("INSERT INTO users(id,name,email,role,password_salt,password_hash,active,created_at) VALUES(?,?,?,'manager',?,?,1,?)",
                    ("u_" + secrets.token_urlsafe(12), name, email, salt, digest, now_iso()))
    print("Администратор создан. Пароль сохранён в виде криптографического хеша.")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        create_admin(); return
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Gruppe Sechs portal listening on http://{HOST}:{PORT}")
    print("Для публичного запуска используйте HTTPS reverse proxy и установите G6_COOKIE_SECURE=1.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
