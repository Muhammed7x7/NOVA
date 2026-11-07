#!/usr/bin/env python3
"""Access Hub — standalone responsive homepage and role-based admin dashboard.
No third-party Python packages required.  State is stored in a local SQLite database.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import secrets
import sqlite3
import shutil
import subprocess
import shlex
import sys
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

APP_DIR = Path(os.environ.get("APP_DIR", Path.home() / "access-hub"))
DATA_DIR = Path(os.environ.get("APP_DATA_DIR", APP_DIR / "data"))
DB_PATH = DATA_DIR / "access_hub.sqlite3"
PORT = int(os.environ.get("ACCESS_HUB_PORT", "5120"))
SESSION_TTL_SECONDS = 60 * 60 * 12
HASH_ROUNDS = 310_000
DB_LOCK = threading.RLock()
MAVIORKIDE_ROOT = Path(os.environ.get("MAVIORKIDE_ROOT", Path.home() / "maviorkide")).resolve()
MAVI_LAB_CONTAINER = "maviorkide-repo-lab"
MAVI_LAB_TIMEOUT = 90
MAVI_LAB_WORKSPACE_LIMIT = 10 * 1024 * 1024 * 1024
MAVI_LAB_LOCK = threading.RLock()

DEFAULT_SETTINGS = {
    "brand_text": "MERKEZ",
    "home_heading": "Özel erişim alanınıza hoş geldiniz.",
    "home_subtitle": "Standart kullanıcı girişiyle devam edin veya sağ üstteki Özel Giriş alanından yetkili hesabınızı seçin.",
    "accent_color": "#7c5cff",
    "text_tone": "#f7f7fb",
    "surface_brightness": "18",
    "contact_phone": "+90 000 000 00 00",
    "contact_email": "iletisim@example.com",
    "contact_whatsapp": "",
    "contact_instagram": "",
    "contact_address": "İletişim bilgileri yönetici panelinden güncellenir.",
}


def now() -> int:
    return int(time.time())


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def hash_credential(value: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(24)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt.encode("ascii"), HASH_ROUNDS)
    return salt, digest.hex()


def verify_credential(value: str, salt: str, expected: str) -> bool:
    _, actual = hash_credential(value, salt)
    return secrets.compare_digest(actual, expected)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def init_db() -> bool:
    """Initialise schema. Returns True when the first admin was created."""
    with DB_LOCK, connect() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','special','standard')),
                credential_salt TEXT NOT NULL,
                credential_hash TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        for key, value in DEFAULT_SETTINGS.items():
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (key, value))
        admin = con.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
        if admin:
            return False
        password = os.environ.get("INITIAL_ADMIN_PASSWORD", "")
        if len(password) < 12:
            raise RuntimeError("İlk kurulum için en az 12 karakterlik INITIAL_ADMIN_PASSWORD gerekli.")
        salt, digest = hash_credential(password)
        con.execute(
            """INSERT INTO users(username,display_name,role,credential_salt,credential_hash,active,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            ("admin", "Yönetici", "admin", salt, digest, 1, now()),
        )
        return True


def get_settings() -> dict[str, str]:
    with DB_LOCK, connect() as con:
        values = {row["key"]: row["value"] for row in con.execute("SELECT key,value FROM settings")}
    return {**DEFAULT_SETTINGS, **values}


def set_settings(values: dict[str, object]) -> None:
    allowed = set(DEFAULT_SETTINGS)
    cleaned: dict[str, str] = {}
    for key, value in values.items():
        if key not in allowed:
            continue
        value = str(value).strip()
        if len(value) > 1800:
            raise ValueError(f"{key} çok uzun")
        if key in {"accent_color", "text_tone"} and not (len(value) in (4, 7) and value.startswith("#")):
            raise ValueError(f"{key} geçerli bir renk değil")
        if key == "surface_brightness":
            value = str(max(5, min(40, int(value))))
        cleaned[key] = value
    with DB_LOCK, connect() as con:
        for key, value in cleaned.items():
            con.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )


def public_special_users() -> list[dict[str, object]]:
    with DB_LOCK, connect() as con:
        rows = con.execute(
            "SELECT id,username,display_name FROM users WHERE role='special' AND active=1 ORDER BY display_name COLLATE NOCASE"
        ).fetchall()
    return [{"id": r["id"], "username": r["username"], "display_name": r["display_name"]} for r in rows]


def safe_user(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"], "username": row["username"], "display_name": row["display_name"],
        "role": row["role"], "active": bool(row["active"]), "created_at": row["created_at"],
    }


def get_user(user_id: int) -> dict[str, object] | None:
    with DB_LOCK, connect() as con:
        row = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return safe_user(row) if row else None


def authenticate_standard(username: str, key: str) -> dict[str, object] | None:
    return authenticate(username, key, permitted_roles={"standard"})


def authenticate_special(user_id: object, password: str) -> dict[str, object] | None:
    try:
        target = int(user_id)
    except (TypeError, ValueError):
        return None
    with DB_LOCK, connect() as con:
        row = con.execute("SELECT * FROM users WHERE id=? AND role='special' AND active=1", (target,)).fetchone()
    return safe_user(row) if row and verify_credential(password, row["credential_salt"], row["credential_hash"]) else None


def authenticate_admin(password: str) -> dict[str, object] | None:
    with DB_LOCK, connect() as con:
        row = con.execute("SELECT * FROM users WHERE role='admin' AND active=1 LIMIT 1").fetchone()
    return safe_user(row) if row and verify_credential(password, row["credential_salt"], row["credential_hash"]) else None


def authenticate(username: str, credential: str, permitted_roles: set[str]) -> dict[str, object] | None:
    username = username.strip()
    with DB_LOCK, connect() as con:
        row = con.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    if not row or row["role"] not in permitted_roles:
        return None
    return safe_user(row) if verify_credential(credential, row["credential_salt"], row["credential_hash"]) else None


def create_session(user_id: int) -> str:
    raw = secrets.token_urlsafe(40)
    with DB_LOCK, connect() as con:
        con.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))
        con.execute(
            "INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
            (token_hash(raw), user_id, now() + SESSION_TTL_SECONDS, now()),
        )
    return raw


def session_user(raw_token: str | None) -> dict[str, object] | None:
    if not raw_token:
        return None
    with DB_LOCK, connect() as con:
        row = con.execute(
            """SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id
               WHERE sessions.token_hash=? AND sessions.expires_at>? AND users.active=1""",
            (token_hash(raw_token), now()),
        ).fetchone()
    return safe_user(row) if row else None


def delete_session(raw_token: str | None) -> None:
    if raw_token:
        with DB_LOCK, connect() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(raw_token),))


def admin_users() -> list[dict[str, object]]:
    with DB_LOCK, connect() as con:
        rows = con.execute("SELECT * FROM users ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'special' THEN 1 ELSE 2 END, display_name COLLATE NOCASE").fetchall()
    return [safe_user(row) for row in rows]


def valid_username(value: str) -> bool:
    return 3 <= len(value) <= 48 and all(c.isalnum() or c in "._-" for c in value)


def admin_create_user(data: dict[str, object]) -> dict[str, object]:
    role = str(data.get("role", "")).strip()
    username = str(data.get("username", "")).strip().lower()
    display_name = str(data.get("display_name", "")).strip()
    credential = str(data.get("credential", ""))
    if role not in {"standard", "special"}:
        raise ValueError("Kullanıcı türü standart veya özel olmalı")
    if not valid_username(username):
        raise ValueError("Kullanıcı adı 3–48 karakter olmalı; harf, rakam, nokta, alt çizgi ve tire kullanılabilir")
    if not 2 <= len(display_name) <= 70:
        raise ValueError("Görünen ad 2–70 karakter olmalı")
    if len(credential) < 8:
        raise ValueError("Key/şifre en az 8 karakter olmalı")
    salt, digest = hash_credential(credential)
    try:
        with DB_LOCK, connect() as con:
            cursor = con.execute(
                """INSERT INTO users(username,display_name,role,credential_salt,credential_hash,active,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (username, display_name, role, salt, digest, 1, now()),
            )
            user_id = cursor.lastrowid
            row = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    except sqlite3.IntegrityError as exc:
        raise ValueError("Bu kullanıcı adı zaten kullanılıyor") from exc
    return safe_user(row)


def admin_set_user_active(user_id: int, active: bool) -> None:
    with DB_LOCK, connect() as con:
        row = con.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or row["role"] == "admin":
            raise ValueError("Yönetici hesabı buradan değiştirilemez")
        con.execute("UPDATE users SET active=? WHERE id=?", (1 if active else 0, user_id))


def admin_delete_user(user_id: int) -> None:
    with DB_LOCK, connect() as con:
        row = con.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or row["role"] == "admin":
            raise ValueError("Yönetici hesabı silinemez")
        con.execute("DELETE FROM users WHERE id=?", (user_id,))


def admin_reset_credential(user_id: int, credential: str) -> None:
    if len(credential) < 8:
        raise ValueError("Yeni key/şifre en az 8 karakter olmalı")
    salt, digest = hash_credential(credential)
    with DB_LOCK, connect() as con:
        row = con.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or row["role"] == "admin":
            raise ValueError("Yönetici parolası ayrı bölümden değiştirilir")
        con.execute("UPDATE users SET credential_salt=?, credential_hash=? WHERE id=?", (salt, digest, user_id))


def admin_change_password(user_id: int, current: str, new: str) -> None:
    if len(new) < 12:
        raise ValueError("Yeni yönetici parolası en az 12 karakter olmalı")
    with DB_LOCK, connect() as con:
        row = con.execute("SELECT * FROM users WHERE id=? AND role='admin'", (user_id,)).fetchone()
        if not row or not verify_credential(current, row["credential_salt"], row["credential_hash"]):
            raise ValueError("Mevcut yönetici parolası doğru değil")
        salt, digest = hash_credential(new)
        con.execute("UPDATE users SET credential_salt=?, credential_hash=? WHERE id=?", (salt, digest, user_id))
        con.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))



# ACCESS_HUB_ADMIN_TOOLS_V2 — server-side status and constrained terminal helpers.
# No shell string is ever executed. Browser-provided text selects only one fixed command.
MANAGED_SERVICES = ("access-hub.service", "access-hub-tunnel.service", "ollama.service")

def _command(argv: list[str], timeout: int = 8) -> str:
    try:
        completed = subprocess.run(
            argv, shell=False, check=False, capture_output=True, text=True,
            timeout=timeout, env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        output = (completed.stdout or completed.stderr or "Komut çıktı üretmedi.").strip()
        return output[:14_000]
    except Exception as error:
        return f"Komut çalıştırılamadı: {type(error).__name__}"

def _service_state(name: str) -> str:
    value = _command(["systemctl", "is-active", name], timeout=4).strip().splitlines()
    return value[0] if value else "unknown"

def _model_inventory() -> list[dict[str, object]]:
    try:
        with urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as response:
            data = json.load(response)
        return [
            {"name": str(row.get("name", "<bilinmiyor>")), "size": int(row.get("size", 0) or 0)}
            for row in data.get("models", [])
        ]
    except Exception:
        return []

def _memory() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, raw = line.split(":", 1)
            values[key] = int(raw.strip().split()[0]) * 1024
    except Exception:
        pass
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    return {"total": total, "used": max(0, total - available), "available": available}

def _uptime_seconds() -> int:
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        return 0

def system_overview() -> dict[str, object]:
    disk = shutil.disk_usage("/")
    services = {name.removesuffix(".service"): _service_state(name) for name in MANAGED_SERVICES}
    with DB_LOCK, connect() as con:
        active_users = int(con.execute("SELECT COUNT(DISTINCT user_id) FROM sessions WHERE expires_at>?", (now(),)).fetchone()[0])
        users = int(con.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0])
    models = _model_inventory()
    issues: list[str] = []
    for name, state in services.items():
        if state != "active":
            issues.append(f"{name} servisi {state} durumda")
    if disk.total and disk.used / disk.total >= 0.85:
        issues.append("Disk kullanımı %85 üzerinde")
    if not models:
        issues.append("Ollama model listesi alınamadı")
    return {
        "services": services,
        "cpu_count": os.cpu_count() or 0,
        "load": [round(x, 2) for x in os.getloadavg()],
        "uptime_seconds": _uptime_seconds(),
        "disk": {"total": disk.total, "used": disk.used, "free": disk.free},
        "memory": _memory(),
        "active_users": active_users,
        "active_accounts": users,
        "models": models,
        "issues": issues,
    }

def safe_terminal_action(action: str) -> dict[str, str]:
    # Each action maps to a hard-coded argv list. There is intentionally no arbitrary shell input.
    labels = {
        "uptime": "Sunucu çalışma süresi", "disk": "Disk kullanımı", "memory": "Bellek kullanımı",
        "models": "Yüklü Ollama modelleri", "services": "Yönetilen servisler", "logs": "Access Hub log özeti",
        "status": "Sistem özeti",
    }
    if action == "status":
        return {"label": labels[action], "output": json.dumps(system_overview(), ensure_ascii=False, indent=2)}
    if action == "models":
        rows = _model_inventory()
        text = "\n".join(f"{row['name']}\t{row['size'] / 1024**3:.2f} GB" for row in rows) or "Model bilgisi alınamadı."
        return {"label": labels[action], "output": text}
    fixed = {
        "uptime": ["uptime"],
        "disk": ["df", "-h", "/"],
        "memory": ["free", "-h"],
        "services": ["systemctl", "is-active", *MANAGED_SERVICES],
        # Application logs contain route/status diagnostics only; request bodies, cookies and credentials are never logged.
        "logs": ["journalctl", "-u", "access-hub.service", "-n", "60", "--no-pager", "-o", "short-iso"],
    }
    if action not in fixed:
        raise ValueError("Bu terminal komutuna izin verilmedi")
    return {"label": labels[action], "output": _command(fixed[action])}


# ACCESS_HUB_MAVIORKIDE_TERMINAL_V3
# This is a deliberately virtual, workspace-only terminal. It does not invoke a shell,
# subprocess, package manager, network client, interpreter, Docker or system command.
# Every path is resolved under MAVIORKIDE_ROOT, so `cd ..` cannot escape the workspace.
MAVI_MAX_OUTPUT = 100_000

def _mavi_cwd(raw: object) -> Path:
    value = str(raw or ".").strip()
    if value in {"", ".", "/", "/maviorkide"}:
        candidate = MAVIORKIDE_ROOT
    else:
        candidate = (MAVIORKIDE_ROOT / value.lstrip("/")).resolve(strict=False)
    if candidate != MAVIORKIDE_ROOT and MAVIORKIDE_ROOT not in candidate.parents:
        raise ValueError("Maviorkide klasörü dışına çıkılamaz")
    if not candidate.exists() or not candidate.is_dir():
        raise ValueError("Geçerli bir çalışma klasörü değil")
    return candidate

def _mavi_path(raw: str, cwd: Path, *, allow_missing: bool = True) -> Path:
    raw = raw.strip()
    if not raw or raw == ".":
        candidate = cwd
    else:
        # Absolute-looking paths are virtual paths under /maviorkide, never host paths.
        if raw.startswith("/"):
            raw = raw.removeprefix("/maviorkide").lstrip("/")
            candidate = MAVIORKIDE_ROOT
        else:
            candidate = cwd
        # Clamp every .. at Maviorkide root rather than ever resolving above it.
        for component in Path(raw).parts:
            if component in {"", "."}:
                continue
            if component == "..":
                candidate = candidate.parent if candidate != MAVIORKIDE_ROOT else MAVIORKIDE_ROOT
            else:
                candidate = candidate / component
        candidate = candidate.resolve(strict=False)
    if candidate != MAVIORKIDE_ROOT and MAVIORKIDE_ROOT not in candidate.parents:
        raise ValueError("Maviorkide klasörü dışına çıkılamaz")
    if not allow_missing and not candidate.exists():
        raise ValueError("Dosya veya klasör bulunamadı")
    return candidate

def _mavi_relative(path: Path) -> str:
    relative = path.relative_to(MAVIORKIDE_ROOT)
    return "." if str(relative) == "." else str(relative)

def _mavi_read(path: Path, limit: int = MAVI_MAX_OUTPUT) -> str:
    if path.is_dir():
        raise ValueError("Bu bir klasör; ls kullanın")
    if path.is_symlink():
        raise ValueError("Sembolik bağlantılar Maviorkide terminalinde okunamaz")
    if path.stat().st_size > limit:
        raise ValueError("Dosya güvenli görüntüleme sınırını aşıyor")
    return path.read_text(encoding="utf-8", errors="replace")

def _mavi_listing(path: Path, detailed: bool = False, include_hidden: bool = False) -> str:
    if not path.is_dir():
        return _mavi_relative(path)
    rows = []
    for item in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        if not include_hidden and item.name.startswith("."):
            continue
        name = item.name + ("/" if item.is_dir() else "")
        if detailed:
            size = "-" if item.is_dir() else str(item.stat().st_size)
            rows.append(f"{size:>10}  {name}")
        else:
            rows.append(name)
    return "\n".join(rows) or "(boş)"

def _mavi_walk(path: Path) -> str:
    rows = []
    for item in sorted(path.rglob("*"), key=lambda p: str(p).lower()):
        if any(part.startswith(".") for part in item.relative_to(path).parts):
            continue
        # resolve guards against a symlink traversal outside workspace.
        try:
            resolved = item.resolve(strict=False)
            if resolved != MAVIORKIDE_ROOT and MAVIORKIDE_ROOT not in resolved.parents:
                continue
        except OSError:
            continue
        rows.append(_mavi_relative(item) + ("/" if item.is_dir() else ""))
        if len(rows) >= 500:
            rows.append("… çıktı 500 kayıtla sınırlandı")
            break
    return "\n".join(rows) or "(boş)"

def maviorkide_terminal(command: str, cwd_value: object) -> dict[str, str]:
    MAVIORKIDE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    cwd = _mavi_cwd(cwd_value)
    command = str(command or "").strip()
    if len(command) > 300:
        raise ValueError("Komut çok uzun")
    if not command:
        return {"cwd": _mavi_relative(cwd), "output": ""}
    if any(mark in command for mark in (";", "&&", "||", "|", "`", "$", ">", "<")):
        raise ValueError("Shell zincirleri, yönlendirmeler ve değişkenler Maviorkide terminalinde kapalı")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError as error:
        raise ValueError("Komut söz dizimi geçersiz") from error
    if not parts:
        return {"cwd": _mavi_relative(cwd), "output": ""}
    cmd, args = parts[0].lower(), parts[1:]
    output = ""
    if cmd == "help":
        output = "İzinli komutlar:\nhelp, pwd, ls, cd, mkdir, touch, cat, head, tail, write, append, cp, mv, rm, find, grep, wc, echo, date, whoami, clear\n\nBu terminal yalnız /maviorkide çalışma alanına erişir. sudo, ssh, docker, systemctl, package manager, shell, interpreter, ağ ve host komutları kapalıdır."
    elif cmd == "pwd":
        output = "/maviorkide" + ("" if _mavi_relative(cwd) == "." else "/" + _mavi_relative(cwd))
    elif cmd == "cd":
        target = _mavi_path(args[0] if args else ".", cwd, allow_missing=False)
        if not target.is_dir():
            raise ValueError("cd hedefi bir klasör olmalı")
        cwd = target
    elif cmd == "ls":
        detailed = "-l" in args
        hidden = "-a" in args
        paths = [a for a in args if not a.startswith("-")]
        target = _mavi_path(paths[0], cwd, allow_missing=False) if paths else cwd
        output = _mavi_listing(target, detailed, hidden)
    elif cmd == "mkdir":
        parents = "-p" in args
        names = [a for a in args if a != "-p"]
        if not names:
            raise ValueError("mkdir için klasör adı gerekli")
        for name in names:
            target = _mavi_path(name, cwd)
            if target == MAVIORKIDE_ROOT:
                raise ValueError("Kök klasör değiştirilemez")
            target.mkdir(parents=parents, exist_ok=parents)
    elif cmd == "touch":
        if not args:
            raise ValueError("touch için dosya adı gerekli")
        for name in args:
            target = _mavi_path(name, cwd)
            if target == MAVIORKIDE_ROOT:
                raise ValueError("Kök klasör değiştirilemez")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.touch(exist_ok=True)
    elif cmd in {"cat", "head", "tail", "wc"}:
        if not args:
            raise ValueError(f"{cmd} için dosya adı gerekli")
        lines = None
        names = list(args)
        if cmd in {"head", "tail"} and len(names) >= 2 and names[0] == "-n":
            lines = max(1, min(1000, int(names[1])))
            names = names[2:]
        if len(names) != 1:
            raise ValueError("Yalnız bir dosya belirtin")
        text = _mavi_read(_mavi_path(names[0], cwd, allow_missing=False))
        if cmd == "head": output = "\n".join(text.splitlines()[: lines or 10])
        elif cmd == "tail": output = "\n".join(text.splitlines()[-(lines or 10):])
        elif cmd == "wc": output = f"{len(text.splitlines())} satır  {len(text.split())} kelime  {len(text.encode('utf-8'))} byte"
        else: output = text
    elif cmd in {"write", "append"}:
        if len(args) < 2:
            raise ValueError(f"{cmd} için dosya adı ve metin gerekli")
        target = _mavi_path(args[0], cwd)
        if target == MAVIORKIDE_ROOT:
            raise ValueError("Kök klasöre yazılamaz")
        target.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if cmd == "append" else "w"
        with target.open(mode, encoding="utf-8") as handle:
            handle.write(" ".join(args[1:]) + ("\n" if cmd == "append" else ""))
    elif cmd in {"cp", "mv"}:
        if len(args) != 2:
            raise ValueError(f"{cmd} için kaynak ve hedef gerekli")
        src = _mavi_path(args[0], cwd, allow_missing=False)
        dst = _mavi_path(args[1], cwd)
        if src == MAVIORKIDE_ROOT or dst == MAVIORKIDE_ROOT:
            raise ValueError("Kök klasör taşınamaz veya kopyalanamaz")
        if src.is_dir():
            if cmd == "cp":
                shutil.copytree(src, dst, dirs_exist_ok=False)
            else:
                shutil.move(str(src), str(dst))
        elif cmd == "cp":
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
    elif cmd == "rm":
        recursive = "-r" in args or "-rf" in args or "-fr" in args
        names = [a for a in args if not a.startswith("-")]
        if not names:
            raise ValueError("rm için hedef gerekli")
        for name in names:
            target = _mavi_path(name, cwd, allow_missing=False)
            if target == MAVIORKIDE_ROOT:
                raise ValueError("Maviorkide kök klasörü silinemez")
            if target.is_dir():
                if not recursive:
                    raise ValueError("Klasör silmek için rm -r kullanın")
                shutil.rmtree(target)
            else:
                target.unlink()
    elif cmd == "find":
        target = _mavi_path(args[0], cwd, allow_missing=False) if args else cwd
        output = _mavi_walk(target)
    elif cmd == "grep":
        if len(args) != 2:
            raise ValueError("grep için aranan metin ve dosya gerekli")
        needle, filename = args
        text = _mavi_read(_mavi_path(filename, cwd, allow_missing=False))
        output = "\n".join(f"{i}: {line}" for i, line in enumerate(text.splitlines(), 1) if needle.lower() in line.lower()) or "Eşleşme bulunamadı"
    elif cmd == "echo":
        output = " ".join(args)
    elif cmd == "date":
        output = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    elif cmd == "whoami":
        output = "maviorkide-user"
    elif cmd == "clear":
        output = "__CLEAR__"
    else:
        raise ValueError("Bu komuta Maviorkide güvenli terminalinde izin verilmedi. help yazın.")
    return {"cwd": _mavi_relative(cwd), "output": output[:MAVI_MAX_OUTPUT]}


# ACCESS_HUB_REPO_LAB_V4
# Commands below run only inside the dedicated `maviorkide-repo-lab` container created by
# the installer. The container has no Docker socket, no host mount except MAVIORKIDE_ROOT,
# no Linux capabilities, a read-only root filesystem, memory/CPU/PID limits, and a non-root UID.
# Network is intentionally enabled only because the owner selected GitHub clone + package downloads.

def _mavi_workspace_size() -> int:
    total = 0
    try:
        for item in MAVIORKIDE_ROOT.rglob("*"):
            try:
                if item.is_file() and not item.is_symlink():
                    total += item.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    return total

def _mavi_lab_container_state() -> dict[str, object]:
    output = _command(["docker", "inspect", "--format", "{{.State.Running}}", MAVI_LAB_CONTAINER], timeout=6).strip()
    return {"running": output == "true", "workspace_bytes": _mavi_workspace_size(), "workspace_limit": MAVI_LAB_WORKSPACE_LIMIT}

def mavi_repo_lab_status() -> dict[str, object]:
    status = _mavi_lab_container_state()
    status["tools"] = {"git": "hazır", "python": "hazır", "node": "hazır", "npm": "hazır"} if status["running"] else {}
    return status

def mavi_repo_lab_command(command: str, cwd_value: object) -> dict[str, object]:
    MAVIORKIDE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    cwd = _mavi_cwd(cwd_value)
    command = str(command or "").strip()
    if not command:
        return {"cwd": _mavi_relative(cwd), "output": "", "exit_code": 0}
    if len(command) > 4000 or "\x00" in command:
        raise ValueError("Komut geçersiz veya çok uzun")
    # Persist only a plain `cd` command in the browser terminal state. _mavi_path clamps .. at root.
    try:
        pieces = shlex.split(command, posix=True)
    except ValueError as error:
        raise ValueError("Komut söz dizimi geçersiz") from error
    if pieces and pieces[0] == "cd" and len(pieces) <= 2:
        target = _mavi_path(pieces[1] if len(pieces) == 2 else ".", cwd, allow_missing=False)
        if not target.is_dir():
            raise ValueError("cd hedefi bir klasör olmalı")
        return {"cwd": _mavi_relative(target), "output": "", "exit_code": 0}
    state = _mavi_lab_container_state()
    if not state["running"]:
        raise ValueError("Maviorkide Repo Laboratuvarı çalışmıyor")
    if int(state["workspace_bytes"]) >= MAVI_LAB_WORKSPACE_LIMIT:
        raise ValueError("Maviorkide çalışma alanı 10 GB güvenlik sınırına ulaştı")
    relative = _mavi_relative(cwd)
    workdir = "/workspace" if relative == "." else "/workspace/" + relative
    # Command text stays opaque to the host. It is passed as one argument to bash inside the sandbox.
    wrapper = (
        "set -o pipefail; ulimit -t 85; ulimit -n 1024; "
        "mkdir -p /tmp/mavi-home /tmp/mavi-cache; "
        "timeout --signal=TERM 85s /bin/bash --noprofile --norc -c " + shlex.quote(command)
    )
    argv = [
        "docker", "exec", "--user", f"{os.getuid()}:{os.getgid()}", "--workdir", workdir,
        "--env", "HOME=/tmp/mavi-home", "--env", "XDG_CACHE_HOME=/tmp/mavi-cache",
        "--env", "PIP_CACHE_DIR=/tmp/mavi-cache/pip", "--env", "npm_config_cache=/tmp/mavi-cache/npm",
        MAVI_LAB_CONTAINER, "/bin/bash", "--noprofile", "--norc", "-c", wrapper,
    ]
    with MAVI_LAB_LOCK:
        try:
            result = subprocess.run(argv, shell=False, check=False, capture_output=True, text=True, timeout=MAVI_LAB_TIMEOUT + 8)
            output = ((result.stdout or "") + ("\n" if result.stdout and result.stderr else "") + (result.stderr or "")).strip()
            if result.returncode == 124:
                output = (output + "\n\n[Komut 85 saniye sınırında durduruldu]").strip()
            return {"cwd": relative, "output": output[:MAVI_MAX_OUTPUT] or "[çıktı yok]", "exit_code": result.returncode}
        except subprocess.TimeoutExpired:
            return {"cwd": relative, "output": "[Komut güvenlik zaman sınırında durduruldu]", "exit_code": 124}

def json_for_script(value: object) -> str:
    return json.dumps(value, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def page(title: str, body: str, state: dict[str, object] | None = None) -> bytes:
    state_tag = f"<script>window.__STATE__={json_for_script(state or {})};</script>" if state is not None else ""
    return f"""<!doctype html><html lang=\"tr\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{html.escape(title)}</title>{COMMON_STYLE}</head><body>{state_tag}{body}</body></html>""".encode("utf-8")


COMMON_STYLE = r"""
<style>
:root{--accent:#7c5cff;--tone:#f7f7fb;--surface:18;--bg:#0b0c10;--panel:rgba(255,255,255,.07);--line:rgba(255,255,255,.13);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--tone)}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 8%,color-mix(in srgb,var(--accent) 24%,transparent),transparent 30%),#0b0c10;color:var(--tone);min-height:100vh}button,input,textarea,select{font:inherit}button{cursor:pointer}.hidden{display:none!important}.shell{max-width:1240px;margin:auto;padding:24px}.topbar{display:flex;justify-content:space-between;align-items:center;gap:16px}.brand{font-size:17px;font-weight:850;letter-spacing:.18em;color:var(--tone)}.tag{font-size:12px;color:color-mix(in srgb,var(--tone) 60%,transparent);letter-spacing:.08em;text-transform:uppercase}.btn{border:1px solid var(--line);background:rgba(255,255,255,.04);color:var(--tone);border-radius:12px;padding:11px 15px;font-weight:700;transition:.2s}.btn:hover{border-color:var(--accent);transform:translateY(-1px)}.btn.primary{background:var(--accent);border-color:var(--accent);color:white}.btn.danger{color:#ffb4bd;border-color:rgba(255,100,120,.35)}.main-grid{display:grid;grid-template-columns:minmax(290px,.78fr) minmax(440px,1.6fr);gap:28px;align-items:center;min-height:calc(100vh - 212px);padding:42px 0}.panel{background:rgba(255,255,255,calc(var(--surface)/100));border:1px solid var(--line);box-shadow:0 24px 65px rgba(0,0,0,.25);border-radius:24px;padding:26px;backdrop-filter:blur(14px)}.login-panel{grid-column:1}.hero{grid-column:2;padding:30px}.eyebrow{color:var(--accent);font-weight:800;font-size:13px;letter-spacing:.12em;text-transform:uppercase}.hero h1{font-size:clamp(35px,5vw,72px);line-height:1.04;letter-spacing:-.055em;margin:14px 0 18px;max-width:800px}.hero p{font-size:18px;line-height:1.65;color:color-mix(in srgb,var(--tone) 72%,transparent);max-width:730px}.section-title{margin:0 0 5px;font-size:22px}.muted{color:color-mix(in srgb,var(--tone) 64%,transparent);line-height:1.55}.field{display:grid;gap:7px;margin:15px 0}.field label{font-size:13px;font-weight:750;color:color-mix(in srgb,var(--tone) 76%,transparent)}.field input,.field textarea,.field select{background:rgba(0,0,0,.24);border:1px solid var(--line);outline:none;color:var(--tone);border-radius:11px;padding:12px}.field input:focus,.field textarea:focus,.field select:focus{border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 21%,transparent)}.field textarea{resize:vertical;min-height:84px}.wide{width:100%}.notice{font-size:13px;min-height:19px;margin-top:10px;color:#ffcc86}.contact{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;padding-bottom:25px}.contact-item{border:1px solid var(--line);border-radius:16px;padding:15px;background:rgba(255,255,255,.035);min-height:84px}.contact-item span{display:block;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:color-mix(in srgb,var(--tone) 55%,transparent);margin-bottom:6px}.contact-item b{font-size:14px;overflow-wrap:anywhere}.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.72);display:grid;place-items:center;padding:18px;z-index:10}.modal{width:min(570px,100%);max-height:90vh;overflow:auto}.modal-head{display:flex;justify-content:space-between;align-items:center}.icon-btn{border:0;background:transparent;color:var(--tone);font-size:24px}.choice-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin:20px 0}.choice{min-height:104px;text-align:left}.choice strong,.choice small{display:block}.choice small{color:color-mix(in srgb,var(--tone) 62%,transparent);margin-top:6px}.choice.admin{border-color:color-mix(in srgb,var(--accent) 75%,white)}
/* Admin */.admin-shell{display:grid;grid-template-columns:244px 1fr;min-height:100vh}.sidebar{border-right:1px solid var(--line);padding:28px 18px;background:rgba(0,0,0,.2)}.sidebar nav{display:grid;gap:8px;margin-top:32px}.nav-btn{text-align:left;border:0;border-radius:10px;padding:11px;background:transparent;color:color-mix(in srgb,var(--tone) 74%,transparent);font-weight:700}.nav-btn.active,.nav-btn:hover{color:var(--tone);background:rgba(255,255,255,.07)}.admin-main{padding:32px;max-width:1200px;width:100%;margin:auto}.admin-header{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}.view{display:none}.view.active{display:block}.settings-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.setting-card{padding:22px}.user-layout{display:grid;grid-template-columns:minmax(300px,.8fr) 1.3fr;gap:18px}.role-row{display:flex;gap:8px}.role-row label{flex:1;border:1px solid var(--line);border-radius:10px;padding:10px;cursor:pointer;font-size:14px}.role-row input{accent-color:var(--accent)}.table-wrap{overflow:auto}.users-table{border-collapse:collapse;width:100%;font-size:14px}.users-table th,.users-table td{padding:12px 9px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}.pill{font-size:11px;border:1px solid var(--line);border-radius:99px;padding:4px 7px}.actions{display:flex;gap:6px}.actions .btn{padding:7px 9px;font-size:12px}.value{font-size:28px;font-weight:850}.private{min-height:100vh;display:grid;place-items:center;padding:22px}.private .panel{max-width:560px;text-align:center}.private h1{font-size:42px;margin-bottom:8px}@media(max-width:780px){.shell{padding:17px}.main-grid{display:flex;flex-direction:column;min-height:auto;padding:46px 0 30px}.hero{order:1;text-align:center;padding:14px 5px}.login-panel{order:2;width:min(470px,100%)}.hero h1{font-size:43px}.contact{grid-template-columns:1fr;text-align:center}.topbar{align-items:flex-start}.admin-shell{display:block}.sidebar{border-right:0;border-bottom:1px solid var(--line);padding:17px}.sidebar nav{display:flex;overflow:auto;margin-top:14px}.nav-btn{white-space:nowrap}.admin-main{padding:18px}.settings-grid,.user-layout{grid-template-columns:1fr}.admin-header{align-items:flex-start;flex-direction:column}.choice-grid{grid-template-columns:1fr}.table-wrap{margin:0 -10px}.modal{padding:20px}.panel{border-radius:18px}}

/* ACCESS_HUB_ADMIN_TOOLS_V2 */
.admin-shell{display:block}.admin-main{padding:32px;max-width:1200px;margin:auto}.admin-menu-toggle{position:fixed;top:18px;left:18px;z-index:31;width:48px;height:48px;border-radius:13px;border:1px solid var(--line);background:rgba(13,14,20,.92);color:var(--tone);font-size:25px}.drawer-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.54);opacity:0;pointer-events:none;z-index:29;transition:.2s}.drawer-backdrop.open{opacity:1;pointer-events:auto}.drawer-backdrop .sidebar{position:absolute;left:0;top:0;bottom:0;width:min(310px,87vw);border-right:1px solid var(--line);padding:84px 18px 24px;background:#101117;transform:translateX(-104%);transition:transform .24s ease;box-shadow:20px 0 50px rgba(0,0,0,.34);overflow:auto}.drawer-backdrop.open .sidebar{transform:translateX(0)}.drawer-close{position:absolute;right:12px;top:14px}.server-summary{margin-top:18px}.status-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:14px}.status-cell{border:1px solid var(--line);border-radius:13px;padding:13px;background:rgba(255,255,255,.025)}.status-cell span{display:block;font-size:11px;color:color-mix(in srgb,var(--tone) 60%,transparent);text-transform:uppercase;letter-spacing:.08em}.status-cell b{display:block;margin-top:7px;font-size:17px;overflow-wrap:anywhere}.tool-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin:18px 0}.terminal{background:#080a0f;border:1px solid color-mix(in srgb,var(--accent) 35%,var(--line));border-radius:14px;padding:16px;min-height:290px;max-height:490px;overflow:auto;color:#b9f8cd;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.terminal::before{content:'ubuntu@access-hub:~$ ';color:var(--accent)}.normal-menu-toggle{position:fixed;top:18px;left:18px;z-index:20;width:46px;height:46px;border-radius:13px;border:1px solid var(--line);background:rgba(13,14,20,.92);color:var(--tone);font-size:24px}.normal-drawer{position:fixed;z-index:19;left:0;top:0;bottom:0;width:min(290px,86vw);padding:82px 18px 22px;background:#101117;border-right:1px solid var(--line);transform:translateX(-104%);transition:.24s;box-shadow:18px 0 45px rgba(0,0,0,.35)}.normal-drawer.open{transform:translateX(0)}@media(max-width:780px){.admin-main{padding:82px 18px 22px}.status-grid,.tool-grid{grid-template-columns:repeat(2,1fr)}.admin-menu-toggle{top:12px;left:12px}.admin-header{padding-left:55px}.normal-menu-toggle{top:12px;left:12px}} 


/* ACCESS_HUB_MAVIORKIDE_TERMINAL_V3 */
.mavi-terminal{background:#070a10;border:1px solid color-mix(in srgb,#51c5ff 38%,var(--line));border-radius:14px;padding:16px;min-height:350px;max-height:570px;overflow:auto;color:#d2edff;font:13px/1.58 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.mavi-terminal .prompt{color:#6ec9ff}.mavi-command{display:flex;gap:9px;margin-top:12px}.mavi-command input{flex:1;background:#0b1018;border:1px solid var(--line);border-radius:11px;color:var(--tone);padding:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.mavi-note{border-left:3px solid #51c5ff;padding:10px 13px;background:rgba(81,197,255,.08);border-radius:0 10px 10px 0;font-size:13px;line-height:1.5}


/* ACCESS_HUB_REPO_LAB_V4 */
.lab-terminal{background:#071009;border:1px solid color-mix(in srgb,#72e59d 38%,var(--line));border-radius:14px;padding:16px;min-height:360px;max-height:590px;overflow:auto;color:#cef7db;font:13px/1.58 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.lab-terminal .prompt{color:#72e59d}.lab-command{display:flex;gap:9px;margin-top:12px}.lab-command input{flex:1;background:#0b1510;border:1px solid var(--line);border-radius:11px;color:var(--tone);padding:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.lab-status{font-size:13px;color:color-mix(in srgb,var(--tone) 68%,transparent);margin:12px 0}


/* ACCESS_HUB_TERMINAL_UI_V5 — visual rhythm + direct terminal composition */
.admin-main{max-width:1320px;padding:92px clamp(18px,3.2vw,48px) 44px}.admin-header{margin-bottom:30px;padding:0 0 20px;border-bottom:1px solid var(--line)}.admin-header h1{font-size:clamp(27px,4vw,39px);letter-spacing:-.04em}.panel{box-shadow:0 18px 52px rgba(0,0,0,.18)}.setting-card{padding:clamp(18px,2.4vw,26px)}.settings-grid{grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:14px}.user-layout{grid-template-columns:minmax(280px,.74fr) 1.26fr;gap:16px}.status-grid{grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px}.drawer-backdrop .sidebar{background:linear-gradient(180deg,#11151c 0%,#0c0f15 100%);padding:82px 14px 28px}.sidebar .brand{padding:0 7px}.sidebar .tag{padding:0 7px}.sidebar nav{gap:4px}.nav-btn{padding:12px 13px;border:1px solid transparent;transition:background .16s,border-color .16s,color .16s}.nav-btn.active,.nav-btn:hover{border-color:rgba(255,255,255,.07);background:rgba(255,255,255,.075)}.admin-menu-toggle{box-shadow:0 8px 28px rgba(0,0,0,.25)}.mavi-console{--term-accent:#9fffc2;--term-dim:#7fb891;--term-border:rgba(159,255,194,.2);--term-bg:#0a1010;position:relative;isolation:isolate;min-height:min(70vh,680px);display:flex;flex-direction:column;overflow:hidden;border:1px solid var(--term-border);border-radius:18px;background:radial-gradient(circle at 80% 0%,rgba(64,184,112,.13),transparent 34%),var(--term-bg);box-shadow:0 22px 70px rgba(0,0,0,.34);font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}.mavi-console::after{content:"";position:absolute;inset:0;z-index:-1;opacity:.22;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px);background-size:100% 4px}.mavi-bar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 14px;border-bottom:1px solid var(--term-border);background:rgba(0,0,0,.27);font-size:11px;letter-spacing:.08em;color:var(--term-dim);text-transform:uppercase}.mavi-brandline{display:flex;align-items:center;gap:8px;color:var(--term-accent);font-weight:800}.mavi-lights{display:flex;gap:5px}.mavi-lights i{display:block;width:8px;height:8px;border-radius:99px;background:#416556}.mavi-lights i:first-child{background:#9fffc2}.mavi-banner{margin:0;padding:19px 18px 13px;border-bottom:1px dashed rgba(159,255,194,.15);color:var(--term-accent);font-size:clamp(10px,1.65vw,13px);line-height:1.25;white-space:pre;overflow:auto;text-shadow:0 0 18px rgba(159,255,194,.15)}.mavi-screen{flex:1;min-height:230px;overflow:auto;padding:15px 18px 24px;color:#e3f5e7;white-space:pre-wrap;overflow-wrap:anywhere;scrollbar-color:rgba(159,255,194,.34) transparent}.mavi-screen .prompt{color:var(--term-accent);font-weight:700}.mavi-screen .muted-output{color:#9db4a4}.mavi-screen .error-output{color:#ffb4aa}.mavi-composer{display:flex;align-items:flex-end;gap:8px;margin:0;padding:12px 13px;border-top:1px solid var(--term-border);background:rgba(1,7,5,.76)}.mavi-composer .prompt{padding:10px 0;color:var(--term-accent);white-space:nowrap;font-weight:700}.mavi-composer textarea{resize:none;display:block;min-width:0;flex:1;max-height:110px;overflow:auto;padding:9px 4px;border:0;outline:0;background:transparent;color:#effff2;caret-color:var(--term-accent);font:inherit;line-height:1.55}.mavi-composer textarea::placeholder{color:rgba(213,241,220,.43)}.mavi-send{display:grid;place-items:center;flex:0 0 38px;width:38px;height:38px;border:1px solid rgba(159,255,194,.34);border-radius:11px;background:rgba(159,255,194,.1);color:var(--term-accent)}.mavi-send:hover{background:rgba(159,255,194,.2)}.mavi-hint{padding:0 15px 11px;background:rgba(1,7,5,.76);color:rgba(213,241,220,.54);font-size:11px}.mavi-console:focus-within{border-color:rgba(159,255,194,.48);box-shadow:0 0 0 3px rgba(159,255,194,.08),0 22px 70px rgba(0,0,0,.34)}.repo-console{--term-accent:#a9d2ff;--term-dim:#8aaacb;--term-border:rgba(126,181,255,.22);--term-bg:#090d14}.repo-console .mavi-lights i:first-child{background:#a9d2ff}.repo-console .mavi-banner{color:#a9d2ff;text-shadow:0 0 18px rgba(126,181,255,.14)}.repo-console .mavi-screen{color:#e4edf9}.repo-console .mavi-screen .prompt,.repo-console .mavi-composer .prompt,.repo-console .mavi-brandline,.repo-console .mavi-send{color:#a9d2ff}.repo-console .mavi-send{border-color:rgba(126,181,255,.34);background:rgba(126,181,255,.11)}.repo-console .mavi-send:hover{background:rgba(126,181,255,.21)}.repo-console .mavi-composer textarea{color:#f0f6ff;caret-color:#a9d2ff}.terminal-intro{margin:0 0 15px;color:color-mix(in srgb,var(--tone) 69%,transparent);font-size:13px;line-height:1.55}.terminal-intro strong{color:var(--tone)}@media(max-width:780px){.admin-main{padding:78px 13px 24px}.admin-header{margin-bottom:18px;padding:0 5px 15px}.user-layout{grid-template-columns:1fr}.mavi-console{min-height:calc(100vh - 172px);border-radius:14px}.mavi-bar{padding:10px 12px}.mavi-banner{padding:15px 13px 11px}.mavi-screen{padding:13px;min-height:200px}.mavi-composer{padding:10px}.mavi-composer .prompt{font-size:12px}.mavi-hint{padding:0 12px 9px}.mavi-note{margin-bottom:13px}}


/* ACCESS_HUB_TERMUX_CONSOLE_V6 — deliberately plain terminal, not a dashboard/code card. */
.termux-terminal{--termux-fg:#f5f6f6;--termux-muted:#b4bab7;--termux-prompt:#a4ffad;--termux-line:#1a2420;min-height:calc(100dvh - 126px);display:flex;flex-direction:column;overflow:hidden;background:#000;color:var(--termux-fg);border:1px solid #202622;border-radius:8px;box-shadow:none;font:16px/1.42 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}.termux-status{min-height:38px;display:flex;justify-content:space-between;align-items:center;gap:12px;padding:8px 13px;border-bottom:1px solid var(--termux-line);background:#050706;color:#dbe5df;font-size:12px;letter-spacing:.025em}.termux-status b{color:var(--termux-prompt);font-weight:700}.termux-welcome{margin:0;padding:18px 16px 8px;overflow:auto;white-space:pre-wrap;color:var(--termux-fg);background:#000;font:inherit;line-height:1.35}.termux-screen{flex:1;min-height:260px;overflow:auto;padding:8px 16px 18px;background:#000;color:var(--termux-fg);white-space:pre-wrap;overflow-wrap:anywhere;scrollbar-color:#4d5d53 #000}.termux-screen .prompt{color:var(--termux-prompt);font-weight:700}.termux-screen .muted-output{color:var(--termux-muted)}.termux-screen .error-output{color:#ffb3aa}.termux-composer{display:flex;align-items:flex-start;gap:8px;padding:10px 13px 12px;border-top:1px solid var(--termux-line);background:#000}.termux-composer .prompt{padding-top:1px;color:var(--termux-prompt);font-weight:700;white-space:nowrap}.termux-composer textarea{display:block;flex:1;min-width:0;max-height:124px;resize:none;overflow:auto;padding:0;border:0;outline:0;background:transparent;color:var(--termux-fg);caret-color:#fff;font:inherit;line-height:1.42}.termux-composer textarea::placeholder{color:#7c847f}.termux-send{width:24px;height:24px;flex:0 0 24px;padding:0;border:0;background:transparent;color:var(--termux-prompt);font:18px/1 ui-monospace,monospace}.termux-send:hover{color:#fff}.termux-hint{padding:0 14px 10px;background:#000;color:#7e8882;font-size:11px;line-height:1.35}.terminal-area:has(.termux-terminal){max-width:100%}.terminal-area:has(.termux-terminal)>.eyebrow,.terminal-area:has(.termux-terminal)>h2,.terminal-area:has(.termux-terminal)>.terminal-intro{display:none}.mavi-focus .admin-header{display:none}.mavi-focus .admin-main{max-width:none;padding:76px 18px 20px}.mavi-focus .view.active{height:calc(100dvh - 96px)}.mavi-focus .terminal-area{height:100%}@media(max-width:780px){.mavi-focus .admin-main{padding:68px 0 0}.mavi-focus .view.active{height:calc(100dvh - 68px)}.termux-terminal{min-height:100%;height:100%;border-left:0;border-right:0;border-bottom:0;border-radius:0;font-size:15px}.termux-status{padding:8px 12px}.termux-welcome{padding:15px 12px 8px}.termux-screen{padding:8px 12px 16px}.termux-composer{padding:10px 12px}.termux-hint{padding:0 12px 10px}.mavi-focus .admin-menu-toggle{top:10px;left:10px}}

</style>
"""

PUBLIC_BODY = r"""
<main class="shell">
 <header class="topbar"><div><div class="brand" id="brandText">MERKEZ</div><div class="tag">Güvenli erişim</div></div><button class="btn" id="specialOpen">Özel Giriş</button></header>
 <section class="main-grid"><section class="panel login-panel"><div class="eyebrow">Standart erişim</div><h2 class="section-title">Giriş yap</h2><p class="muted">Size verilen kullanıcı adı ve key ile devam edin.</p><form id="standardForm"><div class="field"><label>Kullanıcı adı</label><input name="username" autocomplete="username" required maxlength="48"></div><div class="field"><label>Key</label><input name="key" type="password" autocomplete="current-password" required></div><button class="btn primary wide">Güvenli giriş</button><div class="notice" id="standardNotice"></div></form></section>
 <section class="hero"><div class="eyebrow">Kontrollü alan</div><h1 id="homeHeading"></h1><p id="homeSubtitle"></p></section></section>
 <section class="contact" id="contact"></section></main>
 <div class="modal-backdrop hidden" id="specialModal"><section class="panel modal"><div class="modal-head"><div><div class="eyebrow">Özel erişim</div><h2 class="section-title">Hesabınızı seçin</h2></div><button class="icon-btn" id="specialClose" aria-label="Kapat">×</button></div><div class="choice-grid" id="specialChoices"></div><form class="hidden" id="specialPasswordForm"><p class="muted" id="chosenUser"></p><div class="field"><label>Şifre</label><input id="specialPassword" type="password" autocomplete="current-password" required></div><button class="btn primary wide">Devam et</button><button type="button" class="btn wide" id="chooseOther" style="margin-top:8px">Başka hesap seç</button><div class="notice" id="specialNotice"></div></form></section></div>
<script>
const state=window.__STATE__, q=s=>document.querySelector(s); let selected=null;
function safe(v){return String(v||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]))}
function theme(s){document.documentElement.style.setProperty('--accent',s.accent_color);document.documentElement.style.setProperty('--tone',s.text_tone);document.documentElement.style.setProperty('--surface',s.surface_brightness);q('#brandText').textContent=s.brand_text;q('#homeHeading').textContent=s.home_heading;q('#homeSubtitle').textContent=s.home_subtitle;const items=[['Telefon',s.contact_phone],['E-posta',s.contact_email],['WhatsApp',s.contact_whatsapp],['Instagram',s.contact_instagram],['Adres',s.contact_address]];q('#contact').innerHTML=items.filter(x=>x[1]).map(x=>`<article class="contact-item"><span>${safe(x[0])}</span><b>${safe(x[1])}</b></article>`).join('')}
theme(state.settings);
async function api(path,body,method='POST'){const r=await fetch(path,{method,headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||'İşlem gerçekleştirilemedi');return d}
q('#standardForm').onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);const n=q('#standardNotice');n.textContent='';try{const d=await api('/api/login/standard',{username:f.get('username'),key:f.get('key')});location.href=d.redirect}catch(err){n.textContent=err.message}};
function openSpecial(){selected=null;q('#specialPasswordForm').classList.add('hidden');q('#specialChoices').classList.remove('hidden');q('#specialModal').classList.remove('hidden');loadChoices()};
async function loadChoices(){const box=q('#specialChoices');box.innerHTML='<p class="muted">Hesaplar hazırlanıyor…</p>';try{const d=await fetch('/api/special-users').then(r=>r.json());const cards=[{id:'admin',display_name:'Yönetici',admin:true},...d.users];box.innerHTML=cards.map(u=>`<button class="btn choice ${u.admin?'admin':''}" data-id="${safe(u.id)}" data-name="${safe(u.display_name)}"><strong>${safe(u.display_name)}</strong><small>${u.admin?'Yönetim paneli':'Özel kullanıcı erişimi'}</small></button>`).join('')||'<p class="muted">Henüz özel kullanıcı oluşturulmadı.</p>';box.querySelectorAll('[data-id]').forEach(b=>b.onclick=()=>selectUser(b.dataset.id,b.dataset.name))}catch(e){box.innerHTML='<p class="notice">Liste yüklenemedi.</p>'}}
function selectUser(id,name){selected={id,name};q('#chosenUser').textContent=name+' için şifrenizi girin.';q('#specialChoices').classList.add('hidden');q('#specialPasswordForm').classList.remove('hidden');q('#specialPassword').focus()}
q('#specialOpen').onclick=openSpecial;q('#specialClose').onclick=()=>q('#specialModal').classList.add('hidden');q('#chooseOther').onclick=()=>{q('#specialPasswordForm').classList.add('hidden');q('#specialChoices').classList.remove('hidden');q('#specialNotice').textContent=''};q('#specialPasswordForm').onsubmit=async e=>{e.preventDefault();const n=q('#specialNotice');n.textContent='';try{const d=await api('/api/login/special',{user_id:selected.id,password:q('#specialPassword').value});location.href=d.redirect}catch(err){n.textContent=err.message}};
</script>
"""

PRIVATE_BODY = r"""
<button class="normal-menu-toggle" id="normalMenuToggle" aria-label="Menüyü aç">☰</button><aside class="normal-drawer" id="normalDrawer"><button class="icon-btn drawer-close" id="normalMenuClose" aria-label="Menüyü kapat">×</button><div class="brand">ÖZEL ALAN</div><div class="tag">Kullanıcı menüsü</div><nav style="display:grid;gap:9px;margin-top:28px"><button class="nav-btn active">Ana alan</button><button class="nav-btn" disabled>Araçlar · yakında</button><button class="nav-btn" id="logout">Çıkış yap</button></nav></aside><main class="private"><section class="panel"><div class="eyebrow">Erişim doğrulandı</div><h1>Hoş geldiniz.</h1><p class="muted">Özel alanınız etkin. Kullanıcı araçları buraya rolünüze göre eklenecektir.</p></section></main><script>const d=document.querySelector('#normalDrawer');document.querySelector('#normalMenuToggle').onclick=()=>d.classList.add('open');document.querySelector('#normalMenuClose').onclick=()=>d.classList.remove('open');document.querySelector('#logout').onclick=async()=>{await fetch('/api/logout',{method:'POST'});location.href='/'};</script>
"""

ADMIN_BODY = r"""
<div class="admin-shell"><button class="admin-menu-toggle" id="menuToggle" aria-label="Menüyü aç">☰</button><div class="drawer-backdrop" id="adminDrawer"><aside class="sidebar"><button class="icon-btn drawer-close" id="menuClose" aria-label="Menüyü kapat">×</button><div class="brand" id="adminBrand">MERKEZ</div><div class="tag">Yönetim paneli</div><nav><button class="nav-btn active" data-view="overview">Genel bakış</button><button class="nav-btn" data-view="texts">Yazılar & görünüm</button><button class="nav-btn" data-view="contacts">İletişim</button><button class="nav-btn" data-view="users">Kullanıcılar</button><button class="nav-btn" data-view="tools">Araçlar</button><button class="nav-btn" data-view="lab">Maviorkide Terminal</button><button class="nav-btn" data-view="workspace">Maviorkide Dosyalar</button><button class="nav-btn" data-view="security">Yönetici parolası</button><button class="nav-btn" id="logout">Çıkış</button></nav></aside></div><main class="admin-main"><header class="admin-header"><div><div class="eyebrow">Yönetici</div><h1 style="margin:5px 0" id="viewTitle">Genel bakış</h1></div><a class="btn" href="/" target="_blank">Ana sayfayı aç</a></header>
<section class="view active" id="view-overview"><div class="settings-grid"><article class="panel setting-card"><div class="tag">Aktif standart kullanıcı</div><div class="value" id="standardCount">0</div></article><article class="panel setting-card"><div class="tag">Aktif özel kullanıcı</div><div class="value" id="specialCount">0</div></article><article class="panel setting-card"><div class="tag">Ana sayfa</div><p class="muted">Başlıklar, renkler ve iletişim bilgileri bu panelden anlık değiştirilebilir.</p></article><article class="panel setting-card"><div class="tag">Gizlilik</div><p class="muted">Standart kullanıcı listesi ve oturum bilgileri ana sayfada gösterilmez.</p></article></div><article class="panel setting-card server-summary" id="serverSummary"><div class="eyebrow">Canlı sunucu özeti</div><h2 class="section-title">Sunucu durumu yükleniyor…</h2><p class="muted">Access Hub, Ollama, kaynaklar, aktif kullanıcılar ve sorunlar kontrol ediliyor.</p></article></section>
<section class="view" id="view-texts"><form class="settings-grid" id="textForm"><article class="panel setting-card"><h2 class="section-title">Yazılar</h2><div class="field"><label>Sol üst marka yazısı</label><input name="brand_text" maxlength="90"></div><div class="field"><label>Ana başlık</label><textarea name="home_heading" maxlength="500"></textarea></div><div class="field"><label>Açıklama</label><textarea name="home_subtitle" maxlength="1800"></textarea></div></article><article class="panel setting-card"><h2 class="section-title">Renk & ton</h2><div class="field"><label>Vurgu rengi</label><input name="accent_color" type="color"></div><div class="field"><label>Yazı tonu</label><input name="text_tone" type="color"></div><div class="field"><label>Panel parlaklığı</label><input name="surface_brightness" type="range" min="5" max="40"><small id="brightnessValue" class="muted"></small></div><button class="btn primary">Değişiklikleri kaydet</button><div class="notice" id="textNotice"></div></article></form></section>
<section class="view" id="view-contacts"><form class="panel setting-card" id="contactForm"><h2 class="section-title">İletişim bilgileri</h2><p class="muted">Boş bıraktığınız alan ana sayfada görünmez.</p><div class="settings-grid"><div><div class="field"><label>Telefon</label><input name="contact_phone"></div><div class="field"><label>E-posta</label><input name="contact_email" type="email"></div><div class="field"><label>WhatsApp</label><input name="contact_whatsapp"></div></div><div><div class="field"><label>Instagram / sosyal medya</label><input name="contact_instagram"></div><div class="field"><label>Adres / açıklama</label><textarea name="contact_address"></textarea></div></div></div><button class="btn primary">İletişim bilgilerini kaydet</button><div class="notice" id="contactNotice"></div></form></section>
<section class="view" id="view-users"><div class="user-layout"><form class="panel setting-card" id="userForm"><div class="eyebrow">Yeni kullanıcı</div><h2 class="section-title">Kullanıcı oluştur</h2><div class="role-row"><label><input type="radio" name="role" value="standard" checked> Standart kullanıcı</label><label><input type="radio" name="role" value="special"> Özel kullanıcı</label></div><div class="field"><label>Görünen ad</label><input name="display_name" required maxlength="70"></div><div class="field"><label>Kullanıcı adı</label><input name="username" required maxlength="48" pattern="[A-Za-z0-9._-]{3,48}"></div><div class="field"><label id="credentialLabel">Key</label><input name="credential" required minlength="8" type="password"></div><button class="btn primary wide">Kullanıcıyı oluştur</button><div class="notice" id="userNotice"></div></form><section class="panel setting-card"><h2 class="section-title">Kullanıcılar</h2><div class="table-wrap"><table class="users-table"><thead><tr><th>Ad</th><th>Tür</th><th>Durum</th><th>İşlem</th></tr></thead><tbody id="usersTable"></tbody></table></div></section></div></section>
<section class="view" id="view-tools"><section class="panel setting-card"><div class="eyebrow">Admin araçları</div><h2 class="section-title">Sunucu Araçları</h2><p class="muted">Bu ekran yalnız yöneticiye açıktır. Güvenlik nedeniyle rastgele shell komutu değil, izinli tanı komutları çalıştırılır. Tam Ubuntu terminali için SSH kullanılır.</p><div class="tool-grid"><button class="btn" data-terminal="status">Sistem özeti</button><button class="btn" data-terminal="uptime">Çalışma süresi</button><button class="btn" data-terminal="disk">Disk</button><button class="btn" data-terminal="memory">Bellek</button><button class="btn" data-terminal="models">Modeller</button><button class="btn" data-terminal="services">Servisler</button><button class="btn" data-terminal="logs">Access Hub logları</button></div><pre class="terminal" id="terminalOutput">Bir araç seçin. Komutlar yönetici için izinli ve kayıtlı tanı komutlarıyla sınırlıdır.</pre></section></section>
<section class="view" id="view-lab"><section class="terminal-area"><section class="termux-terminal" id="labConsole" aria-label="Maviorkide terminali"><header class="termux-status"><span><b>maviorkide</b> · repo lab</span><span id="labStatus">durum denetleniyor</span></header><pre class="termux-welcome">Welcome to Maviorkide!

Workspace:  /workspace
Runtime:    Git · Python · Node · npm
Isolation:  Repo Lab container

Python projects normally keep their packages in .venv.
Use lowercase python or python3.  Type commands below.</pre><div class="termux-screen" id="labOutput" aria-live="polite"></div><form class="termux-composer" id="labForm"><span class="prompt">mavi@lab:~$</span><textarea id="labCommand" rows="1" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="4000" placeholder="" aria-label="Terminal komutu"></textarea><button class="termux-send" type="submit" aria-label="Komutu çalıştır">↵</button></form><div class="termux-hint">Enter çalıştırır · Shift + Enter yeni satır · ↑ ↓ komut geçmişi · Komut sınırı 85 saniye</div></section></section></section>
<section class="view" id="view-workspace"><section class="terminal-area"><div class="eyebrow">Yerel ve sınırlı dosya alanı</div><h2 class="section-title">Maviorkide Dosya Terminali</h2><p class="terminal-intro">Komutu doğrudan aşağıdaki satıra yazın. Bu alan yalnız <strong>/maviorkide</strong> içindeki dosyalar içindir; <code>cd ..</code> kökte kalır ve Ubuntu, Docker, ağ ya da servis komutlarına erişmez.</p><section class="mavi-console" id="maviConsole" aria-label="Maviorkide güvenli dosya terminali"><header class="mavi-bar"><span class="mavi-brandline"><span class="mavi-lights"><i></i><i></i><i></i></span>maviorkide · safe files</span><span>/maviorkide</span></header><pre class="mavi-banner" aria-hidden="true">╭──────────────────────────────────╮
│          M A V I O R K I D E       │
│        safe workspace terminal     │
╰──────────────────────────────────╯</pre><div class="mavi-screen" id="maviOutput" aria-live="polite"><span class="muted-output">Maviorkide hazır. Bir komut yazın veya yardım için help yazın.</span></div><form class="mavi-composer" id="maviForm"><span class="prompt">mavi@files:~$</span><textarea id="maviCommand" rows="1" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="300" placeholder="Komutu buraya yazın…" aria-label="Maviorkide komutu"></textarea><button class="mavi-send" type="submit" aria-label="Komutu çalıştır">↵</button></form><div class="mavi-hint">Enter çalıştırır · Terminale dokunun ve doğrudan yazın</div></section></section></section>
<section class="view" id="view-security"><form class="panel setting-card" id="passwordForm" style="max-width:620px"><div class="eyebrow">Güvenlik</div><h2 class="section-title">Yönetici parolasını değiştir</h2><div class="field"><label>Mevcut parola</label><input name="current" type="password" required></div><div class="field"><label>Yeni parola</label><input name="new" type="password" minlength="12" required></div><button class="btn primary">Parolayı değiştir</button><div class="notice" id="passwordNotice"></div></form></section>
</main></div>
<script>
let state=window.__STATE__;const q=s=>document.querySelector(s);const titles={overview:'Genel bakış',texts:'Yazılar & görünüm',contacts:'İletişim',users:'Kullanıcılar',tools:'Araçlar',lab:'Maviorkide Terminal',workspace:'Maviorkide Dosyalar',security:'Yönetici parolası'};function safe(v){return String(v||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]))}async function api(path,body,method='POST'){const r=await fetch(path,{method,headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||'İşlem gerçekleştirilemedi');return d}function notice(s,t,ok=false){q(s).textContent=t;q(s).style.color=ok?'#9df6bf':'#ffcc86'}
function fill(){const s=state.settings;q('#adminBrand').textContent=s.brand_text;q('#textForm').querySelectorAll('[name]').forEach(e=>e.value=s[e.name]||'');q('#contactForm').querySelectorAll('[name]').forEach(e=>e.value=s[e.name]||'');q('#brightnessValue').textContent=s.surface_brightness+' / 40';const active=state.users.filter(u=>u.active);q('#standardCount').textContent=active.filter(u=>u.role==='standard').length;q('#specialCount').textContent=active.filter(u=>u.role==='special').length;renderUsers()}
function renderUsers(){q('#usersTable').innerHTML=state.users.map(u=>`<tr><td><b>${safe(u.display_name)}</b><br><small class="muted">${safe(u.username)}</small></td><td><span class="pill">${u.role==='admin'?'Yönetici':u.role==='special'?'Özel':'Standart'}</span></td><td>${u.active?'Aktif':'Pasif'}</td><td>${u.role==='admin'?'<span class="muted">Korunan</span>':`<div class="actions"><button class="btn" data-toggle="${u.id}">${u.active?'Pasifleştir':'Etkinleştir'}</button><button class="btn" data-reset="${u.id}">Key/şifre</button><button class="btn danger" data-delete="${u.id}">Sil</button></div>`}</td></tr>`).join('');q('#usersTable').querySelectorAll('[data-toggle]').forEach(b=>b.onclick=()=>changeActive(b.dataset.toggle));q('#usersTable').querySelectorAll('[data-delete]').forEach(b=>b.onclick=()=>deleteUser(b.dataset.delete));q('#usersTable').querySelectorAll('[data-reset]').forEach(b=>b.onclick=()=>resetCredential(b.dataset.reset))}
async function reload(){state=await fetch('/api/admin/state').then(r=>r.json());fill()}async function changeActive(id){const u=state.users.find(x=>x.id==id);await api('/api/admin/users/'+id+'/active',{active:!u.active});reload()}async function deleteUser(id){if(confirm('Bu kullanıcı silinsin mi?')){await api('/api/admin/users/'+id,null,'DELETE');reload()}}async function resetCredential(id){const v=prompt('Yeni key/şifre (en az 8 karakter):');if(v) {await api('/api/admin/users/'+id+'/credential',{credential:v});alert('Bilgi güncellendi.');}}

async function loadServerStatus(){try{const d=await fetch('/api/admin/system/status').then(r=>{if(!r.ok)throw new Error();return r.json()});const gb=n=>`${(Number(n||0)/1024**3).toFixed(1)} GB`;const diskPct=d.disk.total?Math.round(d.disk.used/d.disk.total*100):0;const issue=d.issues.length?d.issues.join(' · '):'Sorun algılanmadı';q('#serverSummary').innerHTML=`<div class="eyebrow">Canlı sunucu özeti</div><h2 class="section-title">${d.issues.length?'Dikkat gerektiren durum var':'Sistem normal çalışıyor'}</h2><div class="status-grid"><div class="status-cell"><span>Aktif kullanıcı</span><b>${d.active_users}</b></div><div class="status-cell"><span>Aktif hesap</span><b>${d.active_accounts}</b></div><div class="status-cell"><span>Disk</span><b>%${diskPct} · ${gb(d.disk.free)} boş</b></div><div class="status-cell"><span>Bellek</span><b>${gb(d.memory.used)} / ${gb(d.memory.total)}</b></div><div class="status-cell"><span>Ollama modelleri</span><b>${d.models.length}</b></div><div class="status-cell"><span>Access Hub</span><b>${d.services['access-hub']||'bilinmiyor'}</b></div><div class="status-cell"><span>Tunnel</span><b>${d.services['access-hub-tunnel']||'bilinmiyor'}</b></div><div class="status-cell"><span>Ollama</span><b>${d.services.ollama||'bilinmiyor'}</b></div></div><p class="muted" style="margin:16px 0 0">${safe(issue)}</p>`}catch(e){q('#serverSummary').innerHTML='<div class="notice">Sunucu durumu alınamadı.</div>'}}
async function runSafeTerminal(action){const out=q('#terminalOutput');out.textContent='Çalıştırılıyor…';try{const d=await api('/api/admin/terminal',{action});out.textContent=`${d.label}\n\n${d.output}`}catch(e){out.textContent='Hata: '+e.message}}

let maviCwd='.';
const escText=value=>String(value??'').replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));
function terminalPrompt(kind,cwd){return `<span class="prompt">mavi@${kind}:${escText(cwd==='.'?'~':cwd)}$</span>`}
function terminalWrite(target,html){const out=q(target);out.innerHTML+=html;out.scrollTop=out.scrollHeight}
function growTerminalInput(input){input.style.height='auto';input.style.height=Math.min(input.scrollHeight,110)+'px'}
function focusMavi(){requestAnimationFrame(()=>q('#maviCommand')?.focus())}
async function runMavi(command){const out=q('#maviOutput');const before=maviCwd;terminalWrite('#maviOutput',`<div>${terminalPrompt('files',before)} ${escText(command)}</div>`);try{const d=await api('/api/admin/maviorkide-terminal',{command,cwd:maviCwd});maviCwd=d.cwd||'.';if(d.output==='__CLEAR__'){out.innerHTML='<span class="muted-output">Ekran temizlendi.</span>';return}if(d.output)terminalWrite('#maviOutput',`<div>${escText(d.output)}</div>`)}catch(e){terminalWrite('#maviOutput',`<div class="error-output">Hata: ${escText(e.message)}</div>`)}finally{out.scrollTop=out.scrollHeight;focusMavi()}}

let labCwd='.';
async function loadLabStatus(){try{const d=await fetch('/api/admin/maviorkide/lab-status').then(r=>{if(!r.ok)throw new Error();return r.json()});const gb=n=>(Number(n||0)/1024**3).toFixed(2);q('#labStatus').textContent=`${d.running?'online':'kapalı'} · ${gb(d.workspace_bytes)} / ${gb(d.workspace_limit)} GB` }catch(e){q('#labStatus').textContent='durum alınamadı'}}
function focusLab(){requestAnimationFrame(()=>q('#labCommand')?.focus())}
async function runLab(command){const before=labCwd;terminalWrite('#labOutput',`<div>${terminalPrompt('lab',before)} ${escText(command)}</div>`);try{const d=await api('/api/admin/maviorkide/lab-command',{command,cwd:labCwd});labCwd=d.cwd||'.';if(d.output)terminalWrite('#labOutput',`<div>${escText(d.output)}</div>`);terminalWrite('#labOutput',`<div class="muted-output">[çıkış kodu: ${escText(d.exit_code)}]</div>`);loadLabStatus()}catch(e){terminalWrite('#labOutput',`<div class="error-output">Hata: ${escText(e.message)}</div>`)}finally{q('#labOutput').scrollTop=q('#labOutput').scrollHeight;focusLab()}}
q('#textForm').onsubmit=async e=>{e.preventDefault();try{const values=Object.fromEntries(new FormData(e.target));await api('/api/admin/settings',values);await reload();notice('#textNotice','Kaydedildi.',true)}catch(x){notice('#textNotice',x.message)}};q('#contactForm').onsubmit=async e=>{e.preventDefault();try{await api('/api/admin/settings',Object.fromEntries(new FormData(e.target)));await reload();notice('#contactNotice','Kaydedildi.',true)}catch(x){notice('#contactNotice',x.message)}};q('#userForm').onsubmit=async e=>{e.preventDefault();try{await api('/api/admin/users',Object.fromEntries(new FormData(e.target)));e.target.reset();await reload();notice('#userNotice','Kullanıcı oluşturuldu.',true)}catch(x){notice('#userNotice',x.message)}};q('#userForm').role.forEach(x=>x.onchange=()=>q('#credentialLabel').textContent=q('input[name=role]:checked').value==='standard'?'Key':'Şifre');q('[name=surface_brightness]').oninput=e=>q('#brightnessValue').textContent=e.target.value+' / 40';q('#passwordForm').onsubmit=async e=>{e.preventDefault();try{await api('/api/admin/change-password',Object.fromEntries(new FormData(e.target)));notice('#passwordNotice','Parola değişti. Güvenlik için tekrar giriş yapın.',true);setTimeout(()=>location.href='/',900)}catch(x){notice('#passwordNotice',x.message)}};document.querySelectorAll('.nav-btn[data-view]').forEach(b=>b.onclick=()=>{document.querySelectorAll('.nav-btn[data-view]').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));q('#view-'+b.dataset.view).classList.add('active');q('#viewTitle').textContent=titles[b.dataset.view]});q('#logout').onclick=async()=>{await fetch('/api/logout',{method:'POST'});location.href='/'};q('#menuToggle').onclick=()=>q('#adminDrawer').classList.add('open');q('#menuClose').onclick=()=>q('#adminDrawer').classList.remove('open');q('#adminDrawer').onclick=e=>{if(e.target===q('#adminDrawer'))q('#adminDrawer').classList.remove('open')};document.querySelectorAll('[data-terminal]').forEach(b=>b.onclick=()=>runSafeTerminal(b.dataset.terminal));document.querySelectorAll('[data-mavi]').forEach(b=>b.onclick=()=>runMavi(b.dataset.mavi));q('#maviForm').onsubmit=e=>{e.preventDefault();const input=q('#maviCommand');const command=input.value.trim();if(command){input.value='';growTerminalInput(input);runMavi(command)}};q('#maviCommand').oninput=e=>growTerminalInput(e.target);q('#maviCommand').onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();q('#maviForm').requestSubmit()}};q('#maviConsole').onclick=e=>{if(!e.target.closest('textarea,button'))focusMavi()};q('#labForm').onsubmit=e=>{e.preventDefault();const input=q('#labCommand');const command=input.value.trim();if(command){input.value='';growTerminalInput(input);runLab(command)}};const labHistory=[];let labHistoryIndex=-1;q('#labCommand').oninput=e=>growTerminalInput(e.target);q('#labCommand').onkeydown=e=>{const input=e.currentTarget;if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();q('#labForm').requestSubmit()}else if(e.key==='ArrowUp'&&!input.value.includes('\n')){e.preventDefault();if(labHistory.length){labHistoryIndex=Math.min(labHistoryIndex+1,labHistory.length-1);input.value=labHistory[labHistory.length-1-labHistoryIndex];growTerminalInput(input)}}else if(e.key==='ArrowDown'&&!input.value.includes('\n')){e.preventDefault();if(labHistoryIndex>=0){labHistoryIndex--;input.value=labHistoryIndex<0?'':labHistory[labHistory.length-1-labHistoryIndex];growTerminalInput(input)}}};const ui6LabSubmit=q('#labForm').onsubmit;q('#labForm').onsubmit=e=>{const value=q('#labCommand').value.trim();if(value&&labHistory.at(-1)!==value){labHistory.push(value);if(labHistory.length>60)labHistory.shift()}labHistoryIndex=-1;ui6LabSubmit(e)};q('#labConsole').onclick=e=>{if(!e.target.closest('textarea,button'))focusLab()};

document.querySelectorAll('.nav-btn[data-view]').forEach(button=>button.addEventListener('click',()=>document.body.classList.toggle('mavi-focus',button.dataset.view==='lab')));
const ui5OriginalViewClick=document.querySelectorAll('.nav-btn[data-view]');
ui5OriginalViewClick.forEach(button=>button.addEventListener('click',()=>{if(button.dataset.view==='workspace')focusMavi();if(button.dataset.view==='lab'&&typeof focusLab==='function')focusLab()}));
fill();loadServerStatus();loadLabStatus();setInterval(loadServerStatus,30000);setInterval(loadLabStatus,30000);
</script>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "AccessHub/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        # Do not log request bodies, credentials, cookies, or user names.
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {self.client_address[0]} {self.command} {self.path} {args[1] if len(args)>1 else ''}", flush=True)

    def send_bytes(self, status: int, data: bytes, content_type: str = "text/html; charset=utf-8", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, status: int, payload: dict[str, object], headers: dict[str, str] | None = None) -> None:
        self.send_bytes(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", headers)

    def redirect(self, url: str) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", url)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def token(self) -> str | None:
        jar = SimpleCookie(self.headers.get("Cookie"))
        morsel = jar.get("access_hub")
        return morsel.value if morsel else None

    def user(self) -> dict[str, object] | None:
        return session_user(self.token())

    def require_user(self, admin: bool = False) -> dict[str, object] | None:
        user = self.user()
        if not user or (admin and user["role"] != "admin"):
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Oturum geçersiz veya yetkiniz yok"})
            return None
        return user

    def body_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 100_000:
            raise ValueError("Geçersiz istek")
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Geçersiz veri")
        return data

    def session_header(self, token: str) -> dict[str, str]:
        return {"Set-Cookie": f"access_hub={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECONDS}"}

    def clear_session_header(self) -> dict[str, str]:
        return {"Set-Cookie": "access_hub=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"}

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self.send_json(HTTPStatus.OK, {"status": "ok"})
        elif path == "/":
            self.send_bytes(HTTPStatus.OK, page(get_settings()["brand_text"], PUBLIC_BODY, {"settings": get_settings()}))
        elif path == "/private":
            user = self.user()
            if not user:
                self.redirect("/")
            elif user["role"] == "admin":
                self.redirect("/admin")
            else:
                self.send_bytes(HTTPStatus.OK, page("Özel Alan", PRIVATE_BODY, {"user": user}))
        elif path == "/admin":
            user = self.user()
            if not user or user["role"] != "admin":
                self.redirect("/")
            else:
                self.send_bytes(HTTPStatus.OK, page("Yönetim Paneli", ADMIN_BODY, {"settings": get_settings(), "users": admin_users()}))
        elif path == "/api/special-users":
            self.send_json(HTTPStatus.OK, {"users": public_special_users()})
        elif path == "/api/admin/state":
            if self.require_user(admin=True):
                self.send_json(HTTPStatus.OK, {"settings": get_settings(), "users": admin_users()})
        elif path == "/api/admin/system/status":
            if self.require_user(admin=True):
                self.send_json(HTTPStatus.OK, system_overview())
        elif path == "/api/admin/maviorkide/lab-status":
            if self.require_user(admin=True):
                self.send_json(HTTPStatus.OK, mavi_repo_lab_status())
        else:
            self.send_bytes(HTTPStatus.NOT_FOUND, b"Bulunamadi", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/api/login/standard":
                data = self.body_json()
                user = authenticate_standard(str(data.get("username", "")), str(data.get("key", "")))
                if not user:
                    self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Kullanıcı adı veya key doğru değil"})
                    return
                self.send_json(HTTPStatus.OK, {"redirect": "/private"}, self.session_header(create_session(int(user["id"]))))
            elif path == "/api/login/special":
                data = self.body_json()
                if str(data.get("user_id")) == "admin":
                    user = authenticate_admin(str(data.get("password", "")))
                    redirect = "/admin"
                else:
                    user = authenticate_special(data.get("user_id"), str(data.get("password", "")))
                    redirect = "/private"
                if not user:
                    self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Şifre doğru değil veya hesap erişime kapalı"})
                    return
                self.send_json(HTTPStatus.OK, {"redirect": redirect}, self.session_header(create_session(int(user["id"]))))
            elif path == "/api/logout":
                delete_session(self.token())
                self.send_json(HTTPStatus.OK, {"ok": True}, self.clear_session_header())
            elif path == "/api/admin/terminal":
                if not self.require_user(admin=True): return
                data = self.body_json()
                self.send_json(HTTPStatus.OK, safe_terminal_action(str(data.get("action", ""))))
            elif path == "/api/admin/maviorkide-terminal":
                if not self.require_user(admin=True): return
                data = self.body_json()
                self.send_json(HTTPStatus.OK, maviorkide_terminal(str(data.get("command", "")), data.get("cwd", ".")))
            elif path == "/api/admin/maviorkide/lab-command":
                if not self.require_user(admin=True): return
                data = self.body_json()
                self.send_json(HTTPStatus.OK, mavi_repo_lab_command(str(data.get("command", "")), data.get("cwd", ".")))
            elif path == "/api/admin/settings":
                if not self.require_user(admin=True): return
                set_settings(self.body_json())
                self.send_json(HTTPStatus.OK, {"ok": True})
            elif path == "/api/admin/users":
                if not self.require_user(admin=True): return
                self.send_json(HTTPStatus.CREATED, {"user": admin_create_user(self.body_json())})
            elif path == "/api/admin/change-password":
                user = self.require_user(admin=True)
                if not user: return
                data = self.body_json()
                admin_change_password(int(user["id"]), str(data.get("current", "")), str(data.get("new", "")))
                delete_session(self.token())
                self.send_json(HTTPStatus.OK, {"ok": True}, self.clear_session_header())
            elif path.startswith("/api/admin/users/") and path.endswith("/active"):
                if not self.require_user(admin=True): return
                user_id = int(path.split("/")[4])
                data = self.body_json()
                admin_set_user_active(user_id, bool(data.get("active")))
                self.send_json(HTTPStatus.OK, {"ok": True})
            elif path.startswith("/api/admin/users/") and path.endswith("/credential"):
                if not self.require_user(admin=True): return
                user_id = int(path.split("/")[4])
                data = self.body_json()
                admin_reset_credential(user_id, str(data.get("credential", "")))
                self.send_json(HTTPStatus.OK, {"ok": True})
            else:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint bulunamadı"})
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "Geçersiz veri"})
        except Exception as exc:  # avoid leaking implementation details to clients
            print(f"Application error: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Sunucu işlemi tamamlayamadı"})

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        try:
            if path.startswith("/api/admin/users/"):
                if not self.require_user(admin=True): return
                user_id = int(path.split("/")[4])
                admin_delete_user(user_id)
                self.send_json(HTTPStatus.OK, {"ok": True})
            else:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint bulunamadı"})
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            print(f"Application error: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Sunucu işlemi tamamlayamadı"})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true", help="only initialize data store then exit")
    args = parser.parse_args()
    created = init_db()
    if args.init:
        print("INITIAL_ADMIN_CREATED=" + ("YES" if created else "NO"))
        return
    print(f"Access Hub serving on 127.0.0.1:{PORT}", flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
