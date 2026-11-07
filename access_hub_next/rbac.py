"""SQLite RBAC foundation for the existing Access Hub users table.

This module is not an authorization middleware. HTTP endpoints must explicitly call
has_permission before acting. Migrate only on a backup until integration is tested.
"""
import sqlite3
import time

PERMISSIONS = frozenset({
    'portal.view', 'tools.terminal', 'tools.repo.read', 'tools.repo.write',
    'tools.repo.command', 'agent.chat', 'agent.history', 'agent.models.use',
    'agent.manage', 'system.status', 'system.logs', 'access.users.read',
    'access.users.manage', 'access.roles.read', 'access.roles.manage',
    'access.groups.read', 'access.groups.manage', 'settings.home.manage',
    'settings.security.manage',
})

# Individual statements keep transaction ownership with the caller; executescript
# would implicitly commit and make rollback of a failed migration unreliable.
_SCHEMA = (
    'CREATE TABLE IF NOT EXISTS nova_migrations (version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS nova_permissions (code TEXT PRIMARY KEY)',
    'CREATE TABLE IF NOT EXISTS nova_roles (id INTEGER PRIMARY KEY, role_key TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), system_role INTEGER NOT NULL DEFAULT 0 CHECK(system_role IN (0,1)))',
    'CREATE TABLE IF NOT EXISTS nova_groups (id INTEGER PRIMARY KEY, group_key TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)))',
    'CREATE TABLE IF NOT EXISTS nova_role_permissions (role_id INTEGER NOT NULL REFERENCES nova_roles(id) ON DELETE CASCADE, permission TEXT NOT NULL REFERENCES nova_permissions(code) ON DELETE CASCADE, PRIMARY KEY(role_id, permission))',
    'CREATE TABLE IF NOT EXISTS nova_user_roles (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, role_id INTEGER NOT NULL REFERENCES nova_roles(id) ON DELETE CASCADE, PRIMARY KEY(user_id, role_id))',
    'CREATE TABLE IF NOT EXISTS nova_group_members (group_id INTEGER NOT NULL REFERENCES nova_groups(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(group_id, user_id))',
    'CREATE TABLE IF NOT EXISTS nova_group_roles (group_id INTEGER NOT NULL REFERENCES nova_groups(id) ON DELETE CASCADE, role_id INTEGER NOT NULL REFERENCES nova_roles(id) ON DELETE CASCADE, PRIMARY KEY(group_id, role_id))',
    'CREATE TABLE IF NOT EXISTS nova_profiles (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, avatar_filename TEXT NOT NULL DEFAULT "")',
    'CREATE TABLE IF NOT EXISTS nova_models (tag TEXT PRIMARY KEY, display_name TEXT NOT NULL, description TEXT NOT NULL DEFAULT "", active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0,1)), default_model INTEGER NOT NULL DEFAULT 0 CHECK(default_model IN (0,1)), system_prompt TEXT NOT NULL DEFAULT "")',
    'CREATE UNIQUE INDEX IF NOT EXISTS nova_single_default_model ON nova_models(default_model) WHERE default_model=1',
    'CREATE TABLE IF NOT EXISTS nova_model_roles (model_tag TEXT NOT NULL REFERENCES nova_models(tag) ON DELETE CASCADE, role_id INTEGER NOT NULL REFERENCES nova_roles(id) ON DELETE CASCADE, PRIMARY KEY(model_tag, role_id))',
    'CREATE TABLE IF NOT EXISTS nova_model_groups (model_tag TEXT NOT NULL REFERENCES nova_models(tag) ON DELETE CASCADE, group_id INTEGER NOT NULL REFERENCES nova_groups(id) ON DELETE CASCADE, PRIMARY KEY(model_tag, group_id))',
    'CREATE TABLE IF NOT EXISTS nova_conversations (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, created_at INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS nova_messages (id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL REFERENCES nova_conversations(id) ON DELETE CASCADE, role TEXT NOT NULL CHECK(role IN ("user","assistant")), content TEXT NOT NULL, created_at INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS nova_audit_events (id INTEGER PRIMARY KEY, actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, event_type TEXT NOT NULL, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, detail TEXT NOT NULL DEFAULT "", created_at INTEGER NOT NULL)',
)


def migrate(con: sqlite3.Connection) -> None:
    """Create tables and seed legacy roles once, atomically, without changing users.

    Requires foreign keys enabled. The caller controls commit/rollback. A savepoint
    also makes this safe inside a caller's existing transaction.
    """
    if not con.execute('PRAGMA foreign_keys').fetchone()[0]:
        raise ValueError('SQLite foreign_keys must be enabled')
    con.execute('SAVEPOINT nova_migration')
    try:
        for statement in _SCHEMA:
            con.execute(statement)
        con.executemany('INSERT OR IGNORE INTO nova_permissions(code) VALUES (?)', ((p,) for p in sorted(PERMISSIONS)))
        if not con.execute('SELECT 1 FROM nova_migrations WHERE version=?', ('rbac-v1',)).fetchone():
            con.execute('INSERT INTO nova_roles(role_key,display_name,system_role) VALUES (?,?,1)', ('system-owner', 'Sistem Yöneticisi'))
            con.execute('INSERT INTO nova_roles(role_key,display_name,system_role) VALUES (?,?,1)', ('basic-access', 'Temel Erişim'))
            owner = con.execute('SELECT id FROM nova_roles WHERE role_key=?', ('system-owner',)).fetchone()[0]
            basic = con.execute('SELECT id FROM nova_roles WHERE role_key=?', ('basic-access',)).fetchone()[0]
            con.executemany('INSERT INTO nova_role_permissions VALUES (?,?)', ((owner, p) for p in sorted(PERMISSIONS)))
            con.execute('INSERT INTO nova_role_permissions VALUES (?,?)', (basic, 'portal.view'))
            con.execute('INSERT INTO nova_user_roles SELECT id, CASE WHEN role = ? THEN ? ELSE ? END FROM users', ('admin', owner, basic))
            con.execute('INSERT INTO nova_profiles(user_id) SELECT id FROM users')
            con.execute('INSERT INTO nova_migrations VALUES (?,?)', ('rbac-v1', int(time.time())))
        con.execute('RELEASE SAVEPOINT nova_migration')
    except Exception:
        con.execute('ROLLBACK TO SAVEPOINT nova_migration')
        con.execute('RELEASE SAVEPOINT nova_migration')
        raise


def effective_permissions(con: sqlite3.Connection, user_id: int) -> set[str]:
    """Return active user's permissions from active roles and active groups."""
    rows = con.execute('''
        SELECT rp.permission FROM users u
        JOIN nova_user_roles ur ON ur.user_id=u.id
        JOIN nova_roles r ON r.id=ur.role_id AND r.active=1
        JOIN nova_role_permissions rp ON rp.role_id=r.id
        WHERE u.id=? AND u.active=1
        UNION
        SELECT rp.permission FROM users u
        JOIN nova_group_members gm ON gm.user_id=u.id
        JOIN nova_groups g ON g.id=gm.group_id AND g.active=1
        JOIN nova_group_roles gr ON gr.group_id=g.id
        JOIN nova_roles r ON r.id=gr.role_id AND r.active=1
        JOIN nova_role_permissions rp ON rp.role_id=r.id
        WHERE u.id=? AND u.active=1
    ''', (user_id, user_id))
    return {row[0] for row in rows if row[0] in PERMISSIONS}


def has_permission(con: sqlite3.Connection, user_id: int, permission: str) -> bool:
    return permission in PERMISSIONS and permission in effective_permissions(con, user_id)


def _key(value: object) -> str:
    key = str(value or '').strip().lower()
    if not 3 <= len(key) <= 48 or not all(c.isascii() and (c.isalnum() or c in '._-') for c in key):
        raise ValueError('Anahtar 3–48 karakter olmalı; yalnız harf, rakam, nokta, tire ve alt çizgi kullanılabilir')
    return key


def _name(value: object) -> str:
    name = str(value or '').strip()
    if not 2 <= len(name) <= 70:
        raise ValueError('Görünen ad 2–70 karakter olmalı')
    return name


def _audit(con: sqlite3.Connection, actor: int, action: str, kind: str, subject: int) -> None:
    con.execute('INSERT INTO nova_audit_events(actor_user_id,event_type,subject_type,subject_id,created_at) VALUES (?,?,?,?,?)',
                (actor, action, kind, str(subject), int(time.time())))


def create_role(con: sqlite3.Connection, actor: int, data: dict) -> int:
    key, name = _key(data.get('key')), _name(data.get('display_name'))
    try:
        cur = con.execute('INSERT INTO nova_roles(role_key,display_name) VALUES (?,?)', (key, name))
    except sqlite3.IntegrityError as exc:
        raise ValueError('Rol anahtarı zaten kullanılıyor') from exc
    role_id = int(cur.lastrowid)
    _audit(con, actor, 'role.created', 'role', role_id)
    return role_id


def create_group(con: sqlite3.Connection, actor: int, data: dict) -> int:
    key, name = _key(data.get('key')), _name(data.get('display_name'))
    try:
        cur = con.execute('INSERT INTO nova_groups(group_key,display_name) VALUES (?,?)', (key, name))
    except sqlite3.IntegrityError as exc:
        raise ValueError('Grup anahtarı zaten kullanılıyor') from exc
    group_id = int(cur.lastrowid)
    _audit(con, actor, 'group.created', 'group', group_id)
    return group_id


def set_role_permissions(con: sqlite3.Connection, actor: int, role_id: int, permissions: object) -> None:
    if not isinstance(permissions, list) or any(not isinstance(p, str) or p not in PERMISSIONS for p in permissions):
        raise ValueError('Geçersiz izin listesi')
    row = con.execute('SELECT system_role FROM nova_roles WHERE id=?', (role_id,)).fetchone()
    if row is None or row[0]:
        raise ValueError('Rol bulunamadı veya sistem rolü korunuyor')
    con.execute('DELETE FROM nova_role_permissions WHERE role_id=?', (role_id,))
    con.executemany('INSERT INTO nova_role_permissions VALUES (?,?)', ((role_id, p) for p in sorted(set(permissions))))
    _audit(con, actor, 'role.permissions.updated', 'role', role_id)


def link(con: sqlite3.Connection, actor: int, kind: str, left: int, right: int, enabled: bool) -> None:
    """Add or remove a membership/grant; caller must authorize and commit."""
    specs = {
        'user-role': ('nova_user_roles', 'user_id', 'role_id', 'users', 'nova_roles'),
        'group-member': ('nova_group_members', 'group_id', 'user_id', 'nova_groups', 'users'),
        'group-role': ('nova_group_roles', 'group_id', 'role_id', 'nova_groups', 'nova_roles'),
    }
    if kind not in specs or type(enabled) is not bool:
        raise ValueError('Geçersiz atama')
    table, col_a, col_b, table_a, table_b = specs[kind]
    if not con.execute(f'SELECT 1 FROM {table_a} WHERE id=?', (left,)).fetchone() or not con.execute(f'SELECT 1 FROM {table_b} WHERE id=?', (right,)).fetchone():
        raise ValueError('Atama hedefi bulunamadı')
    # The owner role is never assignable by these generic APIs.
    if kind in {'user-role', 'group-role'} and con.execute('SELECT system_role FROM nova_roles WHERE id=?', (right,)).fetchone()[0]:
        raise ValueError('Sistem rolü bu işlemle atanamaz')
    if enabled:
        con.execute(f'INSERT OR IGNORE INTO {table} ({col_a},{col_b}) VALUES (?,?)', (left, right))
    else:
        con.execute(f'DELETE FROM {table} WHERE {col_a}=? AND {col_b}=?', (left, right))
    _audit(con, actor, kind + ('.added' if enabled else '.removed'), kind, left)


def set_object_active(con: sqlite3.Connection, actor: int, kind: str, object_id: int, active: object) -> None:
    if type(active) is not bool or kind not in {'role', 'group'}:
        raise ValueError('Geçersiz durum')
    table = 'nova_roles' if kind == 'role' else 'nova_groups'
    row = con.execute(f'SELECT * FROM {table} WHERE id=?', (object_id,)).fetchone()
    if row is None:
        raise ValueError('Kayıt bulunamadı')
    if kind == 'role' and con.execute('SELECT system_role FROM nova_roles WHERE id=?', (object_id,)).fetchone()[0]:
        raise ValueError('Sistem rolü korunuyor')
    con.execute(f'UPDATE {table} SET active=? WHERE id=?', (int(active), object_id))
    _audit(con, actor, kind + '.activated' if active else kind + '.deactivated', kind, object_id)


def delete_object(con: sqlite3.Connection, actor: int, kind: str, object_id: int) -> None:
    if kind not in {'role', 'group'}:
        raise ValueError('Geçersiz tür')
    table = 'nova_roles' if kind == 'role' else 'nova_groups'
    row = con.execute(f'SELECT id FROM {table} WHERE id=?', (object_id,)).fetchone()
    if row is None:
        raise ValueError('Kayıt bulunamadı')
    if kind == 'role' and con.execute('SELECT system_role FROM nova_roles WHERE id=?', (object_id,)).fetchone()[0]:
        raise ValueError('Sistem rolü korunuyor')
    con.execute(f'DELETE FROM {table} WHERE id=?', (object_id,))
    _audit(con, actor, kind + '.deleted', kind, object_id)
