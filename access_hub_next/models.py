"""Local model policy. No inference or OpenClaw execution is performed here."""
import sqlite3
from access_hub_next import rbac


def configure(con: sqlite3.Connection, actor_id: int, data: dict, available_tags: set[str]) -> None:
    tag = data.get('tag')
    name = data.get('display_name')
    description = data.get('description', '')
    prompt = data.get('system_prompt', '')
    active, default = data.get('active'), data.get('default_model')
    role_ids, group_ids = data.get('role_ids', []), data.get('group_ids', [])
    if not isinstance(tag, str) or tag not in available_tags:
        raise ValueError('Model mevcut Ollama listesinde bulunamadı')
    if not isinstance(name, str) or not 2 <= len(name.strip()) <= 100:
        raise ValueError('Model görünen adı 2–100 karakter olmalı')
    if not isinstance(description, str) or len(description) > 1000 or not isinstance(prompt, str) or len(prompt) > 4000:
        raise ValueError('Açıklama veya sistem talimatı geçersiz')
    if type(active) is not bool or type(default) is not bool or (default and not active):
        raise ValueError('Varsayılan model etkin olmalı')
    if not isinstance(role_ids, list) or not isinstance(group_ids, list) or any(type(x) is not int or x <= 0 for x in role_ids + group_ids):
        raise ValueError('Geçersiz rol veya grup listesi')
    for table, ids in [('nova_roles', role_ids), ('nova_groups', group_ids)]:
        for obj_id in set(ids):
            if not con.execute(f'SELECT 1 FROM {table} WHERE id=?', (obj_id,)).fetchone():
                raise ValueError('Rol veya grup bulunamadı')
    if default:
        con.execute('UPDATE nova_models SET default_model=0 WHERE default_model=1')
    con.execute('''INSERT INTO nova_models(tag,display_name,description,active,default_model,system_prompt)
       VALUES (?,?,?,?,?,?) ON CONFLICT(tag) DO UPDATE SET display_name=excluded.display_name,
       description=excluded.description,active=excluded.active,default_model=excluded.default_model,system_prompt=excluded.system_prompt''',
        (tag, name.strip(), description, int(active), int(default), prompt))
    con.execute('DELETE FROM nova_model_roles WHERE model_tag=?', (tag,))
    con.execute('DELETE FROM nova_model_groups WHERE model_tag=?', (tag,))
    con.executemany('INSERT INTO nova_model_roles VALUES (?,?)', ((tag, x) for x in set(role_ids)))
    con.executemany('INSERT INTO nova_model_groups VALUES (?,?)', ((tag, x) for x in set(group_ids)))
    rbac._audit(con, actor_id, 'model.policy.updated', 'model', tag)


def allowed_models(con: sqlite3.Connection, user_id: int) -> list[dict]:
    if not rbac.has_permission(con, user_id, 'agent.models.use'):
        return []
    rows = con.execute('''SELECT DISTINCT m.tag,m.display_name,m.description,m.default_model FROM nova_models m
        WHERE m.active=1 AND (
          EXISTS (SELECT 1 FROM nova_user_roles ur JOIN nova_roles r ON r.id=ur.role_id AND r.active=1
                  WHERE ur.user_id=? AND r.role_key='system-owner')
          OR EXISTS (SELECT 1 FROM nova_user_roles ur JOIN nova_roles r ON r.id=ur.role_id AND r.active=1
                     JOIN nova_model_roles mr ON mr.role_id=r.id AND mr.model_tag=m.tag WHERE ur.user_id=?)
          OR EXISTS (SELECT 1 FROM nova_group_members gm JOIN nova_groups g ON g.id=gm.group_id AND g.active=1
                     JOIN nova_model_groups mg ON mg.group_id=g.id AND mg.model_tag=m.tag WHERE gm.user_id=?)
          OR EXISTS (SELECT 1 FROM nova_group_members gm JOIN nova_groups g ON g.id=gm.group_id AND g.active=1
                     JOIN nova_group_roles gr ON gr.group_id=g.id JOIN nova_roles r ON r.id=gr.role_id AND r.active=1
                     JOIN nova_model_roles mr ON mr.role_id=r.id AND mr.model_tag=m.tag WHERE gm.user_id=?)
        ) ORDER BY m.display_name''', (user_id, user_id, user_id, user_id)).fetchall()
    return [dict(zip(('tag','display_name','description','default_model'), row)) for row in rows]
