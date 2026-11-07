import sqlite3
import unittest
from access_hub_next.rbac import migrate, effective_permissions, has_permission


class RbacTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT NOT NULL, active INTEGER NOT NULL, credential_hash TEXT)')
        self.db.executemany('INSERT INTO users VALUES (?,?,?,?)', [(1, 'admin', 1, 'legacy'), (2, 'standard', 1, 'legacy2'), (3, 'special', 0, 'legacy3')])
        migrate(self.db)

    def tearDown(self):
        self.db.close()

    def test_preserves_legacy_and_least_privilege(self):
        self.assertEqual(self.db.execute('SELECT credential_hash FROM users WHERE id=1').fetchone()[0], 'legacy')
        self.assertTrue(has_permission(self.db, 1, 'access.users.manage'))
        self.assertEqual(effective_permissions(self.db, 2), {'portal.view'})
        self.assertEqual(effective_permissions(self.db, 3), set())
        self.assertFalse(has_permission(self.db, 999, 'portal.view'))
        self.assertFalse(has_permission(self.db, 1, 'unknown'))

    def test_group_and_role_deactivation(self):
        self.db.execute("INSERT INTO nova_roles(role_key,display_name) VALUES ('coder','Coder')")
        self.db.execute("INSERT INTO nova_groups(group_key,display_name) VALUES ('team','Team')")
        role = self.db.execute("SELECT id FROM nova_roles WHERE role_key='coder'").fetchone()[0]
        group = self.db.execute("SELECT id FROM nova_groups WHERE group_key='team'").fetchone()[0]
        self.db.execute('INSERT INTO nova_group_roles VALUES (?,?)', (group, role))
        self.db.execute('INSERT INTO nova_group_members VALUES (?,?)', (group, 2))
        self.db.execute('INSERT INTO nova_role_permissions VALUES (?,?)', (role, 'tools.terminal'))
        self.assertTrue(has_permission(self.db, 2, 'tools.terminal'))
        self.db.execute('UPDATE nova_groups SET active=0 WHERE id=?', (group,))
        self.assertFalse(has_permission(self.db, 2, 'tools.terminal'))
        self.db.execute('UPDATE nova_groups SET active=1 WHERE id=?', (group,))
        self.db.execute('UPDATE nova_roles SET active=0 WHERE id=?', (role,))
        self.assertFalse(has_permission(self.db, 2, 'tools.terminal'))

    def test_migration_does_not_restore_revoked_role(self):
        self.db.execute('DELETE FROM nova_user_roles WHERE user_id=2')
        migrate(self.db)
        self.assertEqual(effective_permissions(self.db, 2), set())

    def test_missing_users_rolls_back(self):
        db = sqlite3.connect(':memory:')
        db.execute('PRAGMA foreign_keys=ON')
        with self.assertRaises(sqlite3.OperationalError):
            migrate(db)
        self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='nova_roles'").fetchone())
        db.close()

    def test_foreign_keys_required(self):
        db = sqlite3.connect(':memory:')
        with self.assertRaises(ValueError): migrate(db)
        db.close()

if __name__ == '__main__': unittest.main()

class ManagementTests(RbacTests):
    def test_management_and_audit(self):
        from access_hub_next.rbac import create_role, create_group, set_role_permissions, link
        role = create_role(self.db, 1, {'key': 'dev-team', 'display_name': 'Developer'})
        group = create_group(self.db, 1, {'key': 'devs', 'display_name': 'Developers'})
        set_role_permissions(self.db, 1, role, ['tools.terminal'])
        link(self.db, 1, 'group-role', group, role, True)
        link(self.db, 1, 'group-member', group, 2, True)
        self.assertTrue(has_permission(self.db, 2, 'tools.terminal'))
        self.assertEqual(self.db.execute('SELECT count(*) FROM nova_audit_events').fetchone()[0], 5)
        with self.assertRaises(ValueError): set_role_permissions(self.db, 1, role, ['made.up'])
        with self.assertRaises(ValueError): link(self.db, 1, 'user-role', 2, 1, True)
        link(self.db, 1, 'group-member', group, 2, False)
        self.assertFalse(has_permission(self.db, 2, 'tools.terminal'))

    def test_role_delete_and_active_state(self):
        from access_hub_next.rbac import create_role, create_group, set_object_active, delete_object
        role = create_role(self.db, 1, {'key': 'viewer', 'display_name': 'Viewer'})
        group = create_group(self.db, 1, {'key': 'group1', 'display_name': 'Group'})
        set_object_active(self.db, 1, 'role', role, False)
        self.assertEqual(self.db.execute('SELECT active FROM nova_roles WHERE id=?', (role,)).fetchone()[0], 0)
        delete_object(self.db, 1, 'group', group)
        self.assertIsNone(self.db.execute('SELECT id FROM nova_groups WHERE id=?', (group,)).fetchone())
        with self.assertRaises(ValueError): delete_object(self.db, 1, 'role', 1)
