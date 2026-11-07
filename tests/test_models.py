import sqlite3
import unittest
from access_hub_next import rbac, models

class ModelPolicyTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:'); self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('CREATE TABLE users(id INTEGER PRIMARY KEY,role TEXT,active INTEGER)')
        self.db.executemany('INSERT INTO users VALUES (?,?,?)', [(1,'admin',1),(2,'standard',1)])
        rbac.migrate(self.db)
        self.role=rbac.create_role(self.db,1,{'key':'agent-role','display_name':'Agent'})
        rbac.set_role_permissions(self.db,1,self.role,['agent.models.use'])
        rbac.link(self.db,1,'user-role',2,self.role,True)
    def tearDown(self): self.db.close()
    def test_grants_inactive_and_default(self):
        data={'tag':'model:1','display_name':'Model One','active':True,'default_model':True,'role_ids':[self.role]}
        models.configure(self.db,1,data,{'model:1'})
        self.assertEqual(models.allowed_models(self.db,2)[0]['tag'],'model:1')
        self.db.execute('UPDATE nova_roles SET active=0 WHERE id=?',(self.role,))
        self.assertEqual(models.allowed_models(self.db,2),[])
        self.db.execute('UPDATE nova_models SET active=0,default_model=0')
        self.assertEqual(models.allowed_models(self.db,1),[])
    def test_reject_uninstalled_and_bad_default(self):
        with self.assertRaises(ValueError): models.configure(self.db,1,{'tag':'x','display_name':'XX','active':True,'default_model':True},set())
        with self.assertRaises(ValueError): models.configure(self.db,1,{'tag':'x','display_name':'XX','active':False,'default_model':True},{'x'})
