import sqlite3
import unittest
from access_hub_next import rbac, models, chat

class ChatTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:'); self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('CREATE TABLE users(id INTEGER PRIMARY KEY, role TEXT, active INTEGER)')
        self.db.executemany('INSERT INTO users VALUES (?,?,?)', [(1,'admin',1),(2,'standard',1)])
        rbac.migrate(self.db)
        models.configure(self.db,1,{'tag':'test:1','display_name':'Test','active':True,'default_model':True},{'test:1'})
    def tearDown(self): self.db.close()
    def test_private_conversations(self):
        msgs, system = chat.prepare(self.db,1,'test:1','Hello',None)
        self.assertEqual(msgs[-1]['content'],'Hello')
        conversation = chat.save(self.db,1,'test:1','Hello','World',None)
        self.assertEqual(len(chat.messages_for(self.db,1,conversation)),2)
        with self.assertRaises(ValueError): chat.messages_for(self.db,2,conversation)
        with self.assertRaises(PermissionError): chat.prepare(self.db,2,'test:1','Hello',None)
    def test_recheck_after_model_disabled(self):
        chat.prepare(self.db,1,'test:1','Hello',None)
        self.db.execute('UPDATE nova_models SET active=0,default_model=0')
        with self.assertRaises(PermissionError): chat.save(self.db,1,'test:1','Hello','World',None)
    def test_no_history_permission_does_not_store_messages(self):
        self.db.execute("DELETE FROM nova_role_permissions WHERE permission='agent.history'")
        chat.prepare(self.db,1,'test:1','Hello',None)
        self.assertIsNone(chat.save(self.db,1,'test:1','Hello','World',None))
        self.assertEqual(self.db.execute('SELECT count(*) FROM nova_messages').fetchone()[0],0)
        with self.assertRaises(PermissionError): chat.prepare(self.db,1,'test:1','Hello',1)
    def test_context_is_bounded(self):
        conversation=chat.save(self.db,1,'test:1','hello','x'*100000,None)
        history,_=chat.prepare(self.db,1,'test:1','question',conversation)
        self.assertLessEqual(sum(len(m['content']) for m in history), chat.MAX_CONTEXT)
        self.assertEqual(history[-1]['content'],'question')
    def test_inference_single_flight(self):
        self.assertTrue(chat.INFERENCE_SLOT.acquire(blocking=False))
        try:
            with self.assertRaises(BlockingIOError): chat.request_ollama('test:1', [{'role':'user','content':'Hi'}], '')
        finally:
            chat.INFERENCE_SLOT.release()
