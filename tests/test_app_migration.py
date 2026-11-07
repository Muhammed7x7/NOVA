import importlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class AppMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'APP_DATA_DIR': self.tmp.name, 'INITIAL_ADMIN_PASSWORD': 'test-password-123'}, clear=False)
        self.env.start()
        from access_hub_next import app
        self.app = importlib.reload(app)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_fresh_install_and_new_user(self):
        self.assertTrue(self.app.init_db())
        self.assertIsNotNone(self.app.authenticate_admin('test-password-123'))
        user = self.app.admin_create_user({'role': 'standard', 'username': 'sample', 'display_name': 'Sample', 'credential': 'test-key-123'})
        self.assertIsNotNone(self.app.authenticate_standard('sample', 'test-key-123'))
        with self.app.connect() as db:
            self.assertEqual(self.app.rbac.effective_permissions(db, user['id']), {'portal.view'})
            self.assertEqual(db.execute('SELECT count(*) FROM nova_profiles WHERE user_id=?', (user['id'],)).fetchone()[0], 1)
        self.assertFalse(self.app.init_db())

    def test_legacy_user_login_remains_valid(self):
        db = sqlite3.connect(Path(self.tmp.name) / 'access_hub.sqlite3')
        db.executescript('''CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL, role TEXT NOT NULL, credential_salt TEXT NOT NULL, credential_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);''')
        salt, digest = self.app.hash_credential('old-admin-password')
        db.execute('INSERT INTO users VALUES (1,?,?,?,?,?,?,?)', ('admin', 'Admin', 'admin', salt, digest, 1, 100))
        db.commit(); db.close()
        self.assertFalse(self.app.init_db())
        self.assertIsNotNone(self.app.authenticate_admin('old-admin-password'))
        with self.app.connect() as db:
            self.assertTrue(self.app.rbac.has_permission(db, 1, 'access.users.manage'))
            self.assertEqual(db.execute('SELECT credential_hash FROM users WHERE id=1').fetchone()[0], digest)

if __name__ == '__main__': unittest.main()

class HttpAuthorizationTests(unittest.TestCase):
    def setUp(self):
        import threading
        from http.server import ThreadingHTTPServer
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'APP_DATA_DIR': self.tmp.name, 'INITIAL_ADMIN_PASSWORD': 'test-password-123'}, clear=False)
        self.env.start()
        from access_hub_next import app
        self.app = importlib.reload(app)
        self.app.init_db()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), self.app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.env.stop(); self.tmp.cleanup()

    def test_admin_permission_enforced_at_api(self):
        import http.client
        import json
        client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        client.request('POST', '/api/login/special', json.dumps({'user_id':'admin','password':'test-password-123'}), {'Content-Type':'application/json'})
        response = client.getresponse(); cookie = response.getheader('Set-Cookie').split(';')[0]; response.read()
        self.assertEqual(response.status, 200)
        with self.app.connect() as db:
            db.execute("DELETE FROM nova_role_permissions WHERE permission='access.users.manage'")
        client.request('POST', '/api/admin/users', json.dumps({'role':'standard','username':'demo','display_name':'Demo','credential':'12345678'}), {'Content-Type':'application/json', 'Cookie':cookie})
        response = client.getresponse(); response.read(); self.assertEqual(response.status, 403)
        with self.app.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM users WHERE username='demo'").fetchone()[0], 0)
        client.request('POST', '/api/admin/users', json.dumps({'role':'standard'}), {'Content-Type':'application/json'})
        response = client.getresponse(); response.read(); self.assertEqual(response.status, 401)
        client.close()

    def test_role_group_api_and_forbidden_visitor(self):
        import http.client
        import json
        client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        def post(path, payload, cookie=None):
            headers = {'Content-Type': 'application/json'}
            if cookie: headers['Cookie'] = cookie
            client.request('POST', path, json.dumps(payload), headers)
            response = client.getresponse(); raw = response.read()
            return response.status, json.loads(raw), response.getheader('Set-Cookie')
        status, _, _ = post('/api/admin/access/roles', {'key':'dev-role','display_name':'Developers'})
        self.assertEqual(status, 401)
        status, _, header = post('/api/login/special', {'user_id':'admin','password':'test-password-123'})
        cookie = header.split(';')[0]
        status, result, _ = post('/api/admin/access/roles', {'key':'dev-role','display_name':'Developers'}, cookie)
        self.assertEqual(status, 201); role = result['id']
        status, _, _ = post('/api/admin/access/role-permissions', {'role_id':role,'permissions':['tools.terminal']}, cookie)
        self.assertEqual(status, 200)
        status, result, _ = post('/api/admin/access/groups', {'key':'dev-group','display_name':'Developers'}, cookie)
        self.assertEqual(status, 201); group = result['id']
        status, _, _ = post('/api/admin/access/assignment', {'kind':'group-role','left':group,'right':role,'enabled':True}, cookie)
        self.assertEqual(status, 200)
        with self.app.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM nova_audit_events').fetchone()[0], 5)
        client.close()

    def test_profile_only_allows_display_name(self):
        import http.client
        import json
        c = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        c.request('POST', '/api/login/special', json.dumps({'user_id':'admin','password':'test-password-123'}), {'Content-Type':'application/json'})
        response = c.getresponse(); cookie = response.getheader('Set-Cookie').split(';')[0]; response.read()
        headers = {'Content-Type':'application/json', 'Cookie':cookie}
        c.request('POST', '/api/profile', json.dumps({'display_name':'New Admin'}), headers)
        response=c.getresponse(); response.read(); self.assertEqual(response.status, 200)
        c.request('POST', '/api/profile', json.dumps({'display_name':'Test','role':'admin'}), headers)
        response=c.getresponse(); response.read(); self.assertEqual(response.status, 400)
        c.request('GET', '/api/profile', headers={'Cookie':cookie})
        response=c.getresponse(); body=json.loads(response.read()); self.assertEqual(body['user']['display_name'], 'New Admin')
        c.close()

    def test_avatar_reencoding_and_reject_bad_files(self):
        import base64
        import io
        from PIL import Image
        image = Image.new('RGB', (6, 6), 'blue')
        raw = io.BytesIO(); image.save(raw, format='JPEG')
        self.app.store_avatar(1, base64.b64encode(raw.getvalue()).decode())
        with self.app.connect() as db:
            name = db.execute('SELECT avatar_filename FROM nova_profiles WHERE user_id=1').fetchone()[0]
        saved = Path(self.tmp.name, 'avatars', name).read_bytes()
        self.assertTrue(saved.startswith(b'\x89PNG\r\n\x1a\n'))
        with self.assertRaises(ValueError): self.app.store_avatar(1, base64.b64encode(b'<svg/>').decode())
        with self.assertRaises(ValueError): self.app.store_avatar(1, 'not valid base64!')

    def test_model_management_requires_permission(self):
        import http.client, json
        c = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        c.request('POST', '/api/login/special', json.dumps({'user_id':'admin','password':'test-password-123'}), {'Content-Type':'application/json'})
        r=c.getresponse(); cookie=r.getheader('Set-Cookie').split(';')[0]; r.read()
        headers={'Content-Type':'application/json','Cookie':cookie}
        payload={'tag':'local:test','display_name':'Local Test','active':True,'default_model':True}
        with patch.object(self.app, '_model_inventory', return_value=[{'name':'local:test','size':1}]):
            c.request('POST','/api/admin/agent/models',json.dumps(payload),headers)
            r=c.getresponse(); r.read(); self.assertEqual(r.status,200)
        c.request('GET','/api/agent/models',headers={'Cookie':cookie})
        r=c.getresponse(); data=json.loads(r.read()); self.assertEqual(data['models'][0]['tag'],'local:test')
        with self.app.connect() as db: db.execute("DELETE FROM nova_role_permissions WHERE permission='agent.manage'")
        c.request('POST','/api/admin/agent/models',json.dumps(payload),headers)
        r=c.getresponse(); r.read(); self.assertEqual(r.status,403)
        c.close()

    def test_agent_chat_http_with_mock_ollama_and_private_history(self):
        import http.client, json
        client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        def post(path, payload, cookie=None):
            headers={'Content-Type':'application/json'}
            if cookie: headers['Cookie']=cookie
            client.request('POST',path,json.dumps(payload),headers)
            r=client.getresponse(); body=json.loads(r.read()); return r.status,body,r.getheader('Set-Cookie')
        _,_,head=post('/api/login/special',{'user_id':'admin','password':'test-password-123'})
        cookie=head.split(';')[0]
        with patch.object(self.app,'_model_inventory',return_value=[{'name':'test:1','size':1}]):
            status,_,_=post('/api/admin/agent/models',{'tag':'test:1','display_name':'Test model','active':True,'default_model':True},cookie)
        self.assertEqual(status,200)
        with patch.object(self.app.chat,'request_ollama',return_value='Hello there'):
            status,body,_=post('/api/agent/chat',{'model':'test:1','message':'Hi','conversation_id':None},cookie)
        self.assertEqual(status,200); conv=body['conversation_id']; self.assertEqual(body['answer'],'Hello there')
        client.request('GET',f'/api/agent/conversations/{conv}',headers={'Cookie':cookie})
        r=client.getresponse(); messages=json.loads(r.read())['messages']; self.assertEqual([m['role'] for m in messages],['user','assistant'])
        new_user=self.app.admin_create_user({'role':'standard','username':'tester','display_name':'Tester','credential':'tester-password'})
        with self.app.connect() as db:
            role=self.app.rbac.create_role(db,1,{'key':'agent-reader','display_name':'Agent Reader'})
            self.app.rbac.set_role_permissions(db,1,role,['agent.history'])
            self.app.rbac.link(db,1,'user-role',new_user['id'],role,True)
        _,_,head=post('/api/login/standard',{'username':'tester','key':'tester-password'})
        client.request('GET',f'/api/agent/conversations/{conv}',headers={'Cookie':head.split(';')[0]})
        r=client.getresponse();r.read();self.assertEqual(r.status,404)
        client.close()

    def test_session_cookie_secure_by_default(self):
        import http.client, json
        client=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        client.request('POST','/api/login/special',json.dumps({'user_id':'admin','password':'test-password-123'}),{'Content-Type':'application/json'})
        response=client.getresponse();cookie=response.getheader('Set-Cookie');response.read()
        self.assertIn('Secure',cookie);self.assertIn('HttpOnly',cookie);self.assertIn('SameSite=Lax',cookie)
        client.close()

    def test_real_baseline_database_upgrade_preserves_logins_and_session(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('baseline_app', Path(__file__).resolve().parents[1] / 'baseline' / 'app.py')
        baseline = importlib.util.module_from_spec(spec); spec.loader.exec_module(baseline)
        legacy_dir = tempfile.TemporaryDirectory(); self.addCleanup(legacy_dir.cleanup)
        baseline.DATA_DIR = Path(legacy_dir.name)
        baseline.DB_PATH = baseline.DATA_DIR / 'access_hub.sqlite3'
        patch_data = patch.object(self.app, 'DATA_DIR', baseline.DATA_DIR); patch_data.start(); self.addCleanup(patch_data.stop)
        patch_db = patch.object(self.app, 'DB_PATH', baseline.DB_PATH); patch_db.start(); self.addCleanup(patch_db.stop)
        baseline.init_db()
        standard = baseline.admin_create_user({'role':'standard','username':'legacyuser','display_name':'Legacy','credential':'legacy-key-123'})
        special = baseline.admin_create_user({'role':'special','username':'specialuser','display_name':'Special','credential':'special-key-123'})
        token = baseline.create_session(standard['id'])
        before = sqlite3.connect(baseline.DB_PATH).execute('SELECT id,credential_salt,credential_hash FROM users ORDER BY id').fetchall()
        self.assertFalse(self.app.init_db())
        with self.app.connect() as con:
            unchanged = [tuple(row) for row in con.execute('SELECT id,credential_salt,credential_hash FROM users ORDER BY id')]
        self.assertEqual(before,unchanged)
        self.assertIsNotNone(self.app.authenticate_admin('test-password-123'))
        self.assertIsNotNone(self.app.authenticate_standard('legacyuser','legacy-key-123'))
        self.assertIsNotNone(self.app.authenticate_special(special['id'],'special-key-123'))
        self.assertEqual(self.app.session_user(token)['id'], standard['id'])
        with self.app.connect() as con:
            after = [tuple(row) for row in con.execute('SELECT id,credential_salt,credential_hash FROM users ORDER BY id')]
            self.assertEqual([row[0] for row in before],[row[0] for row in after])
            self.assertTrue(all(row[2].startswith('scrypt$') for row in after))
            self.assertEqual(self.app.rbac.effective_permissions(con,standard['id']),{'portal.view'})

    def test_sensitive_admin_endpoints_require_explicit_permissions(self):
        import http.client, json
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        c.request('POST','/api/login/special',json.dumps({'user_id':'admin','password':'test-password-123'}),{'Content-Type':'application/json'})
        r=c.getresponse();cookie=r.getheader('Set-Cookie').split(';')[0];r.read()
        with self.app.connect() as db:
            db.execute("DELETE FROM nova_role_permissions WHERE permission IN ('access.users.read','tools.repo.command')")
        c.request('GET','/api/admin/state',headers={'Cookie':cookie});r=c.getresponse();r.read();self.assertEqual(r.status,403)
        c.request('GET','/admin',headers={'Cookie':cookie});r=c.getresponse();r.read();self.assertEqual(r.status,403)
        c.request('POST','/api/admin/maviorkide/lab-command',json.dumps({'command':'echo test','cwd':'.'}),{'Content-Type':'application/json','Cookie':cookie})
        r=c.getresponse();r.read();self.assertEqual(r.status,403)
        c.close()

    def test_log_summary_does_not_expose_raw_log_values(self):
        with patch.object(self.app,'_command',return_value='[time] 127.0.0.1 GET /secret?token=private 200\nsecret-error private'):
            result=self.app.safe_terminal_action('logs')
        self.assertIn('HTTP 200: 1',result['output'])
        self.assertNotIn('private',result['output'])

    def test_conversation_deletion_is_owner_only(self):
        import http.client, json
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        c.request('POST','/api/login/special',json.dumps({'user_id':'admin','password':'test-password-123'}),{'Content-Type':'application/json'})
        r=c.getresponse();cookie=r.getheader('Set-Cookie').split(';')[0];r.read()
        with self.app.connect() as db:
            db.execute("INSERT INTO nova_conversations(id,user_id,title,created_at) VALUES (10,1,'Private',1)")
            db.execute("INSERT INTO nova_messages(conversation_id,role,content,created_at) VALUES (10,'user','Secret',1)")
        c.request('DELETE','/api/agent/conversations/10',headers={'Cookie':cookie});r=c.getresponse();r.read();self.assertEqual(r.status,200)
        with self.app.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM nova_messages WHERE conversation_id=10').fetchone()[0],0)
        c.request('DELETE','/api/agent/conversations/10',headers={'Cookie':cookie});r=c.getresponse();r.read();self.assertEqual(r.status,404)
        c.close()

    def test_password_reset_revokes_existing_sessions(self):
        user=self.app.admin_create_user({'role':'standard','username':'resetme','display_name':'Reset User','credential':'old-password'})
        token=self.app.create_session(user['id'])
        self.app.admin_reset_credential(user['id'],'new-password')
        self.assertIsNone(self.app.session_user(token))
        self.assertIsNone(self.app.authenticate_standard('resetme','old-password'))
        self.assertIsNotNone(self.app.authenticate_standard('resetme','new-password'))

    def test_user_update_audit_and_role_change_revokes_session(self):
        user=self.app.admin_create_user({'role':'standard','username':'before','display_name':'Before','credential':'sample-password'})
        token=self.app.create_session(user['id'])
        self.app.admin_update_user(user['id'],{'username':'after','display_name':'After','role':'special'},1)
        self.assertIsNone(self.app.session_user(token))
        self.assertIsNone(self.app.authenticate_standard('before','sample-password'))
        self.assertIsNotNone(self.app.authenticate_special(user['id'],'sample-password'))
        with self.app.connect() as db:
            self.assertEqual(db.execute("SELECT event_type FROM nova_audit_events WHERE subject_id=?",(str(user['id']),)).fetchone()[0],'user.updated')
        with self.assertRaises(ValueError): self.app.admin_update_user(1,{'username':'admin','display_name':'Admin','role':'special'},1)

    def test_admin_user_update_and_effective_access_api(self):
        import http.client, json
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        c.request('POST','/api/login/special',json.dumps({'user_id':'admin','password':'test-password-123'}),{'Content-Type':'application/json'})
        r=c.getresponse();cookie=r.getheader('Set-Cookie').split(';')[0];r.read()
        headers={'Content-Type':'application/json','Cookie':cookie}
        body={'role':'standard','username':'client','display_name':'Client','credential':'client-password'}
        c.request('POST','/api/admin/users',json.dumps(body),headers);r=c.getresponse();uid=json.loads(r.read())['user']['id'];self.assertEqual(r.status,201)
        c.request('GET',f'/api/admin/users/{uid}/access',headers={'Cookie':cookie});r=c.getresponse();data=json.loads(r.read());self.assertEqual(data['permissions'],['portal.view'])
        c.request('POST',f'/api/admin/users/{uid}/update',json.dumps({'username':'renamed','display_name':'Renamed','role':'special'}),headers);r=c.getresponse();r.read();self.assertEqual(r.status,200)
        self.assertIsNotNone(self.app.authenticate_special(uid,'client-password'))
        with self.app.connect() as db:
            events=[row[0] for row in db.execute('SELECT event_type FROM nova_audit_events WHERE subject_id=?',(str(uid),))]
            self.assertEqual(events,['user.created','user.updated'])
        c.close()

    def test_request_logs_do_not_include_query_or_path(self):
        import contextlib, io
        # Call the handler method without creating a live request.
        fake=type('Fake',(),{'client_address':('127.0.0.1',12345),'command':'GET','path':'/secret?token=private'})()
        capture=io.StringIO()
        with contextlib.redirect_stdout(capture): self.app.Handler.log_message(fake,'%s','unused','200')
        self.assertNotIn('private',capture.getvalue())
        self.assertNotIn('/secret',capture.getvalue())
        self.assertIn('/[redacted]',capture.getvalue())

    def test_repo_lab_can_be_delegated_without_admin_access(self):
        import http.client, json
        user=self.app.admin_create_user({'role':'standard','username':'developer','display_name':'Developer','credential':'dev-password'})
        cookie='access_hub='+self.app.create_session(user['id'])
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        headers={'Content-Type':'application/json','Cookie':cookie}
        def command():
            c.request('POST','/api/admin/maviorkide/lab-command',json.dumps({'command':'echo ok','cwd':'.'}),headers)
            response=c.getresponse();response.read();return response.status
        self.assertEqual(command(),403)
        with self.app.connect() as db:
            role=self.app.rbac.create_role(db,1,{'key':'repo-user','display_name':'Repo User'})
            self.app.rbac.set_role_permissions(db,1,role,['tools.terminal'])
            self.app.rbac.link(db,1,'user-role',user['id'],role,True)
        self.assertEqual(command(),403)
        with self.app.connect() as db:
            self.app.rbac.set_role_permissions(db,1,role,['tools.terminal','tools.repo.command'])
        with patch.object(self.app,'mavi_repo_lab_command',return_value={'cwd':'.','output':'ok','exit_code':0}):
            self.assertEqual(command(),200)
        with self.app.connect() as db:
            event=db.execute("SELECT actor_user_id,subject_id,detail FROM nova_audit_events WHERE event_type='repo.command.requested'").fetchone()
            self.assertEqual((event[0],event[1],event[2]),(user['id'],str(user['id']),''))
        c.request('GET','/api/admin/state',headers={'Cookie':cookie})
        response=c.getresponse();response.read();self.assertEqual(response.status,401)
        with self.app.connect() as db:
            self.app.rbac.set_role_permissions(db,1,role,['tools.terminal'])
        self.assertEqual(command(),403)
        c.close()

    def test_deactivation_permanently_revokes_old_sessions(self):
        user=self.app.admin_create_user({'role':'standard','username':'suspendme','display_name':'Suspend Me','credential':'secure-key-123'})
        token=self.app.create_session(user['id'])
        self.assertIsNotNone(self.app.session_user(token))
        self.app.admin_set_user_active(user['id'],False,1)
        self.assertIsNone(self.app.session_user(token))
        self.app.admin_set_user_active(user['id'],True,1)
        self.assertIsNone(self.app.session_user(token))
        self.assertIsNotNone(self.app.authenticate_standard('suspendme','secure-key-123'))

    def test_avatar_replacement_and_user_deletion_clean_only_unreferenced_images(self):
        import base64,io
        from PIL import Image
        first=self.app.admin_create_user({'role':'standard','username':'pictureone','display_name':'Picture One','credential':'secret-key-123'})
        second=self.app.admin_create_user({'role':'standard','username':'picturetwo','display_name':'Picture Two','credential':'secret-key-123'})
        buf=io.BytesIO();Image.new('RGB',(5,5),'blue').save(buf,format='PNG');image=base64.b64encode(buf.getvalue()).decode()
        self.app.store_avatar(first['id'],image)
        with self.app.connect() as db:old=db.execute('SELECT avatar_filename FROM nova_profiles WHERE user_id=?',(first['id'],)).fetchone()[0]
        self.app.store_avatar(first['id'],image)
        with self.app.connect() as db:
            new=db.execute('SELECT avatar_filename FROM nova_profiles WHERE user_id=?',(first['id'],)).fetchone()[0]
            db.execute('UPDATE nova_profiles SET avatar_filename=? WHERE user_id=?',(new,second['id']))
        directory=self.app.DATA_DIR/'avatars'
        self.assertFalse((directory/old).exists());self.assertTrue((directory/new).exists())
        self.app.admin_delete_user(first['id'],1);self.assertTrue((directory/new).exists())
        self.app.admin_delete_user(second['id'],1);self.assertFalse((directory/new).exists())

    def test_avatar_rejects_symlinked_storage_directory(self):
        import base64,io
        from PIL import Image
        outside=Path(self.tmp.name)/'outside';outside.mkdir()
        (self.app.DATA_DIR/'avatars').symlink_to(outside,target_is_directory=True)
        buf=io.BytesIO();Image.new('RGB',(5,5)).save(buf,format='PNG')
        with self.assertRaises(ValueError):self.app.store_avatar(1,base64.b64encode(buf.getvalue()).decode())
        self.assertEqual(list(outside.iterdir()),[])

    def test_audit_http_is_permission_checked_paginated_and_redacted(self):
        import http.client,json
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        c.request('GET','/api/admin/audit');r=c.getresponse();r.read();self.assertEqual(r.status,401)
        c.request('POST','/api/login/special',json.dumps({'user_id':'admin','password':'test-password-123'}),{'Content-Type':'application/json'})
        r=c.getresponse();cookie=r.getheader('Set-Cookie').split(';')[0];r.read();self.assertEqual(r.status,200)
        with self.app.connect() as db:
            db.executemany("INSERT INTO nova_audit_events(actor_user_id,event_type,subject_type,subject_id,detail,created_at) VALUES (1,'test.event','test','123','secret-never-return',1)",[()]*105)
        headers={'Cookie':cookie}
        c.request('GET','/api/admin/audit',headers=headers);r=c.getresponse();body=r.read();self.assertEqual(r.status,200)
        data=json.loads(body);self.assertEqual(len(data['events']),100);self.assertNotIn(b'secret-never-return',body);self.assertIsNotNone(data['next_before'])
        c.request('GET','/api/admin/audit?before='+str(data['next_before']),headers=headers);r=c.getresponse();older=json.loads(r.read());self.assertEqual(r.status,200)
        self.assertTrue(all(x['id']<data['next_before'] for x in older['events']))
        c.request('GET','/api/admin/audit?before=invalid',headers=headers);r=c.getresponse();r.read();self.assertEqual(r.status,400)
        with self.app.connect() as db:db.execute("DELETE FROM nova_role_permissions WHERE permission='system.logs'")
        c.request('GET','/api/admin/audit',headers=headers);r=c.getresponse();r.read();self.assertEqual(r.status,403)
        c.request('POST','/api/logout',headers=headers);r=c.getresponse();r.read();self.assertEqual(r.status,200)
        with self.app.connect() as db:
            names=[row[0] for row in db.execute("SELECT event_type FROM nova_audit_events WHERE event_type IN ('login.succeeded','logout.succeeded') ORDER BY id")]
        self.assertEqual(names,['login.succeeded','logout.succeeded']);c.close()

    def test_private_portal_requires_explicit_permission_and_rechecks_it(self):
        import http.client
        user=self.app.admin_create_user({'role':'standard','username':'portaluser','display_name':'Portal User','credential':'portal-key-123'})
        cookie='access_hub='+self.app.create_session(user['id'])
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port);headers={'Cookie':cookie}
        c.request('GET','/private',headers=headers);r=c.getresponse();r.read();self.assertEqual(r.status,200)
        with self.app.connect() as db:db.execute('DELETE FROM nova_user_roles WHERE user_id=?',(user['id'],))
        c.request('GET','/private',headers=headers);r=c.getresponse();r.read();self.assertEqual(r.status,403)
        c.close()
