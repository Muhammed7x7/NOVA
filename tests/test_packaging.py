import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from tools import backup, preflight

class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.base=Path(self.tmp.name)
        self.app=self.base/'app'; (self.app/'data').mkdir(parents=True)
        (self.app/'app.py').write_text('# ACCESS_HUB_TERMUX_CONSOLE_V6\n')
        con=sqlite3.connect(self.app/'data'/'access_hub.sqlite3')
        con.execute('CREATE TABLE users (id INTEGER PRIMARY KEY,username TEXT,display_name TEXT,role TEXT,credential_salt TEXT,credential_hash TEXT,active INTEGER,created_at INTEGER)')
        con.execute('CREATE TABLE sessions (token_hash TEXT PRIMARY KEY)');con.execute('CREATE TABLE settings (id INTEGER)')
        con.execute("INSERT INTO users(username) VALUES ('private')");con.commit();con.close()
        self.out=self.base/'backups';self.out.mkdir()
    def tearDown(self): self.tmp.cleanup()
    def test_readonly_inventory_without_sensitive_data(self):
        result=preflight.inspect_db(self.app/'data'/'access_hub.sqlite3')
        self.assertTrue(result['quick_check']);self.assertTrue(result['legacy_users_schema_compatible'])
        self.assertNotIn('private',json.dumps(result))
        self.assertTrue(preflight.inspect_app(self.app/'app.py')['markers']['terminal_v6'])
    def test_backup_database_and_permissions(self):
        avatars=self.app/'data'/'avatars';avatars.mkdir();(avatars/'one.png').write_bytes(b'example')
        out=backup.backup(self.app,self.out)
        self.assertEqual(os.stat(out).st_mode & 0o777,0o700)
        self.assertEqual(os.stat(out/'access_hub.sqlite3').st_mode & 0o777,0o600)
        db=sqlite3.connect(out/'access_hub.sqlite3');self.assertEqual(db.execute('SELECT username FROM users').fetchone()[0],'private');db.close()
        self.assertEqual((out/'avatars'/'one.png').read_bytes(),b'example')
        self.assertEqual(json.loads((out/'manifest.json').read_text())['format'],1)
    def test_invalid_dest_and_symlink_rejected(self):
        with self.assertRaises(ValueError):backup.backup(self.app,self.app/'data')
        avatars=self.app/'data'/'avatars';avatars.mkdir();(avatars/'link').symlink_to(self.app/'app.py')
        with self.assertRaises(ValueError): backup.backup(self.app,self.out)
        self.assertEqual(list(self.out.iterdir()),[])
    def test_backup_uses_sqlite_backup_with_wal(self):
        live=sqlite3.connect(self.app/'data'/'access_hub.sqlite3')
        live.execute('PRAGMA journal_mode=WAL')
        live.execute("INSERT INTO users(username) VALUES ('uncheckpointed')");live.commit()
        out=backup.backup(self.app,self.out)
        copy=sqlite3.connect(out/'access_hub.sqlite3')
        self.assertEqual(copy.execute('SELECT count(*) FROM users').fetchone()[0],2)
        copy.close();live.close()
    def test_container_inventory_checks_host_boundaries(self):
        from unittest.mock import patch
        workspace=str(self.base/'workspace')
        data=[{'State':{'Running':True},'Config':{'User':'1000:1000'},
               'HostConfig':{'Privileged':False,'ReadonlyRootfs':True,'Memory':3221225472,'PidsLimit':256,'SecurityOpt':['no-new-privileges:true'],'CapDrop':['ALL'],'NetworkMode':'bridge','PidMode':'','IpcMode':'private'},
               'Mounts':[{'Type':'bind','Source':workspace,'Destination':'/workspace'}]}]
        with patch.object(preflight,'command',return_value=(0,json.dumps(data))):
            result=preflight.inspect_lab('lab',workspace)
        self.assertTrue(result['workspace_bind_matches_expected']);self.assertTrue(result['all_capabilities_dropped'])
        self.assertFalse(result['docker_socket_mounted']);self.assertFalse(result['host_network']);self.assertFalse(result['extra_mounts_present'])
        data[0]['Mounts'].append({'Type':'bind','Source':'/var/run/docker.sock','Destination':'/var/run/docker.sock'})
        data[0]['HostConfig']['NetworkMode']='host'
        with patch.object(preflight,'command',return_value=(0,json.dumps(data))):
            result=preflight.inspect_lab('lab',workspace)
        self.assertTrue(result['docker_socket_mounted']);self.assertTrue(result['host_network']);self.assertTrue(result['extra_mounts_present'])
    def test_stage_migrates_copy_only_and_rejects_wrong_hash(self):
        from tools import stage_candidate
        self.assertRaises(ValueError, stage_candidate.stage, self.app,self.out,'wrong')
        self.assertEqual(list(self.out.iterdir()),[])
        digest=backup.file_sha256(self.app/'app.py')
        original_before=backup.file_sha256(self.app/'data'/'access_hub.sqlite3')
        out=stage_candidate.stage(self.app,self.out,digest)
        self.assertEqual(backup.file_sha256(self.app/'data'/'access_hub.sqlite3'),original_before)
        self.assertTrue((out/'candidate'/'access_hub_next'/'app.py').is_file())
        self.assertIn('Do not deploy',(out/'STAGING-ONLY.txt').read_text())
        con=sqlite3.connect(out/'candidate-data.sqlite3')
        self.assertEqual(con.execute("SELECT username FROM users").fetchone()[0],'private')
        self.assertIsNotNone(con.execute("SELECT name FROM sqlite_master WHERE name='nova_roles'").fetchone());con.close()
        original=sqlite3.connect(out/'access_hub.sqlite3')
        self.assertIsNone(original.execute("SELECT name FROM sqlite_master WHERE name='nova_roles'").fetchone());original.close()
        self.assertEqual(json.loads((out/'manifest.json').read_text())['db_sha256'],backup.file_sha256(out/'access_hub.sqlite3'))
    def test_stage_failure_does_not_touch_original(self):
        from tools import stage_candidate
        db=sqlite3.connect(self.app/'data'/'access_hub.sqlite3');db.execute('DROP TABLE sessions');db.commit();db.close()
        before=backup.file_sha256(self.app/'data'/'access_hub.sqlite3')
        with self.assertRaises(ValueError):stage_candidate.stage(self.app,self.out,backup.file_sha256(self.app/'app.py'))
        self.assertEqual(backup.file_sha256(self.app/'data'/'access_hub.sqlite3'),before)
        self.assertEqual(list(self.out.iterdir()),[])
