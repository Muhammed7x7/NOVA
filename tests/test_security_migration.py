import hashlib
import importlib
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

class CredentialMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.env=patch.dict(os.environ,{'APP_DATA_DIR':self.tmp.name,'INITIAL_ADMIN_PASSWORD':'test-password-123'});self.env.start()
        from access_hub_next import app
        self.app=importlib.reload(app);self.app.init_db()
    def tearDown(self):self.env.stop();self.tmp.cleanup()
    def test_failed_legacy_login_does_not_migrate(self):
        salt='ab'*24;old=hashlib.pbkdf2_hmac('sha256',b'password123',salt.encode(),self.app.HASH_ROUNDS).hex()
        with self.app.connect() as db:
            db.execute('INSERT INTO users(username,display_name,role,credential_salt,credential_hash,active,created_at) VALUES (?,?,?,?,?,1,1)',('legacy','Legacy','standard',salt,old))
        self.assertIsNone(self.app.authenticate_standard('legacy','incorrect'))
        with self.app.connect() as db:
            self.assertEqual(db.execute("SELECT credential_hash FROM users WHERE username='legacy'").fetchone()[0],old)
        self.assertIsNotNone(self.app.authenticate_standard('legacy','password123'))
        with self.app.connect() as db:
            self.assertTrue(db.execute("SELECT credential_hash FROM users WHERE username='legacy'").fetchone()[0].startswith('scrypt$'))
    def test_scrypt_untrusted_parameters_are_not_executed(self):
        self.assertFalse(self.app.verify_credential('password','ab'*24,'scrypt$999999999$8$1$abc'))
