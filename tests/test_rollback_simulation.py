"""Temporary rollback proof only; no systemd or production access."""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tools.backup import backup
from access_hub_next import app

class RollbackSimulationTests(unittest.TestCase):
    def test_scrypt_upgrade_requires_matching_database_restore(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);live=root/'live';(live/'data').mkdir(parents=True);backup_dir=root/'backups';backup_dir.mkdir()
            repo=Path(__file__).resolve().parents[1];shutil.copyfile(repo/'baseline'/'app.py',live/'app.py')
            spec=importlib.util.spec_from_file_location('legacy_rollback',repo/'baseline'/'app.py')
            legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
            legacy.DATA_DIR=live/'data';legacy.DB_PATH=legacy.DATA_DIR/'access_hub.sqlite3'
            with patch.dict('os.environ',{'INITIAL_ADMIN_PASSWORD':'temporary-password-123'}):
                legacy.init_db()
            old=backup(live,backup_dir)
            with patch.object(app,'DATA_DIR',legacy.DATA_DIR),patch.object(app,'DB_PATH',legacy.DB_PATH):
                self.assertFalse(app.init_db())
                self.assertIsNotNone(app.authenticate_admin('temporary-password-123'))
            # The old app cannot verify the new hash: restoring source alone is unsafe.
            self.assertIsNone(legacy.authenticate_admin('temporary-password-123'))
            restored=root/'restore';restored.mkdir();shutil.copyfile(old/'access_hub.sqlite3',restored/'access_hub.sqlite3')
            legacy.DATA_DIR=restored;legacy.DB_PATH=restored/'access_hub.sqlite3'
            self.assertIsNotNone(legacy.authenticate_admin('temporary-password-123'))

    def test_compat_mode_keeps_credentials_readable_by_original_app(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);data=root/'data';data.mkdir()
            repo=Path(__file__).resolve().parents[1]
            spec=importlib.util.spec_from_file_location('legacy_compat',repo/'baseline'/'app.py')
            legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
            legacy.DATA_DIR=data;legacy.DB_PATH=data/'access_hub.sqlite3'
            with patch.dict('os.environ',{'INITIAL_ADMIN_PASSWORD':'temporary-password-123'}): legacy.init_db()
            with patch.object(app,'DATA_DIR',data),patch.object(app,'DB_PATH',legacy.DB_PATH),patch.object(app,'LEGACY_CREDENTIAL_COMPAT',True):
                app.init_db()
                self.assertIsNotNone(app.authenticate_admin('temporary-password-123'))
                user=app.admin_create_user({'username':'new-user','display_name':'New','role':'standard','credential':'new-password'})
                self.assertIsNotNone(app.authenticate_standard('new-user','new-password'))
                salt,digest=app.hash_credential('new-password')
                self.assertFalse(digest.startswith('scrypt$'))
                # Previously-created scrypt credentials still verify, though legacy cannot use them.
                with patch.object(app,'LEGACY_CREDENTIAL_COMPAT',False):
                    salt,digest=app.hash_credential('other-password')
                self.assertTrue(app.verify_credential('other-password',salt,digest))
                app.admin_reset_credential(user['id'],'reset-password')
                app.admin_change_password(1,'temporary-password-123','changed-admin-password')
            self.assertIsNotNone(legacy.authenticate_admin('changed-admin-password'))
            self.assertIsNotNone(legacy.authenticate_standard('new-user','reset-password'))
