import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sysconfig
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from tools import deploy_candidate as deploy

class LocalProcessService:
    """Real local HTTP process, but NOT systemd, sudo, tunnel or Docker."""
    def __init__(self,root,port):
        self.root=root;self.port=port;self.process=None;self.fail_next_candidate_health=False
    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate();self.process.wait(timeout=10)
        self.process=None
    def start(self):
        if self.process and self.process.poll() is None:return
        env=os.environ.copy();env.update(APP_DIR=str(self.root),APP_DATA_DIR=str(self.root/'data'),ACCESS_HUB_PORT=str(self.port),INITIAL_ADMIN_PASSWORD='test-password-123')
        self.process=subprocess.Popen(['/usr/bin/python3',str(self.root/'app.py')],cwd=self.root,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def healthy(self,candidate):
        path='/health' if candidate else '/'
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            if self.process.poll() is not None:raise RuntimeError('Local server exited')
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{self.port}{path}',timeout=1) as r:
                    if r.status==200:break
            except (OSError,urllib.error.URLError):pass
            time.sleep(.05)
        else:raise RuntimeError('Local health check failed')
        if candidate and self.fail_next_candidate_health:
            self.fail_next_candidate_health=False
            raise RuntimeError('Simulated candidate startup failure')

class DeploySimulationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.app=self.root/'app';self.app.mkdir();self.backups=self.root/'backups';self.backups.mkdir()
        base=Path(__file__).resolve().parents[1]/'baseline'/'app.py';shutil.copyfile(base,self.app/'app.py')
        spec=importlib.util.spec_from_file_location('legacy_install_sim',base);self.legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.legacy)
        self.legacy.DATA_DIR=self.app/'data';self.legacy.DB_PATH=self.legacy.DATA_DIR/'access_hub.sqlite3'
        old=os.environ.get('INITIAL_ADMIN_PASSWORD');os.environ['INITIAL_ADMIN_PASSWORD']='test-password-123'
        try:self.legacy.init_db()
        finally:
            if old is None:os.environ.pop('INITIAL_ADMIN_PASSWORD',None)
            else:os.environ['INITIAL_ADMIN_PASSWORD']=old
        self.legacy.admin_create_user({'role':'standard','username':'legacy','display_name':'Legacy','credential':'legacy-key-123'})
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));self.port=sock.getsockname()[1]
        self.service=LocalProcessService(self.app,self.port);self.addCleanup(self.service.stop)
        self.service.start();self.service.healthy(False)
        self.vendor=Path(sysconfig.get_path('purelib'))
    def test_deploy_and_rollback_preserve_new_legacy_compatible_user(self):
        backup=deploy.deploy(self.app,self.backups,self.vendor,self.service)
        self.assertTrue((backup/'access_hub.sqlite3').is_file())
        self.assertIn('ACCESS_HUB_LEGACY_CREDENTIAL_COMPAT', (self.app/'app.py').read_text())
        # Exercise the actual running candidate via HTTP and its real DB.
        req=urllib.request.Request(f'http://127.0.0.1:{self.port}/api/login/standard',data=json.dumps({'username':'legacy','key':'legacy-key-123'}).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as r:self.assertEqual(r.status,200)
        req=urllib.request.Request(f'http://127.0.0.1:{self.port}/api/login/special',data=json.dumps({'user_id':'admin','password':'test-password-123'}).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=3) as r:cookie=r.headers['Set-Cookie'].split(';')[0]
        payload={'username':'created','display_name':'Created','role':'standard','credential':'created-key-123'}
        req=urllib.request.Request(f'http://127.0.0.1:{self.port}/api/admin/users',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','Cookie':cookie})
        with urllib.request.urlopen(req,timeout=3) as r:self.assertEqual(r.status,201)
        deploy.rollback(self.app,backup,self.service)
        self.assertEqual(deploy.file_sha256(self.app/'app.py'),deploy.KNOWN_SOURCE_SHA256)
        self.assertIsNotNone(self.legacy.authenticate_standard('legacy','legacy-key-123'))
        self.assertIsNotNone(self.legacy.authenticate_standard('created','created-key-123'))
    def test_candidate_failure_recovers_legacy_code_and_database(self):
        self.service.fail_next_candidate_health=True
        with self.assertRaises(deploy.DeploymentError):deploy.deploy(self.app,self.backups,self.vendor,self.service)
        self.assertEqual(deploy.file_sha256(self.app/'app.py'),deploy.KNOWN_SOURCE_SHA256)
        self.service.healthy(False)
        self.assertIsNotNone(self.legacy.authenticate_admin('test-password-123'))
    def test_reject_unknown_hash_and_restart_original(self):
        import sqlite3
        self.service.stop()
        with sqlite3.connect(self.legacy.DB_PATH) as db:db.execute("UPDATE users SET credential_hash='scrypt$unknown' WHERE username='legacy'")
        self.service.start();self.service.healthy(False)
        with self.assertRaises(deploy.DeploymentError):deploy.deploy(self.app,self.backups,self.vendor,self.service)
        self.assertEqual(deploy.file_sha256(self.app/'app.py'),deploy.KNOWN_SOURCE_SHA256)
        self.service.healthy(False)
    def test_stop_failure_attempts_to_recover_original_service(self):
        original=self.service.stop;calls=0
        def fail_once():
            nonlocal calls
            calls+=1
            if calls==1:raise RuntimeError('simulated stop error')
            original()
        self.service.stop=fail_once
        with self.assertRaises(deploy.DeploymentError):deploy.deploy(self.app,self.backups,self.vendor,self.service)
        self.assertEqual(deploy.file_sha256(self.app/'app.py'),deploy.KNOWN_SOURCE_SHA256)
        self.service.healthy(False)
    def test_rollback_refuses_incompatible_credentials_and_recovers_candidate(self):
        import sqlite3
        backup=deploy.deploy(self.app,self.backups,self.vendor,self.service)
        self.service.stop()
        with sqlite3.connect(self.legacy.DB_PATH) as db:db.execute("UPDATE users SET credential_hash='scrypt$unknown' WHERE username='legacy'")
        self.service.start();self.service.healthy(True)
        with self.assertRaises(deploy.DeploymentError):deploy.rollback(self.app,backup,self.service)
        self.assertNotEqual(deploy.file_sha256(self.app/'app.py'),deploy.KNOWN_SOURCE_SHA256)
        self.service.healthy(True)

    def test_systemd_adapter_preflight_deploy_and_rollback_with_simulated_systemctl(self):
        from types import SimpleNamespace
        from tools.systemd_adapter import SystemdService
        def run(args, **kwargs):
            if args[0]=='systemctl' and 'is-active' in args:
                if self.service.process is None or self.service.process.poll() is not None:raise subprocess.CalledProcessError(3,args)
                return SimpleNamespace(stdout='active\n')
            if args[0]=='systemctl' and 'show' in args:
                return SimpleNamespace(stdout=str(self.service.process.pid)+'\n')
            if args[:3]==['sudo','-n','systemctl'] and args[3]=='stop':self.service.stop();return SimpleNamespace(stdout='')
            if args[:3]==['sudo','-n','systemctl'] and args[3]=='start':self.service.start();return SimpleNamespace(stdout='')
            raise AssertionError(args)
        adapter=SystemdService(self.app,runner=run)
        self.assertEqual(adapter.inspect(),self.port)
        saved=deploy.deploy(self.app,self.backups,self.vendor,adapter)
        adapter.healthy(True)
        deploy.rollback(self.app,saved,adapter)
        adapter.healthy(False)
        self.assertIsNotNone(self.legacy.authenticate_standard('legacy','legacy-key-123'))

    def test_systemd_adapter_rejects_different_working_directory(self):
        from types import SimpleNamespace
        from tools.systemd_adapter import SystemdService,ServiceCheckError
        def run(args,**kwargs):
            return SimpleNamespace(stdout=(str(self.service.process.pid)+'\n') if 'show' in args else 'active\n')
        wrong=self.root/'wrong';wrong.mkdir()
        with self.assertRaises(ServiceCheckError):SystemdService(wrong,runner=run).inspect()

    def test_concurrent_deployment_is_rejected_before_service_stop(self):
        import fcntl
        lock=self.app/'.nova-deploy.lock'
        fd=os.open(lock,os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(deploy.DeploymentError):deploy.deploy(self.app,self.backups,self.vendor,self.service)
            self.service.healthy(False)
            self.assertEqual(deploy.file_sha256(self.app/'app.py'),deploy.KNOWN_SOURCE_SHA256)
        finally:os.close(fd)
    def test_preflight_migrates_copy_without_changing_running_service(self):
        from types import SimpleNamespace
        from tools import deploy_preflight
        from tools.systemd_adapter import SystemdService
        def run(args,**kwargs):
            if 'is-active' in args:return SimpleNamespace(stdout='active\n')
            if 'show' in args:return SimpleNamespace(stdout=str(self.service.process.pid)+'\n')
            raise AssertionError(args)
        service=SystemdService(self.app,runner=run)
        before=deploy.file_sha256(self.app/'app.py')
        saved=deploy_preflight.run_preflight(self.app,self.vendor,self.backups,service,lambda:{'running':True,'boundary_safe':True})
        self.assertTrue((saved/'candidate-data.sqlite3').exists())
        self.assertEqual(deploy.file_sha256(self.app/'app.py'),before)
        service.healthy(False)
    def test_preflight_rejects_failed_lab_without_stopping_service(self):
        from types import SimpleNamespace
        from tools import deploy_preflight
        from tools.systemd_adapter import SystemdService
        def run(args,**kwargs):
            return SimpleNamespace(stdout=(str(self.service.process.pid)+'\n') if 'show' in args else 'active\n')
        service=SystemdService(self.app,runner=run)
        with self.assertRaises(RuntimeError):deploy_preflight.run_preflight(self.app,self.vendor,self.backups,service,lambda:{'running':True,'boundary_safe':False})
        service.healthy(False)
