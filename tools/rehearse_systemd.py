#!/usr/bin/env python3
"""Run an isolated real-systemd deployment/rollback rehearsal on a backup COPY.

Creates and removes a uniquely named temporary unit in /run/systemd/system. Never
stops or replaces access-hub.service. The test copy contains private user data.
Requires already-cached sudo authorization. This is not a production deployment.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sysconfig
import tempfile
import urllib.error
import urllib.request

from tools import deploy_candidate
from tools.backup import file_sha256
from tools.systemd_adapter import SystemdService
from tools.deploy_cli import recover_on_disconnect

_SYSTEMD_DIR = Path('/run/systemd/system')


def _sudo(*args):
    subprocess.run(['sudo','-n',*args],check=True,timeout=30,capture_output=True,text=True)


def _login(port, path, payload):
    req=urllib.request.Request(f'http://127.0.0.1:{port}{path}',
        data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=5) as response:
        if response.status!=200:raise RuntimeError('Temporary test login failed')
        response.read()


def _check_session(port, token):
    req=urllib.request.Request(f'http://127.0.0.1:{port}/private',headers={'Cookie':f'access_hub={token}'})
    with urllib.request.urlopen(req,timeout=5) as response:
        if response.status!=200 or response.geturl().endswith('/'):raise RuntimeError('Temporary test session was not preserved')
        response.read()


def _prepare_clone(backup: Path, destination: Path):
    home=Path.home().resolve();live=(home/'access-hub').resolve()
    destination=destination.resolve(strict=True);backup=backup.resolve(strict=True)
    if destination==live or live in destination.parents or home not in destination.parents:
        raise ValueError('Destination must be a private directory under home, outside the live application')
    if destination not in backup.parents:raise ValueError('Backup must reside within the private destination')
    info=destination.stat()
    if info.st_uid!=os.getuid() or info.st_mode & 0o077:raise ValueError('Destination must be private and owned by the service user')
    manifest=json.loads((backup/'manifest.json').read_text())
    if file_sha256(backup/'app.py')!=deploy_candidate.KNOWN_SOURCE_SHA256:
        raise ValueError('Unexpected backup application hash')
    if file_sha256(backup/'access_hub.sqlite3')!=manifest.get('db_sha256'):
        raise ValueError('Backup database hash mismatch')
    work=Path(tempfile.mkdtemp(prefix='systemd-rehearsal-',dir=destination));os.chmod(work,0o700)
    app=work/'app';data=app/'data';data.mkdir(parents=True,mode=0o700)
    shutil.copyfile(backup/'app.py',app/'app.py');shutil.copyfile(backup/'access_hub.sqlite3',data/'access_hub.sqlite3')
    backups=work/'backups';backups.mkdir(mode=0o700)
    return work,app,data,backups


def _make_fake_accounts(app: Path, data: Path):
    spec=importlib.util.spec_from_file_location('nova_rehearsal_legacy',app/'app.py')
    legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
    legacy.DATA_DIR=data;legacy.DB_PATH=data/'access_hub.sqlite3'
    suffix=secrets.token_hex(8);password=secrets.token_urlsafe(18)
    standard=legacy.admin_create_user({'username':'teststd'+suffix,'display_name':'Test Standard','role':'standard','credential':password})
    special=legacy.admin_create_user({'username':'testsp'+suffix,'display_name':'Test Special','role':'special','credential':password})
    salt,digest=legacy.hash_credential(password)
    with sqlite3.connect(legacy.DB_PATH) as con:
        admin=con.execute("SELECT id FROM users WHERE role='admin' AND active=1 LIMIT 1").fetchone()
        if admin is None:raise ValueError('No active administrator in test copy')
        con.execute('UPDATE users SET credential_salt=?,credential_hash=? WHERE id=?',(salt,digest,admin[0]))
    token=legacy.create_session(standard['id'])
    return standard,special,password,token


def _test_logins(port, standard, special, password, token):
    _check_session(port,token)
    _login(port,'/api/login/standard',{'username':standard['username'],'key':password})
    _login(port,'/api/login/special',{'user_id':special['id'],'password':password})
    _login(port,'/api/login/special',{'user_id':'admin','password':password})


def _port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def run(backup: Path, destination: Path, vendor: Path):
    if os.getuid()==0:raise ValueError('Run as the service user, not root')
    _sudo('true')
    work,app,data,backups=_prepare_clone(backup,destination)
    standard,special,password,token=_make_fake_accounts(app,data)
    port=_port();ident=secrets.token_hex(8);unit=f'nova-rehearsal-{ident}.service'
    unit_path=_SYSTEMD_DIR/unit
    username=pwd.getpwuid(os.getuid()).pw_name
    # Only exact safe characters are allowed in systemd configuration values.
    for value in (str(app),str(data),str(Path.home()),username):
        if not value or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_.-' for c in value):
            raise ValueError('Unsafe path or user name for transient unit')
    if unit_path.exists() or unit_path.is_symlink():raise ValueError('Temporary service unit already exists')
    conf=(f'[Unit]\nDescription=Temporary NOVA isolated rehearsal\n'
          f'[Service]\nType=simple\nUser={username}\nWorkingDirectory={app}\n'
          f'Environment=HOME={Path.home()}\nEnvironment=APP_DIR={app}\nEnvironment=APP_DATA_DIR={data}\n'
          f'Environment=ACCESS_HUB_PORT={port}\nExecStart=/usr/bin/python3 {app}/app.py\n')
    local_unit=work/'rehearsal.service';local_unit.write_text(conf);os.chmod(local_unit,0o600)
    installed=False;cleanup_error=None
    try:
        _sudo('install','-m','0644',str(local_unit),str(unit_path));installed=True
        _sudo('systemctl','daemon-reload')
        service=SystemdService(app,unit=unit)
        service.port=port  # Wait for Type=simple to bind before strict preflight.
        service.start();service.healthy(candidate=False);service.inspect()
        _test_logins(port,standard,special,password,token)
        saved=deploy_candidate.deploy(app,backups,vendor,service)
        _test_logins(port,standard,special,password,token)
        deploy_candidate.rollback(app,saved,service)
        _test_logins(port,standard,special,password,token)
        return work
    finally:
        if installed:
            try:
                _sudo('systemctl','stop',unit)
                _sudo('rm','-f','--',str(unit_path))
                _sudo('systemctl','daemon-reload')
            except (OSError,subprocess.SubprocessError) as exc:
                cleanup_error=exc
            if cleanup_error:
                raise RuntimeError(f'Temporary unit cleanup failed: {unit}. Do not remove any other service.') from cleanup_error


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup',type=Path,required=True)
    parser.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args()
    try:
        with recover_on_disconnect():
            work=run(args.backup,args.destination,Path(sysconfig.get_path('purelib')))
    except Exception as exc:parser.exit(1,f'Isolated rehearsal failed ({type(exc).__name__}): {exc}\n')
    print('Temporary systemd deployment, all three test logins, existing session, and rollback succeeded.')
    print('Live access-hub.service was not changed. Private rehearsal data:',work)

if __name__=='__main__':main()
