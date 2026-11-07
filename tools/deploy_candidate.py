#!/usr/bin/env python3
"""Experimental deployment/rollback building blocks. Not production-approved.

Only a service-specific adapter should call deploy(). The separate operator CLI
is experimental and must not be treated as production-approved.
"""
from __future__ import annotations

import hashlib
import fcntl
from functools import wraps
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import tempfile
from typing import Protocol

from tools.backup import backup, file_sha256
from tools.stage_candidate import KNOWN_SOURCE_SHA256, database_fingerprint
from access_hub_next import rbac

ROOT = Path(__file__).resolve().parents[1]

class Service(Protocol):
    def stop(self) -> None: ...
    def start(self) -> None: ...
    def healthy(self, candidate: bool) -> None: ...

class DeploymentError(RuntimeError):
    pass


def _with_deployment_lock(function):
    @wraps(function)
    def wrapped(app_dir, *args, **kwargs):
        directory=Path(app_dir).resolve(strict=True)
        fd=os.open(directory/'.nova-deploy.lock', os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077:
                raise DeploymentError('Deployment lock is not private or owned by the service user')
            try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as exc: raise DeploymentError('Another deployment is running') from exc
            return function(app_dir,*args,**kwargs)
        finally:
            os.close(fd)
    return wrapped


def _legacy_credentials(con: sqlite3.Connection) -> None:
    # The original server understands only hex PBKDF2 hashes. Never proceed with
    # an unknown hash or pretend source-only rollback would be safe in that case.
    for (value,) in con.execute('SELECT credential_hash FROM users'):
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise DeploymentError('Database contains credentials incompatible with the legacy application')


def _validate_copy(path: Path) -> None:
    con=sqlite3.connect(path)
    con.row_factory=sqlite3.Row
    try:
        con.execute('PRAGMA foreign_keys=ON')
        _legacy_credentials(con)
        before=database_fingerprint(con)
        with con:
            rbac.migrate(con)
            if before != database_fingerprint(con):
                raise DeploymentError('Migration changed legacy account or session data')
            if con.execute('PRAGMA foreign_key_check').fetchone() is not None:
                raise DeploymentError('Migration foreign key check failed')
            if con.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise DeploymentError('Migration database integrity check failed')
    finally:
        con.close()


def _replace_file(target: Path, content: bytes, mode: int) -> None:
    # Write in the same directory for atomic replacement; never follow a target symlink.
    if target.is_symlink(): raise DeploymentError('Application file is a symlink')
    fd,name=tempfile.mkstemp(prefix='.nova-app-',dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(content);f.flush();os.fsync(f.fileno())
        os.chmod(name, mode)
        os.replace(name,target)
    finally:
        if os.path.exists(name): os.unlink(name)


def _prepare_release(app_dir: Path, vendor: Path) -> tuple[Path, bytes]:
    """Create an immutable-by-convention private release beside the live app."""
    vendor=vendor.resolve(strict=True)
    pil=vendor/'PIL'
    if not pil.is_dir() or pil.is_symlink():
        raise DeploymentError('Pillow package unavailable in the prepared environment')
    release=Path(tempfile.mkdtemp(prefix='nova-release-',dir=app_dir))
    os.chmod(release,0o700)
    try:
        shutil.copytree(ROOT/'access_hub_next',release/'access_hub_next',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        target=release/'vendor';target.mkdir(mode=0o700)
        for name in ('PIL','pillow.libs'):
            item=vendor/name
            if item.is_symlink(): raise DeploymentError('Vendor symlink rejected')
            if item.exists(): shutil.copytree(item,target/name,symlinks=False,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        # Validate the actual systemd interpreter and native Pillow binaries
        # before stopping the service; venv and service Python may differ.
        check = (f"import sys; sys.path[:0]=[{str(release)!r},{str(target)!r}]; "
                 "from PIL import Image; import access_hub_next.app; "
                 "Image.new('RGB',(1,1))")
        subprocess.run(['/usr/bin/python3','-I','-c',check], check=True,
                       timeout=15, capture_output=True, text=True)
        # Use a literal repr rather than interpolating a shell command.
        wrapper=("#!/usr/bin/env python3\n"
                 "import os, sys\n"
                 "os.environ['ACCESS_HUB_LEGACY_CREDENTIAL_COMPAT'] = '1'\n"
                 "os.environ['ACCESS_HUB_INSECURE_DEV_COOKIE'] = '0'\n"
                 f"sys.path.insert(0, {str(release / 'vendor')!r})\n"
                 f"sys.path.insert(0, {str(release)!r})\n"
                 "from access_hub_next.app import main\n"
                 "main()\n").encode()
        return release,wrapper
    except BaseException:
        shutil.rmtree(release)
        raise


@_with_deployment_lock
def deploy(app_dir: Path, backup_parent: Path, vendor: Path, service: Service) -> Path:
    """Install with a *caller-provided verified* service adapter. Experimental."""
    app_dir=app_dir.resolve(strict=True);backup_parent=backup_parent.resolve(strict=True)
    app_file=app_dir/'app.py'
    if app_file.is_symlink() or not app_file.is_file() or file_sha256(app_file)!=KNOWN_SOURCE_SHA256:
        raise DeploymentError('Unsupported or modified baseline application')
    if app_dir.stat().st_uid != os.getuid() or app_file.stat().st_uid != os.getuid():
        raise DeploymentError('Application files must belong to the service user')
    mode=stat.S_IMODE(app_file.stat().st_mode)
    release, wrapper=_prepare_release(app_dir,vendor)
    stopped=False; switched=False; saved=None
    try:
        stopped=True
        service.stop()
        # The service is stopped for DB+avatar snapshot and live source swap.
        saved=backup(app_dir,backup_parent)
        if file_sha256(saved/'app.py')!=KNOWN_SOURCE_SHA256:
            raise DeploymentError('Application changed during backup')
        scratch=saved/'migration-check.sqlite3'
        shutil.copyfile(saved/'access_hub.sqlite3',scratch);os.chmod(scratch,0o600)
        _validate_copy(scratch)
        manifest={'format':1,'baseline_sha256':KNOWN_SOURCE_SHA256,
                  'wrapper_sha256':hashlib.sha256(wrapper).hexdigest(),
                  'release':str(release),'app_mode':mode,'port':getattr(service,'port',None)}
        (saved/'deploy-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        os.chmod(saved/'deploy-manifest.json',0o600)
        # Mark intent before the atomic swap so an interrupt immediately after
        # os.replace still restores the verified original rather than deleting
        # the release that the new wrapper depends on.
        switched=True
        _replace_file(app_file,wrapper,mode)
        service.start()
        service.healthy(candidate=True)
        return saved
    except BaseException as exc:
        # Source-only recovery keeps newer DB changes. It is valid only because
        # this candidate is forced to generate legacy-compatible credentials.
        if stopped:
            try:
                if switched:
                    service.stop()
                    with sqlite3.connect((app_dir/'data'/'access_hub.sqlite3').resolve().as_uri()+'?mode=ro',uri=True) as con:
                        _legacy_credentials(con)
                    if saved is None or file_sha256(saved/'app.py')!=KNOWN_SOURCE_SHA256:
                        raise DeploymentError('Cannot verify rollback source')
                    _replace_file(app_file,(saved/'app.py').read_bytes(),mode)
                service.start();service.healthy(candidate=False)
                stopped=False
            except BaseException as rollback_exc:
                raise DeploymentError(f'Deploy failed; automatic recovery also failed: {type(rollback_exc).__name__}: {rollback_exc}. Backup: {saved}') from exc
        raise DeploymentError(f'Deploy failed; original service recovery attempted. Backup: {saved}; cause: {type(exc).__name__}: {exc}') from exc
    finally:
        if not switched:
            shutil.rmtree(release,ignore_errors=True)


@_with_deployment_lock
def rollback(app_dir: Path, backup_dir: Path, service: Service) -> None:
    """Restore only the matching old code, keeping the current live database.

    This is not a full disaster recovery or a restoration of newly added features.
    """
    app_dir=app_dir.resolve(strict=True);backup_dir=backup_dir.resolve(strict=True)
    app_file=app_dir/'app.py'
    if app_file.is_symlink() or not app_file.is_file(): raise DeploymentError('Unsupported app file')
    manifest=json.loads((backup_dir/'deploy-manifest.json').read_text())
    if manifest.get('format')!=1 or file_sha256(backup_dir/'app.py')!=KNOWN_SOURCE_SHA256:
        raise DeploymentError('Backup source could not be verified')
    if file_sha256(app_file)!=manifest.get('wrapper_sha256'):
        raise DeploymentError('Current application does not match this deployment')
    old_wrapper=app_file.read_bytes();mode=stat.S_IMODE(app_file.stat().st_mode)
    stopped=False;switched=False
    try:
        stopped=True;service.stop()
        dbpath=(app_dir/'data'/'access_hub.sqlite3').resolve(strict=True)
        with sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True) as con:
            _legacy_credentials(con)
            if con.execute('PRAGMA quick_check').fetchone()[0]!='ok':
                raise DeploymentError('Current database integrity check failed')
        switched=True
        _replace_file(app_file,(backup_dir/'app.py').read_bytes(),mode)
        service.start();service.healthy(candidate=False)
    except BaseException as exc:
        if stopped:
            try:
                if switched:
                    service.stop();_replace_file(app_file,old_wrapper,mode)
                service.start();service.healthy(candidate=True)
            except BaseException as recovery_exc:
                raise DeploymentError(f'Rollback failed and candidate recovery failed: {type(recovery_exc).__name__}: {recovery_exc}') from exc
        raise DeploymentError(f'Rollback failed; candidate recovery attempted: {type(exc).__name__}: {exc}') from exc
