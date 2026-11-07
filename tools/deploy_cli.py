#!/usr/bin/env python3
"""EXPERIMENTAL systemd operator interface: not validated for production.

No changes without an explicit --apply or --rollback. Run as the service user;
this program does not request, accept or store passwords. A cached sudo approval
is required for a mutating operation. See README for limitations.
"""
import argparse
import os
import signal
from contextlib import contextmanager
from pathlib import Path
import stat
import subprocess
import sysconfig

from tools import deploy_candidate, deploy_preflight
from tools.systemd_adapter import SystemdService


def private_directory(path: Path, app_dir: Path) -> Path:
    if path.is_symlink():raise ValueError('Backup path must not be a symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path=path.resolve(strict=True)
    info=path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077:
        raise ValueError('Backup directory must be private and owned by the service user')
    if path==app_dir or app_dir in path.parents:raise ValueError('Backup directory must be outside the application directory')
    return path


def execute(action, app_dir, destination, vendor, service, *, lab_inspector=None, rollback_dir=None, sudo_check=None):
    """Explicit mutating actions; adapter and sudo check injectable for tests."""
    app_dir=Path(app_dir).resolve(strict=True)
    destination=private_directory(Path(destination),app_dir)
    if action=='preflight':
        return deploy_preflight.run_preflight(app_dir,vendor,destination,service,lab_inspector)
    service.inspect()
    if action=='apply':
        # Dry-run and snapshot the actual current DB before the service is touched.
        deploy_preflight.run_preflight(app_dir,vendor,destination,service,lab_inspector)
        (sudo_check or check_sudo)()
        return deploy_candidate.deploy(app_dir,destination,vendor,service)
    if action=='rollback':
        if rollback_dir is None:raise ValueError('Rollback backup path required')
        service.healthy(candidate=True)
        (sudo_check or check_sudo)()
        deploy_candidate.rollback(app_dir,Path(rollback_dir),service)
        return Path(rollback_dir)
    raise ValueError('Unknown action')


def check_sudo():
    subprocess.run(['sudo','-n','true'],check=True,capture_output=True,timeout=10)


@contextmanager
def recover_on_disconnect():
    """Convert hangup/termination into an exception so deploy can recover."""
    watched=(signal.SIGTERM,signal.SIGHUP)
    previous={sig:signal.getsignal(sig) for sig in watched}
    def interrupted(signum, _frame):
        # Prevent a second disconnect signal from interrupting recovery itself.
        for sig in watched:signal.signal(sig,signal.SIG_IGN)
        raise InterruptedError(f'Interrupted by signal {signum}')
    try:
        for sig in watched:signal.signal(sig,interrupted)
        yield
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_mutually_exclusive_group()
    actions.add_argument('--apply',action='store_true',help='experimental, not approved for production')
    actions.add_argument('--rollback',type=Path,help='experimental, not approved for production')
    parser.add_argument('--confirm-https',action='store_true',help='confirm external access uses HTTPS')
    parser.add_argument('--app-dir',type=Path,default=Path.home()/'access-hub')
    parser.add_argument('--destination',type=Path,default=Path.home()/'nova-deploy-backups')
    args=parser.parse_args()
    action='rollback' if args.rollback else 'apply' if args.apply else 'preflight'
    if action=='apply' and not args.confirm_https:
        parser.exit(2,'HTTPS confirmation is required.\n')
    try:
        with recover_on_disconnect():
            result=execute(action,args.app_dir,args.destination,Path(sysconfig.get_path('purelib')),
                           SystemdService(args.app_dir),rollback_dir=args.rollback)
    except Exception as exc:
        parser.exit(1,f'{action} failed ({type(exc).__name__}): {exc}\n')
    print(f'{action}: complete; private backup/staging: {result}')
    if action=='preflight':print('No application file or service was changed.')
    if action=='apply':print('Verify real logins and existing features. Rollback code only retains the current database; it does not restore a full system backup.')
    if action=='rollback':print('Original code restored; current database retained. New feature data is not usable by the old application.')

if __name__=='__main__':main()
