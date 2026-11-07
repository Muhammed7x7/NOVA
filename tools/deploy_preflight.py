#!/usr/bin/env python3
"""Experimental read-only service preflight + private backup/migration rehearsal.

This tool does not replace application files, stop a service or perform a deploy.
It may create private staging copies under --destination.
"""
import argparse
from pathlib import Path
import shutil
import sys
import sysconfig

from access_hub_next import app
from tools.deploy_candidate import _prepare_release
from tools.stage_candidate import stage
from tools.systemd_adapter import SystemdService


def run_preflight(app_dir: Path, vendor: Path, destination: Path, service: SystemdService, lab_inspector=None) -> Path:
    app_dir=app_dir.resolve(strict=True);destination=destination.resolve(strict=True)
    service.inspect()
    service.healthy(candidate=False)
    app.MAVIORKIDE_ROOT=service.mavi_root
    inspector=lab_inspector or app._mavi_lab_container_state
    lab=inspector()
    if not lab.get('running') or not lab.get('boundary_safe'):
        raise RuntimeError('Repo Lab is not running or its expected boundary configuration could not be verified')
    # Build release in private staging, and verify the actual /usr/bin/python3
    # can import the code and native Pillow binaries, before any service change.
    release,_=_prepare_release(destination,vendor)
    shutil.rmtree(release)
    # Includes online backup, migration on a separate DB copy and legacy-user/session fingerprint.
    return stage(app_dir,destination)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-dir',type=Path,default=Path.home()/'access-hub')
    parser.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args()
    try:
        service=SystemdService(args.app_dir)
        result=run_preflight(args.app_dir,Path(sysconfig.get_path('purelib')),args.destination,service)
    except Exception as exc:
        parser.exit(1,f'Preflight failed ({type(exc).__name__}): {exc}\n')
    print('Service, interpreter, Repo Lab configuration and migration-copy checks passed.')
    print('Private staging directory:',result)
    print('No application file or service was changed. This is not a deployment.')

if __name__=='__main__':main()
