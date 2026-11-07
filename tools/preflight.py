#!/usr/bin/env python3
"""Read-only compatibility inventory; does not install, restart or print secrets."""
import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path


def command(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=8, check=False)
        return result.returncode, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return -1, ''


def inspect_app(path: Path):
    result = {'present': path.is_file()}
    if path.is_file():
        data = path.read_bytes()
        result.update({'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                       'markers': {label: marker in data for label, marker in {
                           'admin_v2': b'ACCESS_HUB_ADMIN_TOOLS_V2',
                           'workspace_v3': b'ACCESS_HUB_MAVIORKIDE_TERMINAL_V3',
                           'repo_lab_v4': b'ACCESS_HUB_REPO_LAB_V4',
                           'terminal_v5': b'ACCESS_HUB_TERMINAL_UI_V5',
                           'terminal_v6': b'ACCESS_HUB_TERMUX_CONSOLE_V6',
                       }.items()}})
    return result


def inspect_db(path: Path):
    if not path.is_file():
        return {'present': False}
    result = {'present': True, 'readable': False}
    try:
        con = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
        try:
            result['readable'] = True
            result['quick_check'] = con.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
            columns = {r[1] for r in con.execute('PRAGMA table_info(users)')}
            result['legacy_users_schema_compatible'] = {'id', 'username', 'display_name', 'role', 'credential_salt', 'credential_hash', 'active', 'created_at'} <= columns
            result['tables_present'] = {name: bool(con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()) for name in ('users', 'sessions', 'settings')}
        finally:
            con.close()
    except sqlite3.Error:
        result['error'] = 'Database could not be safely inspected; no values were printed.'
    return result


def inspect_lab(name, workspace=None):
    rc, output = command('docker', 'inspect', name)
    if rc:
        return {'inspectable': False, 'reason': 'Docker or container unavailable to current user'}
    try:
        data = json.loads(output)[0]
        config, host = data.get('Config', {}), data.get('HostConfig', {})
        mounts = data.get('Mounts', [])
        socket_mounted = any('docker.sock' in str(m.get('Source', '')) or 'docker.sock' in str(m.get('Destination', '')) for m in mounts)
        security = host.get('SecurityOpt') or []
        expected_workspace = str(Path(workspace).expanduser().resolve()) if workspace is not None else None
        workspace_mounts = [m for m in mounts if m.get('Destination') == '/workspace']
        workspace_matches = (len(workspace_mounts) == 1 and expected_workspace is not None and
                             workspace_mounts[0].get('Type') == 'bind' and
                             str(Path(workspace_mounts[0].get('Source', '')).resolve()) == expected_workspace)
        return {'inspectable': True, 'running': bool(data.get('State', {}).get('Running')),
                'privileged': bool(host.get('Privileged')), 'read_only_root': bool(host.get('ReadonlyRootfs')),
                'docker_socket_mounted': socket_mounted, 'no_new_privileges': any(str(x).startswith('no-new-privileges') for x in security),
                'configured_user': bool(config.get('User')), 'memory_limit_bytes': host.get('Memory', 0),
                'pid_limit': host.get('PidsLimit'), 'mount_count': len(mounts),
                'workspace_bind_matches_expected': workspace_matches,
                'extra_mounts_present': any(m.get('Destination') != '/workspace' for m in mounts),
                'all_capabilities_dropped': 'ALL' in (host.get('CapDrop') or []),
                'host_network': host.get('NetworkMode') == 'host',
                'host_pid_namespace': host.get('PidMode') == 'host',
                'host_ipc_namespace': host.get('IpcMode') == 'host',
                'note': 'Configuration inventory only; not proof of isolation or of the user used by docker exec.'}
    except (ValueError, KeyError, IndexError, TypeError):
        return {'inspectable': False, 'reason': 'Unexpected Docker inspect output'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-dir', type=Path, default=Path.home() / 'access-hub')
    parser.add_argument('--container', default='maviorkide-repo-lab')
    parser.add_argument('--workspace', type=Path, default=Path.home() / 'maviorkide')
    args = parser.parse_args()
    service_rc, service = command('systemctl', 'is-active', 'access-hub.service')
    result = {'mode': 'inventory-only', 'app': inspect_app(args.app_dir / 'app.py'),
              'database': inspect_db(args.app_dir / 'data' / 'access_hub.sqlite3'),
              'service_active': service_rc == 0 and service == 'active', 'repo_lab': inspect_lab(args.container, args.workspace),
              'notice': 'No installation performed; this output does not establish production safety.'}
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main()
