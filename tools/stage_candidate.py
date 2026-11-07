#!/usr/bin/env python3
"""EXPERIMENTAL: stage and migrate a private copy, never deploy or restart services."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.backup import backup, file_sha256
from access_hub_next import rbac

# Source actually supplied by the user, not a wildcard compatibility claim.
KNOWN_SOURCE_SHA256 = 'ee9123b2c6e48a5bcbef19c746b71f963a9327286070c5d00ebe329601a6220b'


def database_fingerprint(con: sqlite3.Connection) -> str:
    """Hash legacy account and session values without printing private data."""
    digest = hashlib.sha256()
    for table, order in [('users', 'id'), ('sessions', 'token_hash')]:
        columns = [row[1] for row in con.execute(f'PRAGMA table_info({table})')]
        if not columns or order not in columns:
            raise ValueError(f'Missing required legacy table: {table}')
        for row in con.execute(f'SELECT * FROM {table} ORDER BY {order}'):
            digest.update(json.dumps(list(row), ensure_ascii=True, separators=(',', ':'), default=str).encode())
            digest.update(b'\n')
    return digest.hexdigest()


def stage(app_dir: Path, destination: Path, expected_sha256: str = KNOWN_SOURCE_SHA256) -> Path:
    source = app_dir.expanduser().resolve(strict=True) / 'app.py'
    if file_sha256(source) != expected_sha256:
        raise ValueError('Unsupported source hash; staging aborted')
    result = backup(app_dir, destination)
    try:
        if file_sha256(result / 'app.py') != expected_sha256:
            raise ValueError('Source changed during backup; staging aborted')
        # Keep the untouched online backup separately from the test migration.
        candidate_db = result / 'candidate-data.sqlite3'
        shutil.copyfile(result / 'access_hub.sqlite3', candidate_db)
        os.chmod(candidate_db, 0o600)
        con = sqlite3.connect(candidate_db)
        con.row_factory = sqlite3.Row
        try:
            con.execute('PRAGMA foreign_keys=ON')
            before = database_fingerprint(con)
            with con:
                rbac.migrate(con)
                if before != database_fingerprint(con):
                    raise ValueError('Legacy user/session data unexpectedly changed')
                if con.execute('PRAGMA foreign_key_check').fetchone() is not None:
                    raise ValueError('Foreign key check failed')
                if con.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise ValueError('SQLite quick_check failed')
        finally:
            con.close()
        release = result / 'candidate'
        release.mkdir(mode=0o700)
        shutil.copytree(ROOT / 'access_hub_next', release / 'access_hub_next',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copyfile(ROOT / 'requirements.txt', release / 'requirements.txt')
        for path in release.rglob('*'):
            if path.is_file(): os.chmod(path, 0o600)
            elif path.is_dir(): os.chmod(path, 0o700)
        (result / 'STAGING-ONLY.txt').write_text(
            'PRIVATE DATA. Experimental copy for migration verification only. '
            'Do not deploy, restart services, or use as a complete rollback backup.\n', encoding='utf-8')
        os.chmod(result / 'STAGING-ONLY.txt', 0o600)
        return result
    except Exception:
        shutil.rmtree(result)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-dir', type=Path, default=Path.home() / 'access-hub')
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        out = stage(args.app_dir, args.destination)
    except (OSError, sqlite3.Error, ValueError) as exc:
        parser.exit(1, f'Staging failed: {exc}\n')
    print(f'Staging copy created: {out}')
    print('Private data. Original server files and services were not modified. DO NOT DEPLOY.')

if __name__ == '__main__': main()
