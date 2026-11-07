#!/usr/bin/env python3
"""Create a private, non-destructive backup for evaluation; never restores or installs."""
import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def backup(app_dir: Path, destination: Path) -> Path:
    app_dir = app_dir.expanduser().resolve(strict=True)
    destination = destination.expanduser().resolve(strict=True)
    app, database = app_dir / 'app.py', app_dir / 'data' / 'access_hub.sqlite3'
    if not app.is_file() or not database.is_file():
        raise ValueError('Expected app.py and data/access_hub.sqlite3 are required')
    if not destination.is_dir() or destination == app_dir or app_dir in destination.parents:
        raise ValueError('Backup destination must be an existing directory outside the application directory')
    previous_umask = os.umask(0o077)
    out = None
    try:
        out = Path(tempfile.mkdtemp(prefix='access-hub-backup-', dir=destination))
        os.chmod(out, 0o700)
        shutil.copyfile(app, out / 'app.py')
        os.chmod(out / 'app.py', 0o600)
        source = sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True, timeout=15)
        target = sqlite3.connect(out / 'access_hub.sqlite3')
        try:
            source.backup(target)
            if target.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise ValueError('Database backup integrity check failed')
        finally:
            source.close()
            target.close()
        os.chmod(out / 'access_hub.sqlite3', 0o600)
        avatar_dir = app_dir / 'data' / 'avatars'
        if avatar_dir.is_symlink():
            raise ValueError('Avatar directory may not be a symlink')
        if avatar_dir.is_dir():
            target_dir = out / 'avatars'
            target_dir.mkdir(mode=0o700)
            for path in avatar_dir.iterdir():
                if path.is_symlink() or not path.is_file():
                    raise ValueError('Unsupported item in avatars directory')
                with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f, (target_dir / path.name).open('xb') as t:
                    shutil.copyfileobj(f, t)
                os.chmod(target_dir / path.name, 0o600)
        manifest = {'format': 1, 'database': 'access_hub.sqlite3',
                    'app_sha256': file_sha256(out / 'app.py'),
                    'db_sha256': file_sha256(out / 'access_hub.sqlite3'),
                    'warning': 'App, SQLite and avatars only; excludes systemd settings and workspace. Avatar files and database are not a single atomic snapshot. Backup contains private data.'}
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        os.chmod(out / 'manifest.json', 0o600)
        return out
    except Exception:
        if out is not None:
            shutil.rmtree(out)
        raise
    finally:
        os.umask(previous_umask)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-dir', type=Path, default=Path.home() / 'access-hub')
    parser.add_argument('--destination', type=Path, required=True, help='Existing private backup parent directory')
    args = parser.parse_args()
    try:
        path = backup(args.app_dir, args.destination)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f'Backup failed: {exc}\n')
    print(f'Backup created: {path}')
    print('Private data: restrict access; this does not back up systemd settings or the workspace.')

if __name__ == '__main__': main()
