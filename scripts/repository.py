"""Portable Docker repository backups/exports; Python standard library only.

Examples (run from the project folder):
  py -3.13 scripts/repository.py backup backups/rules.db
  py -3.13 scripts/repository.py export backups/rules.zip
  py -3.13 scripts/repository.py restore backups/rules.db --replace

Stop the destination API before restoring. Use the same storage/project as the
server. Binary data goes directly to files, never through PowerShell pipelines.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil


ROOT = Path(__file__).resolve().parents[1]


def compose_command(storage):
    command = ['docker', 'compose', '--project-directory', str(ROOT), '-f', str(ROOT / 'compose.yaml')]
    if storage == 'windows':
        command += ['-f', str(ROOT / 'deployment/compose.windows.yaml')]
    return command


def run_transfer(command, storage, **kwargs):
    """Explain a stale container image without mixing diagnostics into backups."""
    try:
        result = subprocess.run(command, stderr=subprocess.PIPE, check=True, **kwargs)
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or b'').decode('utf-8', errors='replace')
        if 'No module named api.repository_transfer' in detail or "No module named 'api.repository_transfer'" in detail:
            launcher = (r'.\scripts\compose.bat' if storage == 'windows' else './scripts/compose.sh')
            raise ValueError(
                'The API container image is missing api.repository_transfer. Updating the checkout '
                'does not update an existing container. Ensure api/repository_transfer.py exists '
                f'on this server, then rebuild and recreate with: {launcher} up -d --build --force-recreate. '
                'For restore, stop the API again before retrying. If using a custom storage layout, '
                'use the same Compose files as this transfer command.'
            ) from error
        if detail:
            print(detail, file=sys.stderr, end='')
        raise
    if getattr(result, 'stderr', None):
        print(result.stderr.decode('utf-8', errors='replace'), file=sys.stderr, end='')


def transfer(action, file, *, storage, replace=False):
    file = Path(file).resolve()
    command = compose_command(storage)
    if action == 'restore':
        # Validate local file before contacting or changing any container.
        with file.open('rb') as source:
            running = subprocess.run(command + ['ps', '--all', '--format', 'json', 'yaraxgui-api'],
                                     check=True, capture_output=True, text=True)
            status = running.stdout.strip()
            containers = (json.loads(status) if status.startswith('[') else
                          [json.loads(line) for line in status.splitlines()])
            if any(item.get('State') not in ('exited', 'created') for item in containers):
                raise ValueError('Stop the destination API before restore: scripts/compose.bat stop yaraxgui-api '
                                 '(Linux: ./scripts/compose.sh stop yaraxgui-api). Back up its existing rules first.')
            operation = command + ['run', '--rm', '-T', '--no-deps', 'yaraxgui-api',
                                   'python', '-m', 'api.repository_transfer', 'restore', '-']
            if replace:
                operation.append('--replace')
            run_transfer(operation, storage, stdin=source)
        return
    if file.exists():
        raise FileExistsError(f'Output already exists: {file}; choose a new backup filename')
    file.parent.mkdir(parents=True, exist_ok=True)
    # Stage complete output before exposing the final backup filename.
    with tempfile.TemporaryDirectory(prefix='.repository-', dir=file.parent) as folder:
        staged = Path(folder) / 'output'
        with staged.open('xb') as target:
            run_transfer(command + ['exec', '-T', 'yaraxgui-api', 'python', '-m',
                                    'api.repository_transfer', action, '-'], storage, stdout=target)
        # Exclusive copy works on filesystems without hard-link support too.
        with file.open('xb') as target:
            try:
                with staged.open('rb') as source:
                    shutil.copyfileobj(source, target)
                target.flush()
                os.fsync(target.fileno())
            except BaseException:
                target.close()
                file.unlink(missing_ok=True)
                raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('backup', 'export', 'restore'))
    parser.add_argument('file')
    parser.add_argument('--storage', choices=('windows', 'linux'),
                        default='windows' if os.name == 'nt' else 'linux',
                        help='Compose storage layout; defaults to this OS (WSL uses Linux)')
    parser.add_argument('--replace', action='store_true', help='Replace an existing destination repository on restore')
    args = parser.parse_args(argv)
    try:
        transfer(args.action, args.file, storage=args.storage, replace=args.replace)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{error}\n')
    print(f'{args.action.capitalize()} complete: {Path(args.file).resolve()}')


if __name__ == '__main__':
    main()
